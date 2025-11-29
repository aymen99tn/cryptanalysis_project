#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include "sqlite3.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <csignal>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <string_view>

namespace fs = std::filesystem;

constexpr int kPort = 8080;
constexpr const char *kDefaultCert = "cert.pem";
constexpr const char *kDefaultKey = "key.pem";
constexpr const char *kDefaultDb = "data/documents.db";
constexpr size_t kMaxRequestLine = 1024;
constexpr int kSocketTimeoutSeconds = 5;

// Global handles for signal cleanup
sqlite3 *g_db = nullptr;
int g_listen_fd = -1;

static void log_ssl_errors(const std::string &context) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << context << ": " << buf << std::endl;
    }
}

static void signal_handler(int signum) {
    std::cout << "\nCaught signal " << signum << ", shutting down..." << std::endl;
    if (g_listen_fd != -1) close(g_listen_fd);
    if (g_db) sqlite3_close(g_db);
    std::exit(EXIT_SUCCESS);
}

static SSL_CTX *create_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *ctx = SSL_CTX_new(method);
    if (!ctx) {
        log_ssl_errors("SSL_CTX_new");
        std::exit(EXIT_FAILURE);
    }

    if (SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION) != 1) {
        log_ssl_errors("set_min_proto_version");
        std::exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);

    // Prefer modern AEAD suites.
    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256") != 1) {
        log_ssl_errors("set_ciphersuites");
        std::exit(EXIT_FAILURE);
    }

    // Request client cert optionally; can tighten later.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    return ctx;
}

static void load_credentials(SSL_CTX *ctx, const std::string &cert_path, const std::string &key_path) {
    if (SSL_CTX_use_certificate_file(ctx, cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        log_ssl_errors("use_certificate_file");
        std::exit(EXIT_FAILURE);
    }
    if (SSL_CTX_use_PrivateKey_file(ctx, key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        log_ssl_errors("use_PrivateKey_file");
        std::exit(EXIT_FAILURE);
    }
    if (SSL_CTX_check_private_key(ctx) != 1) {
        log_ssl_errors("check_private_key");
        std::exit(EXIT_FAILURE);
    }
}

static int create_listen_socket() {
    int sock = ::socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        std::exit(EXIT_FAILURE);
    }

    int opt = 1;
    setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(kPort);

    if (bind(sock, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
        perror("bind");
        close(sock);
        std::exit(EXIT_FAILURE);
    }

    if (listen(sock, 8) < 0) {
        perror("listen");
        close(sock);
        std::exit(EXIT_FAILURE);
    }

    return sock;
}

static void set_socket_timeouts(int fd) {
    timeval tv{};
    tv.tv_sec = kSocketTimeoutSeconds;
    tv.tv_usec = 0;
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
}

struct Document {
    std::string id;
    std::string mime;
    std::string content;
};

static int ensure_schema(sqlite3 *db) {
    const char *sql = R"SQL(
        CREATE TABLE IF NOT EXISTS documents (
            id TEXT PRIMARY KEY,
            mime TEXT NOT NULL,
            content BLOB NOT NULL
        );
    )SQL";
    char *errmsg = nullptr;
    int rc = sqlite3_exec(db, sql, nullptr, nullptr, &errmsg);
    if (rc != SQLITE_OK) {
        std::cerr << "SQLite error: " << (errmsg ? errmsg : "unknown") << std::endl;
        sqlite3_free(errmsg);
    }
    return rc;
}

static void seed_documents(sqlite3 *db) {
    const char *count_sql = "SELECT COUNT(*) FROM documents;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, count_sql, -1, &stmt, nullptr) != SQLITE_OK) return;
    int rc = sqlite3_step(stmt);
    int count = (rc == SQLITE_ROW) ? sqlite3_column_int(stmt, 0) : 0;
    sqlite3_finalize(stmt);
    if (count > 0) return;

    const char *insert_sql = "INSERT INTO documents (id, mime, content) VALUES (?, ?, ?);";
    if (sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr) != SQLITE_OK) return;

    struct Seed { const char *id; const char *mime; const char *body; } seeds[] = {
        {"welcome", "text/html", "<html><body><h1>Welcome</h1><p>Secure content served over TLS.</p></body></html>"},
        {"readme", "text/plain", "Sample document stored in SQLite for OpenSSL demo."}
    };

    for (const auto &seed : seeds) {
        sqlite3_bind_text(stmt, 1, seed.id, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, seed.mime, -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 3, seed.body, static_cast<int>(strlen(seed.body)), SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);
}

static std::optional<Document> fetch_document(sqlite3 *db, std::string_view id) {
    const char *sql = "SELECT id, mime, content FROM documents WHERE id = ?;";
    sqlite3_stmt *stmt = nullptr;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return std::nullopt;
    sqlite3_bind_text(stmt, 1, id.data(), static_cast<int>(id.size()), SQLITE_STATIC);

    Document doc;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        doc.id = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        doc.mime = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        const unsigned char *blob = reinterpret_cast<const unsigned char *>(sqlite3_column_blob(stmt, 2));
        int blob_size = sqlite3_column_bytes(stmt, 2);
        doc.content.assign(reinterpret_cast<const char *>(blob), blob_size);
        sqlite3_finalize(stmt);
        return doc;
    }

    sqlite3_finalize(stmt);
    return std::nullopt;
}

static bool send_all(SSL *ssl, const void *data, size_t len) {
    const unsigned char *p = static_cast<const unsigned char *>(data);
    size_t sent = 0;
    while (sent < len) {
        int ret = SSL_write(ssl, p + sent, static_cast<int>(len - sent));
        if (ret <= 0) {
            log_ssl_errors("SSL_write");
            return false;
        }
        sent += static_cast<size_t>(ret);
    }
    return true;
}

static void handle_client(SSL *ssl, sqlite3 *db, const char *client_ip) {
    std::string request;
    char ch;
    while (true) {
        int ret = SSL_read(ssl, &ch, 1);
        if (ret <= 0) {
            log_ssl_errors("SSL_read");
            return;
        }
        if (ch == '\n') break;
        if (request.size() >= kMaxRequestLine) {
            const char msg[] = "ERR request_too_long\n";
            send_all(ssl, msg, sizeof(msg) - 1);
            std::cout << "[LOG] IP=" << client_ip << " Status=ERR_TOO_LONG" << std::endl;
            return;
        }
        request.push_back(ch);
    }

    // Expect: GET <id>
    const std::string prefix = "GET ";
    if (request.rfind(prefix, 0) != 0) {
        const char msg[] = "ERR unsupported_command\n";
        send_all(ssl, msg, sizeof(msg) - 1);
        std::cout << "[LOG] IP=" << client_ip << " Status=ERR_UNSUPPORTED" << std::endl;
        return;
    }

    std::string id = request.substr(prefix.size());
    if (id.empty()) {
        const char msg[] = "ERR missing_id\n";
        send_all(ssl, msg, sizeof(msg) - 1);
        std::cout << "[LOG] IP=" << client_ip << " Status=ERR_MISSING_ID" << std::endl;
        return;
    }

    auto doc = fetch_document(db, id);
    if (!doc) {
        const char msg[] = "ERR not_found\n";
        send_all(ssl, msg, sizeof(msg) - 1);
        std::cout << "[LOG] IP=" << client_ip << " ID=" << id << " Status=404_NOT_FOUND" << std::endl;
        return;
    }

    std::string header = "OK " + doc->mime + " " + std::to_string(doc->content.size()) + "\n";
    if (!send_all(ssl, header.data(), header.size())) return;
    send_all(ssl, doc->content.data(), doc->content.size());
    std::cout << "[LOG] IP=" << client_ip << " ID=" << id << " Status=200_OK" << std::endl;
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    const char *cert_env = std::getenv("TLS_CERT");
    const char *key_env = std::getenv("TLS_KEY");
    const char *db_env = std::getenv("DOC_DB");

    std::string cert_path = cert_env ? cert_env : kDefaultCert;
    std::string key_path = key_env ? key_env : kDefaultKey;
    std::string db_path = db_env ? db_env : kDefaultDb;

    fs::create_directories(fs::path(db_path).parent_path());

    if (sqlite3_open(db_path.c_str(), &g_db) != SQLITE_OK) {
        std::cerr << "Failed to open database at " << db_path << std::endl;
        return EXIT_FAILURE;
    }
    if (ensure_schema(g_db) != SQLITE_OK) return EXIT_FAILURE;
    seed_documents(g_db);

    OPENSSL_init_ssl(0, nullptr);

    SSL_CTX *ctx = create_server_context();
    load_credentials(ctx, cert_path, key_path);

    g_listen_fd = create_listen_socket();
    std::cout << "Listening on port " << kPort << "..." << std::endl;

    while (true) {
        sockaddr_in addr{};
        socklen_t len = sizeof(addr);
        int client_fd = accept(g_listen_fd, reinterpret_cast<sockaddr *>(&addr), &len);
        if (client_fd < 0) {
            perror("accept");
            continue;
        }
        set_socket_timeouts(client_fd);

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &addr.sin_addr, ip, sizeof(ip));
        std::cout << "Connection from " << ip << std::endl;

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_fd);

        if (SSL_accept(ssl) <= 0) {
            log_ssl_errors("SSL_accept");
            SSL_free(ssl);
            close(client_fd);
            continue;
        }

        const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
        std::cout << "Negotiated " << SSL_get_version(ssl) << " / " << SSL_CIPHER_get_name(cipher) << std::endl;

        handle_client(ssl, g_db, ip);

        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(client_fd);
    }

    // Should be unreachable due to signals, but for completeness:
    close(g_listen_fd);
    sqlite3_close(g_db);
    SSL_CTX_free(ctx);
    return 0;
}
