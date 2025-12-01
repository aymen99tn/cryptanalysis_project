#include <arpa/inet.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include "sqlite3.h"
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>
#include <csignal>

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <iostream>
#include <map>
#include <memory>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <vector>

namespace fs = std::filesystem;

constexpr int kPort = 8080;
constexpr const char *kDefaultCert = "cert.pem";
constexpr const char *kDefaultKey = "key.pem";
constexpr const char *kDefaultDb = "data/documents.db";
constexpr size_t kMaxRequestLine = 1024;
constexpr size_t kMaxDocumentId = 256;
constexpr size_t kMaxDocumentSize = 10 << 20;  // 10 MiB cap to prevent DoS
constexpr int kSocketTimeoutSeconds = 5;

// Rate limiting configuration
constexpr int kMaxConnectionsPerIP = 10;
constexpr int kRateLimitWindowSeconds = 60;
constexpr int kCertExpiryWarningDays = 30;

// Buffered read configuration
constexpr size_t kReadBufferSize = 4096;

// RAII wrappers for resource management
struct SSLDeleter {
    void operator()(SSL *ssl) const {
        if (ssl) {
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    }
};

struct SSLCtxDeleter {
    void operator()(SSL_CTX *ctx) const {
        if (ctx) SSL_CTX_free(ctx);
    }
};

struct FileDescriptorCloser {
    void operator()(int *fd) const {
        if (fd && *fd >= 0) {
            close(*fd);
        }
    }
};

using UniqueSSL = std::unique_ptr<SSL, SSLDeleter>;
using UniqueSSLCtx = std::unique_ptr<SSL_CTX, SSLCtxDeleter>;

// Rate limiting tracker
struct RateLimitEntry {
    std::chrono::steady_clock::time_point first_conn;
    int count;
};

class RateLimiter {
public:
    bool allow_connection(const std::string &ip) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto now = std::chrono::steady_clock::now();

        // Clean up old entries
        cleanup_old_entries(now);

        auto &entry = connections_[ip];
        if (entry.count == 0) {
            entry.first_conn = now;
            entry.count = 1;
            return true;
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - entry.first_conn).count();
        if (elapsed < kRateLimitWindowSeconds) {
            if (entry.count >= kMaxConnectionsPerIP) {
                return false;
            }
            entry.count++;
            return true;
        }

        // Window expired, reset
        entry.first_conn = now;
        entry.count = 1;
        return true;
    }

    void log_stats() {
        std::lock_guard<std::mutex> lock(mutex_);
        std::cout << "{\"type\":\"rate_limit_stats\",\"tracked_ips\":" << connections_.size() << "}" << std::endl;
    }

private:
    void cleanup_old_entries(std::chrono::steady_clock::time_point now) {
        auto it = connections_.begin();
        while (it != connections_.end()) {
            auto elapsed = std::chrono::duration_cast<std::chrono::seconds>(now - it->second.first_conn).count();
            if (elapsed >= kRateLimitWindowSeconds && it->second.count == 0) {
                it = connections_.erase(it);
            } else {
                ++it;
            }
        }
    }

    std::map<std::string, RateLimitEntry> connections_;
    std::mutex mutex_;
};

// Global handles for signal cleanup
sqlite3 *g_db = nullptr;
int g_listen_fd = -1;
SSL_CTX *g_ssl_ctx = nullptr;
std::string g_cert_path;
std::string g_key_path;
RateLimiter g_rate_limiter;

// JSON logging helper
static std::string json_escape(const std::string &s) {
    std::ostringstream oss;
    for (char c : s) {
        switch (c) {
            case '"':  oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:   oss << c; break;
        }
    }
    return oss.str();
}

static void log_json(const std::map<std::string, std::string> &fields) {
    std::ostringstream oss;
    oss << "{";
    bool first = true;
    for (const auto &[key, value] : fields) {
        if (!first) oss << ",";
        oss << "\"" << key << "\":\"" << json_escape(value) << "\"";
        first = false;
    }
    oss << "}";
    std::cout << oss.str() << std::endl;
}

static void log_ssl_errors(const std::string &context) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        log_json({
            {"type", "ssl_error"},
            {"context", context},
            {"error", buf}
        });
    }
}

static void reload_certificates() {
    if (!g_ssl_ctx || g_cert_path.empty() || g_key_path.empty()) {
        log_json({{"type", "cert_reload"}, {"status", "error"}, {"reason", "missing_context_or_paths"}});
        return;
    }

    if (SSL_CTX_use_certificate_file(g_ssl_ctx, g_cert_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        log_ssl_errors("cert_reload_certificate");
        return;
    }
    if (SSL_CTX_use_PrivateKey_file(g_ssl_ctx, g_key_path.c_str(), SSL_FILETYPE_PEM) <= 0) {
        log_ssl_errors("cert_reload_key");
        return;
    }
    if (SSL_CTX_check_private_key(g_ssl_ctx) != 1) {
        log_ssl_errors("cert_reload_check");
        return;
    }

    log_json({{"type", "cert_reload"}, {"status", "success"}});
}

static void signal_handler(int signum) {
    if (signum == SIGHUP) {
        log_json({{"type", "signal"}, {"signal", "SIGHUP"}, {"action", "reloading_certificates"}});
        reload_certificates();
        return;
    }

    log_json({{"type", "signal"}, {"signal", std::to_string(signum)}, {"action", "shutting_down"}});
    if (g_listen_fd != -1) close(g_listen_fd);
    if (g_db) sqlite3_close(g_db);
    std::exit(EXIT_SUCCESS);
}

static void check_certificate_expiry(const std::string &cert_path) {
    FILE *fp = fopen(cert_path.c_str(), "r");
    if (!fp) {
        log_json({{"type", "cert_check"}, {"status", "error"}, {"reason", "cannot_open_file"}});
        return;
    }

    X509 *cert = PEM_read_X509(fp, nullptr, nullptr, nullptr);
    fclose(fp);

    if (!cert) {
        log_json({{"type", "cert_check"}, {"status", "error"}, {"reason", "cannot_parse_cert"}});
        return;
    }

    const ASN1_TIME *not_after = X509_get0_notAfter(cert);
    if (!not_after) {
        X509_free(cert);
        return;
    }

    // Convert ASN1_TIME to time_t
    int day = 0, sec = 0;
    if (ASN1_TIME_diff(&day, &sec, nullptr, not_after)) {
        int days_until_expiry = day;

        if (days_until_expiry < 0) {
            log_json({
                {"type", "cert_expiry"},
                {"status", "expired"},
                {"days_ago", std::to_string(-days_until_expiry)}
            });
        } else if (days_until_expiry < kCertExpiryWarningDays) {
            log_json({
                {"type", "cert_expiry"},
                {"status", "warning"},
                {"days_remaining", std::to_string(days_until_expiry)}
            });
        } else {
            log_json({
                {"type", "cert_expiry"},
                {"status", "valid"},
                {"days_remaining", std::to_string(days_until_expiry)}
            });
        }
    }

    X509_free(cert);
}

static UniqueSSLCtx create_server_context() {
    const SSL_METHOD *method = TLS_server_method();
    SSL_CTX *raw_ctx = SSL_CTX_new(method);
    if (!raw_ctx) {
        log_ssl_errors("SSL_CTX_new");
        std::exit(EXIT_FAILURE);
    }

    UniqueSSLCtx ctx(raw_ctx);

    if (SSL_CTX_set_min_proto_version(ctx.get(), TLS1_3_VERSION) != 1) {
        log_ssl_errors("set_min_proto_version");
        std::exit(EXIT_FAILURE);
    }

    SSL_CTX_set_options(ctx.get(), SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);

    // Prefer modern AEAD suites.
    if (SSL_CTX_set_ciphersuites(ctx.get(), "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256") != 1) {
        log_ssl_errors("set_ciphersuites");
        std::exit(EXIT_FAILURE);
    }

    // Enable TLS 1.3 session resumption with session tickets
    SSL_CTX_set_options(ctx.get(), SSL_OP_NO_TICKET);  // First disable to reset
    SSL_CTX_clear_options(ctx.get(), SSL_OP_NO_TICKET);  // Then enable tickets

    // Set session cache mode for stateless resumption
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_SERVER);

    // Request client cert optionally; can tighten later.
    SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
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
    if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
    }
    if (setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_SNDTIMEO");
    }
}

struct Document {
    std::string id;
    std::string mime;
    std::string content;
};

// Validates document ID: alphanumeric, underscore, hyphen only
static bool is_valid_document_id(std::string_view id) {
    if (id.empty() || id.size() > kMaxDocumentId) {
        return false;
    }
    return std::all_of(id.begin(), id.end(), [](unsigned char c) {
        return std::isalnum(c) || c == '_' || c == '-' || c == '.';
    });
}

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
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) {
        return std::nullopt;
    }
    sqlite3_bind_text(stmt, 1, id.data(), static_cast<int>(id.size()), SQLITE_STATIC);

    Document doc;
    int rc = sqlite3_step(stmt);
    if (rc == SQLITE_ROW) {
        doc.id = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 0));
        doc.mime = reinterpret_cast<const char *>(sqlite3_column_text(stmt, 1));
        const unsigned char *blob = reinterpret_cast<const unsigned char *>(sqlite3_column_blob(stmt, 2));
        int blob_size = sqlite3_column_bytes(stmt, 2);

        // Enforce document size limit to prevent DoS
        if (blob_size < 0 || static_cast<size_t>(blob_size) > kMaxDocumentSize) {
            std::cerr << "Document size exceeds limit: " << blob_size << " bytes" << std::endl;
            sqlite3_finalize(stmt);
            return std::nullopt;
        }

        doc.content.assign(reinterpret_cast<const char *>(blob), static_cast<size_t>(blob_size));
        sqlite3_finalize(stmt);
        return doc;
    }

    sqlite3_finalize(stmt);
    return std::nullopt;
}

// Buffered SSL reader for better protocol parsing
class BufferedSSLReader {
public:
    explicit BufferedSSLReader(SSL *ssl) : ssl_(ssl), buffer_pos_(0), buffer_len_(0) {}

    bool read_line(std::string &out, size_t max_len) {
        out.clear();
        while (out.size() < max_len) {
            if (buffer_pos_ >= buffer_len_) {
                // Refill buffer
                int ret = SSL_read(ssl_, buffer_, kReadBufferSize);
                if (ret <= 0) {
                    log_ssl_errors("SSL_read");
                    return false;
                }
                buffer_len_ = static_cast<size_t>(ret);
                buffer_pos_ = 0;
            }

            char ch = buffer_[buffer_pos_++];
            if (ch == '\n') return true;
            out.push_back(ch);
        }
        return false;  // Line too long
    }

private:
    SSL *ssl_;
    char buffer_[kReadBufferSize];
    size_t buffer_pos_;
    size_t buffer_len_;
};

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
    const char *tls_version = SSL_get_version(ssl);
    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    const char *cipher_name = cipher ? SSL_CIPHER_get_name(cipher) : "unknown";
    auto start = std::chrono::steady_clock::now();

    // Check for session resumption
    bool resumed = SSL_session_reused(ssl);

    BufferedSSLReader reader(ssl);
    std::string request;
    if (!reader.read_line(request, kMaxRequestLine)) {
        const char msg[] = "ERR request_too_long\n";
        send_all(ssl, msg, sizeof(msg) - 1);
        log_json({
            {"type", "request"},
            {"ip", client_ip},
            {"tls", tls_version},
            {"cipher", cipher_name},
            {"resumed", resumed ? "true" : "false"},
            {"status", "ERR_TOO_LONG"}
        });
        return;
    }

    // Expect: GET <id>
    const std::string prefix = "GET ";
    if (request.rfind(prefix, 0) != 0) {
        const char msg[] = "ERR unsupported_command\n";
        send_all(ssl, msg, sizeof(msg) - 1);
        log_json({
            {"type", "request"},
            {"ip", client_ip},
            {"tls", tls_version},
            {"cipher", cipher_name},
            {"resumed", resumed ? "true" : "false"},
            {"status", "ERR_UNSUPPORTED"}
        });
        return;
    }

    std::string id = request.substr(prefix.size());
    if (id.empty()) {
        const char msg[] = "ERR missing_id\n";
        send_all(ssl, msg, sizeof(msg) - 1);
        log_json({
            {"type", "request"},
            {"ip", client_ip},
            {"tls", tls_version},
            {"cipher", cipher_name},
            {"resumed", resumed ? "true" : "false"},
            {"status", "ERR_MISSING_ID"}
        });
        return;
    }

    // Validate document ID for security
    if (!is_valid_document_id(id)) {
        const char msg[] = "ERR invalid_id\n";
        send_all(ssl, msg, sizeof(msg) - 1);
        log_json({
            {"type", "request"},
            {"ip", client_ip},
            {"tls", tls_version},
            {"cipher", cipher_name},
            {"resumed", resumed ? "true" : "false"},
            {"id", id},
            {"status", "ERR_INVALID_ID"}
        });
        return;
    }

    auto doc = fetch_document(db, id);
    if (!doc) {
        const char msg[] = "ERR not_found\n";
        send_all(ssl, msg, sizeof(msg) - 1);
        log_json({
            {"type", "request"},
            {"ip", client_ip},
            {"tls", tls_version},
            {"cipher", cipher_name},
            {"resumed", resumed ? "true" : "false"},
            {"id", id},
            {"status", "404_NOT_FOUND"}
        });
        return;
    }

    std::string header = "OK " + doc->mime + " " + std::to_string(doc->content.size()) + "\n";
    if (!send_all(ssl, header.data(), header.size())) return;
    send_all(ssl, doc->content.data(), doc->content.size());

    auto end = std::chrono::steady_clock::now();
    auto elapsed_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    log_json({
        {"type", "request"},
        {"ip", client_ip},
        {"tls", tls_version},
        {"cipher", cipher_name},
        {"resumed", resumed ? "true" : "false"},
        {"id", id},
        {"mime", doc->mime},
        {"length", std::to_string(doc->content.size())},
        {"duration_ms", std::to_string(elapsed_ms)},
        {"status", "200_OK"}
    });
}

int main() {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    signal(SIGHUP, signal_handler);

    const char *cert_env = std::getenv("TLS_CERT");
    const char *key_env = std::getenv("TLS_KEY");
    const char *db_env = std::getenv("DOC_DB");

    g_cert_path = cert_env ? cert_env : kDefaultCert;
    g_key_path = key_env ? key_env : kDefaultKey;
    std::string db_path = db_env ? db_env : kDefaultDb;

    log_json({{"type", "startup"}, {"cert", g_cert_path}, {"key", g_key_path}, {"db", db_path}});

    // Check certificate expiry on startup
    check_certificate_expiry(g_cert_path);

    fs::create_directories(fs::path(db_path).parent_path());

    if (sqlite3_open(db_path.c_str(), &g_db) != SQLITE_OK) {
        log_json({{"type", "error"}, {"context", "database"}, {"message", "failed to open database"}});
        return EXIT_FAILURE;
    }
    if (ensure_schema(g_db) != SQLITE_OK) return EXIT_FAILURE;
    seed_documents(g_db);

    OPENSSL_init_ssl(0, nullptr);

    UniqueSSLCtx ctx = create_server_context();
    load_credentials(ctx.get(), g_cert_path, g_key_path);

    // Store context globally for reload capability
    g_ssl_ctx = ctx.get();

    g_listen_fd = create_listen_socket();
    log_json({{"type", "listening"}, {"port", std::to_string(kPort)}});

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

        // Rate limiting check
        if (!g_rate_limiter.allow_connection(ip)) {
            log_json({
                {"type", "rate_limit"},
                {"ip", ip},
                {"status", "rejected"}
            });
            close(client_fd);
            continue;
        }

        log_json({{"type", "connection"}, {"ip", ip}});

        SSL *raw_ssl = SSL_new(ctx.get());
        if (!raw_ssl) {
            log_ssl_errors("SSL_new");
            close(client_fd);
            continue;
        }

        UniqueSSL ssl(raw_ssl);
        SSL_set_fd(ssl.get(), client_fd);

        if (SSL_accept(ssl.get()) <= 0) {
            log_ssl_errors("SSL_accept");
            close(client_fd);
            continue;
        }

        const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl.get());
        log_json({
            {"type", "handshake"},
            {"ip", ip},
            {"tls", SSL_get_version(ssl.get())},
            {"cipher", SSL_CIPHER_get_name(cipher)},
            {"resumed", SSL_session_reused(ssl.get()) ? "true" : "false"}
        });

        handle_client(ssl.get(), g_db, ip);

        // SSL and client_fd will be cleaned up automatically by UniqueSSL and when client_fd goes out of scope
        close(client_fd);
    }

    // Should be unreachable due to signals, but for completeness:
    close(g_listen_fd);
    sqlite3_close(g_db);
    return 0;
}
