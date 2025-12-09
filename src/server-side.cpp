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
#ifdef SO_REUSEPORT
    setsockopt(sock, SOL_SOCKET, SO_REUSEPORT, &opt, sizeof(opt));
#endif

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
        // Welcome & Introduction
        {"welcome", "text/html",
         "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Welcome</title></head>"
         "<body style='font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px;'>"
         "<h1 style='color: #d32f2f;'>🔒 Welcome to the TLS 1.3 Secure Document Server</h1>"
         "<p>This is a demonstration of a secure document retrieval system built with:</p>"
         "<ul><li><strong>TLS 1.3</strong> - Latest transport security protocol</li>"
         "<li><strong>AEAD Encryption</strong> - Authenticated encryption with AES-GCM</li>"
         "<li><strong>Perfect Forward Secrecy</strong> - Ephemeral key exchange</li></ul>"
         "<h2>University of New Brunswick</h2>"
         "<p>Fredericton, New Brunswick, Canada</p>"
         "<hr><p><em>Secure content delivered over TLS 1.3 | " __DATE__ "</em></p></body></html>"},

        // UNB Course Catalog (JSON)
        {"course-catalog", "application/json",
         "{\"university\":\"University of New Brunswick\",\"term\":\"Winter 2025\","
         "\"courses\":["
         "{\"code\":\"CS3413\",\"name\":\"Operating Systems I\",\"credits\":3,\"instructor\":\"Dr. Smith\"},"
         "{\"code\":\"CS4735\",\"name\":\"Network Security\",\"credits\":3,\"instructor\":\"Dr. Johnson\"},"
         "{\"code\":\"CS6735\",\"name\":\"Advanced Cryptography\",\"credits\":3,\"instructor\":\"Dr. Martinez\"},"
         "{\"code\":\"CS5123\",\"name\":\"Distributed Systems\",\"credits\":3,\"instructor\":\"Dr. Lee\"},"
         "{\"code\":\"CS5713\",\"name\":\"Software Security\",\"credits\":3,\"instructor\":\"Dr. Brown\"}"
         "]}"},

        // Student Records (Anonymized JSON)
        {"student-records", "application/json",
         "{\"records\":["
         "{\"id\":\"S001\",\"program\":\"Computer Science\",\"year\":4,\"gpa\":3.85,\"enrolled\":[\"CS3413\",\"CS4735\"]},"
         "{\"id\":\"S002\",\"program\":\"Software Engineering\",\"year\":3,\"gpa\":3.92,\"enrolled\":[\"CS5123\",\"CS5713\"]},"
         "{\"id\":\"S003\",\"program\":\"Computer Science\",\"year\":5,\"gpa\":4.0,\"enrolled\":[\"CS6735\"]},"
         "{\"id\":\"S004\",\"program\":\"Cybersecurity\",\"year\":2,\"gpa\":3.67,\"enrolled\":[\"CS4735\"]}"
         "],\"semester\":\"Winter 2025\",\"generated\":\"" __DATE__ "\"}"},

        // TLS 1.3 Specification Excerpt
        {"tls13-spec", "text/plain",
         "RFC 8446 - The Transport Layer Security (TLS) Protocol Version 1.3\n\n"
         "ABSTRACT\n\n"
         "This document specifies version 1.3 of the Transport Layer Security (TLS) "
         "protocol. TLS allows client/server applications to communicate over the "
         "Internet in a way that is designed to prevent eavesdropping, tampering, and "
         "message forgery.\n\n"
         "KEY IMPROVEMENTS IN TLS 1.3:\n\n"
         "1. Improved Handshake Performance\n"
         "   - Reduced from 2-RTT to 1-RTT for full handshake\n"
         "   - 0-RTT mode for resumption (with replay protection considerations)\n\n"
         "2. Enhanced Security\n"
         "   - Removed support for weak cryptographic algorithms\n"
         "   - All handshake messages after ServerHello are encrypted\n"
         "   - Mandatory forward secrecy via ephemeral key exchange\n\n"
         "3. Simplified Cipher Suite Negotiation\n"
         "   - Separation of key exchange and authentication\n"
         "   - AEAD-only cipher suites (no CBC mode)\n"
         "   - Recommended suites: TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256\n\n"
         "4. Removed Legacy Features\n"
         "   - No renegotiation\n"
         "   - No compression\n"
         "   - No custom DHE groups\n"
         "   - No RSA key exchange\n\n"
         "For complete specification, see: https://www.rfc-editor.org/rfc/rfc8446\n"},

        // Cryptography Primer
        {"cryptography-primer", "text/html",
         "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Cryptography Primer</title></head>"
         "<body style='font-family: Georgia, serif; max-width: 700px; margin: 40px auto; padding: 20px; line-height: 1.6;'>"
         "<h1>🔐 Modern Cryptography Primer</h1>"
         "<h2>Authenticated Encryption with Associated Data (AEAD)</h2>"
         "<p>AEAD provides both <strong>confidentiality</strong> and <strong>authenticity</strong> in a single cryptographic primitive.</p>"
         "<h3>AES-GCM (Galois/Counter Mode)</h3>"
         "<ul><li><strong>Encryption</strong>: AES in Counter (CTR) mode</li>"
         "<li><strong>Authentication</strong>: GMAC (Galois Message Authentication Code)</li>"
         "<li><strong>Key sizes</strong>: 128-bit or 256-bit</li>"
         "<li><strong>Benefits</strong>: Parallelizable, efficient, secure</li></ul>"
         "<h3>Perfect Forward Secrecy</h3>"
         "<p>Even if long-term keys are compromised, past session keys remain secure.</p>"
         "<p><strong>Implementation</strong>: Ephemeral Diffie-Hellman key exchange (ECDHE)</p>"
         "<hr><p><em>Used in TLS 1.3 for all connections</em></p></body></html>"},

        // Research Data (CSV)
        {"research-data", "text/csv",
         "timestamp,protocol,cipher_suite,handshake_ms,throughput_mbps,packet_count\n"
         "2025-01-15T10:23:45,TLS1.3,TLS_AES_256_GCM_SHA384,8.7,145.3,42\n"
         "2025-01-15T10:24:12,TLS1.3,TLS_AES_256_GCM_SHA384,9.2,142.1,45\n"
         "2025-01-15T10:24:39,TLS1.3,TLS_AES_128_GCM_SHA256,7.9,156.7,38\n"
         "2025-01-15T10:25:06,TLS1.3,TLS_AES_256_GCM_SHA384,8.5,148.2,41\n"
         "2025-01-15T10:25:33,TLS1.3,TLS_AES_128_GCM_SHA256,8.1,152.9,39\n"
         "2025-01-15T10:26:00,TLS1.3,TLS_AES_256_GCM_SHA384,9.0,143.5,44\n"
         "2025-01-15T10:26:27,TLS1.3,TLS_AES_128_GCM_SHA256,7.8,158.1,37\n"
         "2025-01-15T10:26:54,TLS1.3,TLS_AES_256_GCM_SHA384,8.9,144.8,43\n"},

        // Architecture Diagram (ASCII Art)
        {"architecture-diagram", "text/plain",
         "TLS 1.3 Document Server Architecture\n"
         "=====================================\n\n"
         "┌─────────────────────────────────────────────────────────────────┐\n"
         "│                         CLIENT SIDE                             │\n"
         "│  ┌──────────────┐                                               │\n"
         "│  │  TLS Client  │  ─────────[1]─────────▶  ClientHello         │\n"
         "│  │  (C++17)     │                           + Key Share         │\n"
         "│  └──────────────┘  ◀─────[2]─────────────  ServerHello         │\n"
         "│         │                                   + Key Share         │\n"
         "│         │          ◀─────[3]─────────────  {EncryptedExtensions}│\n"
         "│         │          ◀─────[4]─────────────  {Certificate}        │\n"
         "│         │          ◀─────[5]─────────────  {CertificateVerify}  │\n"
         "│         │          ◀─────[6]─────────────  {Finished}           │\n"
         "│         │          ─────────[7]─────────▶  {Finished}           │\n"
         "│         │                                                         │\n"
         "│         └──────────────[8]─────────▶  {GET document_id}         │\n"
         "│                    ◀─────[9]───────  {OK mime length + content} │\n"
         "└─────────────────────────────────────────────────────────────────┘\n"
         "                               │\n"
         "                               │ TCP Port 8080\n"
         "                               │ TLS 1.3 Only\n"
         "                               ▼\n"
         "┌─────────────────────────────────────────────────────────────────┐\n"
         "│                         SERVER SIDE                             │\n"
         "│  ┌──────────────────────────────────────────────────────────┐   │\n"
         "│  │  TLS 1.3 Server (OpenSSL 3)                             │   │\n"
         "│  │  • Cipher Suites: AES-256-GCM, AES-128-GCM              │   │\n"
         "│  │  • Key Exchange: ECDHE (Perfect Forward Secrecy)        │   │\n"
         "│  │  • Certificate: X.509 (self-signed for demo)            │   │\n"
         "│  └──────────────────────────────────────────────────────────┘   │\n"
         "│                         │                                        │\n"
         "│                         │ JSON Logging                           │\n"
         "│                         ▼                                        │\n"
         "│  ┌──────────────────────────────────────────────────────────┐   │\n"
         "│  │  SQLite Database                                         │   │\n"
         "│  │  Table: documents (id, mime, content)                    │   │\n"
         "│  └──────────────────────────────────────────────────────────┘   │\n"
         "└─────────────────────────────────────────────────────────────────┘\n\n"
         "Legend:\n"
         "  ────▶  Plaintext\n"
         "  {···}  Encrypted with handshake keys\n"
         "  [n]    Message sequence number\n"},

        // OpenSSL Guide
        {"openssl-guide", "text/plain",
         "OpenSSL 3.x - TLS 1.3 Quick Reference\n"
         "======================================\n\n"
         "TESTING TLS 1.3 SERVER\n"
         "----------------------\n"
         "# Connect with TLS 1.3 (should succeed):\n"
         "openssl s_client -connect 127.0.0.1:8080 -tls1_3 \\\n"
         "  -servername localhost -CAfile cert.pem\n\n"
         "# Try TLS 1.2 (should be rejected):\n"
         "openssl s_client -connect 127.0.0.1:8080 -tls1_2 \\\n"
         "  -servername localhost -CAfile cert.pem\n\n"
         "# View negotiated cipher suite:\n"
         "openssl s_client -connect 127.0.0.1:8080 -tls1_3 \\\n"
         "  -CAfile cert.pem 2>/dev/null | grep \"Cipher\"\n\n"
         "# Send GET request:\n"
         "echo \"GET welcome\" | openssl s_client -connect 127.0.0.1:8080 \\\n"
         "  -tls1_3 -CAfile cert.pem -quiet\n\n"
         "CERTIFICATE OPERATIONS\n"
         "----------------------\n"
         "# Generate self-signed certificate:\n"
         "openssl req -x509 -newkey rsa:2048 -nodes \\\n"
         "  -keyout key.pem -out cert.pem -days 365 \\\n"
         "  -subj \"/CN=localhost\"\n\n"
         "# View certificate details:\n"
         "openssl x509 -in cert.pem -text -noout\n\n"
         "# Check certificate expiry:\n"
         "openssl x509 -in cert.pem -noout -dates\n\n"
         "CIPHER SUITES\n"
         "-------------\n"
         "TLS 1.3 AEAD-only suites:\n"
         "  • TLS_AES_256_GCM_SHA384 (recommended)\n"
         "  • TLS_AES_128_GCM_SHA256 (faster)\n"
         "  • TLS_CHACHA20_POLY1305_SHA256 (mobile-optimized)\n\n"
         "Legacy removed:\n"
         "  ✗ CBC mode ciphers\n"
         "  ✗ RC4\n"
         "  ✗ 3DES\n"
         "  ✗ MD5-based MACs\n"},

        // Performance Analysis
        {"performance-analysis", "text/html",
         "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>Performance Analysis</title></head>"
         "<body style='font-family: Consolas, monospace; max-width: 900px; margin: 20px auto; padding: 20px; background: #f5f5f5;'>"
         "<h1>📊 TLS 1.3 Performance Analysis</h1>"
         "<h2>Handshake Latency Comparison</h2>"
         "<table style='width:100%; border-collapse: collapse; background: white;'>"
         "<tr style='background: #333; color: white;'><th>Protocol</th><th>RTT Count</th><th>Mean (ms)</th><th>Median (ms)</th><th>p99 (ms)</th></tr>"
         "<tr><td>TLS 1.2</td><td>2-RTT</td><td>15.7</td><td>15.2</td><td>21.3</td></tr>"
         "<tr style='background: #e8f5e9;'><td><strong>TLS 1.3</strong></td><td><strong>1-RTT</strong></td><td><strong>9.15</strong></td><td><strong>8.59</strong></td><td><strong>12.30</strong></td></tr>"
         "<tr><td><em>Improvement</em></td><td><em>50%</em></td><td><em>41.7%</em></td><td><em>43.5%</em></td><td><em>42.3%</em></td></tr>"
         "</table>"
         "<h2>Throughput</h2>"
         "<ul><li>Mean: <strong>53.05 RPS</strong></li><li>95% CI: [48.24, 57.86]</li>"
         "<li>Coefficient of Variation: 14.63%</li></ul>"
         "<h2>Security Properties</h2>"
         "<ul><li>✅ TLS 1.2 correctly rejected</li><li>✅ Perfect Forward Secrecy (ECDHE)</li>"
         "<li>✅ AEAD-only encryption (AES-GCM)</li><li>✅ No session resumption vulnerabilities</li></ul>"
         "<hr><p><em>Network: Kali VM ↔ WSL2 | Generated: " __DATE__ "</em></p></body></html>"},

        // Test document 1KB
        {"doc-1kb", "text/plain",
         "This is a 1KB test document for performance benchmarking.\n"
         "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Sed do eiusmod tempor "
         "incididunt ut labore et dolore magna aliqua. Ut enim ad minim veniam, quis nostrud "
         "exercitation ullamco laboris nisi ut aliquip ex ea commodo consequat. Duis aute irure "
         "dolor in reprehenderit in voluptate velit esse cillum dolore eu fugiat nulla pariatur. "
         "Excepteur sint occaecat cupidatat non proident, sunt in culpa qui officia deserunt "
         "mollit anim id est laborum. Sed ut perspiciatis unde omnis iste natus error sit voluptatem "
         "accusantium doloremque laudantium, totam rem aperiam, eaque ipsa quae ab illo inventore "
         "veritatis et quasi architecto beatae vitae dicta sunt explicabo. Nemo enim ipsam voluptatem "
         "quia voluptas sit aspernatur aut odit aut fugit, sed quia consequuntur magni dolores eos qui "
         "ratione voluptatem sequi nesciunt. Neque porro quisquam est, qui dolorem ipsum quia dolor sit "
         "amet, consectetur, adipisci velit, sed quia non numquam eius modi tempora incidunt ut labore et "
         "dolore magnam aliquam quaerat voluptatem. End of 1KB document.\n"},

        // Test document 10KB (filled with repeated content)
        {"doc-10kb", "text/plain",
         "This is a 10KB test document for performance benchmarking.\n"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
         " End of 10KB document.\n"},

        // University Info
        {"unb-info", "text/html",
         "<!DOCTYPE html><html><head><meta charset='UTF-8'><title>UNB Information</title></head>"
         "<body style='font-family: Arial, sans-serif; max-width: 800px; margin: 40px auto; padding: 20px;'>"
         "<h1 style='color: #d32f2f;'>University of New Brunswick</h1>"
         "<h2>About UNB</h2>"
         "<p>Founded in 1785, the University of New Brunswick is Canada's oldest English-language university. "
         "Located in Fredericton and Saint John, New Brunswick, UNB is a comprehensive university with a strong "
         "commitment to excellence in teaching and research.</p>"
         "<h2>Computer Science Program</h2>"
         "<p>The Faculty of Computer Science offers undergraduate and graduate programs in:</p>"
         "<ul><li>Computer Science (BCS, MCS, PhD)</li>"
         "<li>Software Engineering (BSE)</li>"
         "<li>Cybersecurity Specializations</li>"
         "<li>Artificial Intelligence and Machine Learning</li></ul>"
         "<h2>Research Areas</h2>"
         "<ul><li>Network Security and Cryptography</li>"
         "<li>Distributed Systems</li>"
         "<li>Software Engineering</li>"
         "<li>Artificial Intelligence</li>"
         "<li>Human-Computer Interaction</li></ul>"
         "<hr><p><strong>Contact:</strong> Fredericton, NB E3B 5A3, Canada</p></body></html>"},

        // Security Best Practices
        {"security-practices", "text/markdown",
         "# TLS 1.3 Security Best Practices\n\n"
         "## Server Configuration\n\n"
         "### 1. Protocol Version\n"
         "```c++\n"
         "SSL_CTX_set_min_proto_version(ctx, TLS1_3_VERSION);\n"
         "SSL_CTX_set_max_proto_version(ctx, TLS1_3_VERSION);\n"
         "```\n"
         "✅ Enforces TLS 1.3 only\n"
         "❌ Rejects TLS 1.2 and earlier\n\n"
         "### 2. Cipher Suite Selection\n"
         "```c++\n"
         "SSL_CTX_set_ciphersuites(ctx, \"TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256\");\n"
         "```\n"
         "✅ AEAD-only ciphers\n"
         "✅ Strong key sizes (128-bit or 256-bit)\n"
         "❌ No CBC mode vulnerabilities\n\n"
         "### 3. Disable Dangerous Features\n"
         "```c++\n"
         "SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);\n"
         "```\n"
         "✅ Prevents CRIME/BREACH attacks\n"
         "✅ Eliminates renegotiation risks\n\n"
         "### 4. Certificate Validation\n"
         "```c++\n"
         "SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);\n"
         "SSL_CTX_load_verify_locations(ctx, ca_file, nullptr);\n"
         "```\n"
         "✅ Verifies peer certificates\n"
         "✅ Prevents MITM attacks\n\n"
         "## Deployment Checklist\n\n"
         "- [ ] Use strong certificates (2048-bit RSA minimum, ECDSA preferred)\n"
         "- [ ] Enable Perfect Forward Secrecy (ECDHE key exchange)\n"
         "- [ ] Monitor certificate expiration\n"
         "- [ ] Implement rate limiting\n"
         "- [ ] Log security events (JSON structured logging)\n"
         "- [ ] Regular security audits\n"
         "- [ ] Keep OpenSSL up-to-date\n\n"
         "## Common Pitfalls\n\n"
         "❌ **Don't**: Allow TLS 1.2 fallback\n"
         "❌ **Don't**: Use self-signed certs in production\n"
         "❌ **Don't**: Disable certificate verification\n"
         "❌ **Don't**: Hardcode credentials\n"
         "❌ **Don't**: Ignore OpenSSL error messages\n\n"
         "✅ **Do**: Enforce TLS 1.3 only\n"
         "✅ **Do**: Use proper CA-signed certificates\n"
         "✅ **Do**: Validate all inputs\n"
         "✅ **Do**: Monitor and log security events\n"
         "✅ **Do**: Follow OWASP guidelines\n"},

        // Lab Instructions
        {"lab-instructions", "text/plain",
         "TLS 1.3 SECURE DOCUMENT SERVER - LAB INSTRUCTIONS\n"
         "==================================================\n\n"
         "OBJECTIVE\n"
         "---------\n"
         "Build a secure document retrieval system using TLS 1.3, demonstrating:\n"
         "1. Protocol enforcement (TLS 1.3 only)\n"
         "2. AEAD encryption (AES-GCM cipher suites)\n"
         "3. Perfect Forward Secrecy (ephemeral key exchange)\n"
         "4. Performance analysis (latency and throughput)\n\n"
         "PREREQUISITES\n"
         "-------------\n"
         "• Linux environment (Ubuntu 20.04+ or Kali Linux)\n"
         "• OpenSSL 3.x\n"
         "• C++17 compiler (g++ 9.0+)\n"
         "• SQLite3\n"
         "• Wireshark (for packet analysis)\n\n"
         "BUILD INSTRUCTIONS\n"
         "------------------\n"
         "1. Clone the repository\n"
         "2. Build: make clean && make\n"
         "3. Generate certificates:\n"
         "   openssl req -x509 -newkey rsa:2048 -nodes \\\n"
         "     -keyout certs/key.pem -out certs/cert.pem -days 365 \\\n"
         "     -subj \"/CN=localhost\"\n\n"
         "RUNNING THE SERVER\n"
         "------------------\n"
         "Terminal 1:\n"
         "  export LD_LIBRARY_PATH=/lib/x86_64-linux-gnu:$LD_LIBRARY_PATH\n"
         "  ./server\n\n"
         "TESTING\n"
         "-------\n"
         "Terminal 2:\n"
         "  # Fetch a document\n"
         "  ./client 127.0.0.1 8080 welcome certs/cert.pem 1\n\n"
         "  # Try with TLS 1.2 (should fail)\n"
         "  openssl s_client -connect 127.0.0.1:8080 -tls1_2\n\n"
         "PERFORMANCE TESTING\n"
         "-------------------\n"
         "Run comprehensive test suite:\n"
         "  ./scripts/run_tests_tui.py 127.0.0.1\n\n"
         "PACKET CAPTURE\n"
         "--------------\n"
         "In separate terminal:\n"
         "  sudo tcpdump -i lo -w capture.pcap tcp port 8080\n"
         "  wireshark capture.pcap\n\n"
         "EXPECTED RESULTS\n"
         "----------------\n"
         "✓ TLS 1.3 handshake completes successfully\n"
         "✓ TLS 1.2 connection attempts are rejected\n"
         "✓ Cipher suite: TLS_AES_256_GCM_SHA384 or TLS_AES_128_GCM_SHA256\n"
         "✓ Mean latency < 15ms (local network)\n"
         "✓ Throughput > 50 RPS\n"
         "✓ No memory leaks (valgrind clean)\n\n"
         "DELIVERABLES\n"
         "------------\n"
         "1. Working implementation (server + client)\n"
         "2. Performance measurements\n"
         "3. Packet captures (PCAP files)\n"
         "4. Written report (ACM format)\n\n"
         "QUESTIONS?\n"
         "----------\n"
         "See: docs/README.md, docs/WIRESHARK_ANALYSIS_GUIDE.md\n"},

        // Simple readme (backward compatibility)
        {"readme", "text/plain",
         "TLS 1.3 Secure Document Server\n"
         "===============================\n\n"
         "This server demonstrates secure document retrieval over TLS 1.3.\n\n"
         "Key Features:\n"
         "• TLS 1.3 only (rejects legacy protocols)\n"
         "• AEAD encryption (AES-GCM)\n"
         "• Perfect Forward Secrecy\n"
         "• SQLite document storage\n"
         "• JSON structured logging\n\n"
         "Usage:\n"
         "  ./client 127.0.0.1 8080 <document-id> certs/cert.pem 1\n\n"
         "Available documents:\n"
         "  welcome, readme, tls13-spec, course-catalog, student-records\n"
         "  cryptography-primer, research-data, architecture-diagram\n"
         "  openssl-guide, performance-analysis, unb-info\n"
         "  security-practices, lab-instructions\n"
         "  doc-1kb, doc-10kb (performance testing)\n\n"
         "For more information, request the 'lab-instructions' document.\n"}
    };

    for (const auto &seed : seeds) {
        sqlite3_bind_text(stmt, 1, seed.id, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, seed.mime, -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 3, seed.body, static_cast<int>(strlen(seed.body)), SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_reset(stmt);
    }
    sqlite3_finalize(stmt);

    std::cout << "{\"type\":\"seed\",\"count\":" << (sizeof(seeds) / sizeof(seeds[0]))
              << ",\"status\":\"complete\"}" << std::endl;
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
