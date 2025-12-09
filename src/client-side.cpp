#include <arpa/inet.h>
#include <netdb.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/time.h>
#include <unistd.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <sstream>
#include <string>
#include <chrono>
#include <iomanip>

// ANSI Color codes for terminal output
namespace Color {
    constexpr const char* RESET = "\033[0m";
    constexpr const char* BOLD = "\033[1m";
    constexpr const char* DIM = "\033[2m";

    constexpr const char* RED = "\033[31m";
    constexpr const char* GREEN = "\033[32m";
    constexpr const char* YELLOW = "\033[33m";
    constexpr const char* BLUE = "\033[34m";
    constexpr const char* MAGENTA = "\033[35m";
    constexpr const char* CYAN = "\033[36m";
    constexpr const char* WHITE = "\033[37m";

    constexpr const char* BRIGHT_GREEN = "\033[92m";
    constexpr const char* BRIGHT_YELLOW = "\033[93m";
    constexpr const char* BRIGHT_BLUE = "\033[94m";
    constexpr const char* BRIGHT_CYAN = "\033[96m";
}

constexpr int kDefaultPort = 8080;
constexpr const char *kDefaultHost = "127.0.0.1";
constexpr const char *kDefaultDoc = "welcome";
constexpr const char *kDefaultCaCert = "";
constexpr size_t kMaxContentLength = 1 << 20;  // 1 MiB cap to avoid runaway allocations
constexpr int kSocketTimeoutSeconds = 5;

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

using UniqueSSL = std::unique_ptr<SSL, SSLDeleter>;
using UniqueSSLCtx = std::unique_ptr<SSL_CTX, SSLCtxDeleter>;

static void log_ssl_errors(const std::string &ctx) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << Color::RED << "✗ " << ctx << ": " << buf << Color::RESET << std::endl;
    }
}

// Format file size in human-readable format
static std::string format_size(size_t bytes) {
    const char* units[] = {"B", "KB", "MB", "GB"};
    int unit_index = 0;
    double size = static_cast<double>(bytes);

    while (size >= 1024.0 && unit_index < 3) {
        size /= 1024.0;
        unit_index++;
    }

    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << size << " " << units[unit_index];
    return oss.str();
}

// Simple syntax highlighting for content preview
static void print_content_preview(const std::string& content, const std::string& mime, size_t max_lines = 20) {
    std::istringstream iss(content);
    std::string line;
    size_t line_count = 0;
    bool is_json = (mime.find("json") != std::string::npos);
    bool is_html = (mime.find("html") != std::string::npos);
    bool is_csv = (mime.find("csv") != std::string::npos);

    std::cout << Color::DIM << "─────────────────────────────────────────────────────────" << Color::RESET << std::endl;

    while (std::getline(iss, line) && line_count < max_lines) {
        if (is_json || is_html || is_csv) {
            // Simple highlighting for structured data
            if (line.find('{') != std::string::npos || line.find('[') != std::string::npos) {
                std::cout << Color::CYAN << line << Color::RESET << std::endl;
            } else if (line.find('<') != std::string::npos) {
                std::cout << Color::MAGENTA << line << Color::RESET << std::endl;
            } else {
                std::cout << line << std::endl;
            }
        } else {
            std::cout << line << std::endl;
        }
        line_count++;
    }

    // Show truncation indicator if content is long
    size_t total_lines = line_count;
    while (std::getline(iss, line)) total_lines++;

    if (total_lines > max_lines) {
        std::cout << Color::DIM << "... (" << (total_lines - max_lines) << " more lines)" << Color::RESET << std::endl;
    }
    std::cout << Color::DIM << "─────────────────────────────────────────────────────────" << Color::RESET << std::endl;
}

static UniqueSSLCtx create_client_context(const std::string &ca_path, bool verify) {
    const SSL_METHOD *method = TLS_client_method();
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

    if (SSL_CTX_set_ciphersuites(ctx.get(), "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256") != 1) {
        log_ssl_errors("set_ciphersuites");
        std::exit(EXIT_FAILURE);
    }

    // Enable TLS 1.3 session resumption (client side)
    SSL_CTX_set_session_cache_mode(ctx.get(), SSL_SESS_CACHE_CLIENT);

    if (verify) {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_default_verify_paths(ctx.get());
        if (SSL_CTX_load_verify_locations(ctx.get(), ca_path.c_str(), nullptr) != 1) {
            log_ssl_errors("load_verify_locations");
            std::exit(EXIT_FAILURE);
        }
    } else {
        SSL_CTX_set_verify(ctx.get(), SSL_VERIFY_NONE, nullptr);
    }

    return ctx;
}

static int connect_tcp(const std::string &host, int port) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    addrinfo *res = nullptr;
    std::string port_str = std::to_string(port);
    int rc = getaddrinfo(host.c_str(), port_str.c_str(), &hints, &res);
    if (rc != 0) {
        std::cerr << "getaddrinfo: " << gai_strerror(rc) << std::endl;
        return -1;
    }

    int sock = -1;
    for (addrinfo *p = res; p; p = p->ai_next) {
        sock = ::socket(p->ai_family, p->ai_socktype, p->ai_protocol);
        if (sock < 0) continue;
        if (connect(sock, p->ai_addr, p->ai_addrlen) == 0) {
            break;
        }
        close(sock);
        sock = -1;
    }

    freeaddrinfo(res);
    return sock;
}

static void set_socket_timeouts(int sock) {
    timeval tv{};
    tv.tv_sec = kSocketTimeoutSeconds;
    tv.tv_usec = 0;
    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_RCVTIMEO");
    }
    if (setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv)) < 0) {
        perror("setsockopt SO_SNDTIMEO");
    }
}

static bool recv_line(SSL *ssl, std::string &out) {
    out.clear();
    char ch;
    while (true) {
        int ret = SSL_read(ssl, &ch, 1);
        if (ret <= 0) {
            log_ssl_errors("SSL_read");
            return false;
        }
        if (ch == '\n') break;
        out.push_back(ch);
    }
    return true;
}

static bool recv_exact(SSL *ssl, std::string &out, size_t len) {
    out.resize(len);
    size_t got = 0;
    while (got < len) {
        int ret = SSL_read(ssl, out.data() + got, static_cast<int>(len - got));
        if (ret <= 0) {
            log_ssl_errors("SSL_read");
            return false;
        }
        got += static_cast<size_t>(ret);
    }
    return true;
}

static void print_usage(const char *prog_name) {
    std::cerr << "Usage: " << prog_name << " [host] [port] [doc_id] [ca_file] [verify]\n"
              << "  host     - Server hostname/IP (default: " << kDefaultHost << ")\n"
              << "  port     - Server port (default: " << kDefaultPort << ")\n"
              << "  doc_id   - Document ID to fetch (default: " << kDefaultDoc << ")\n"
              << "  ca_file  - CA certificate file for verification (default: none)\n"
              << "  verify   - Enable certificate verification: 0 or 1 (default: 0)\n"
              << "\nEnvironment variables:\n"
              << "  SERVER_HOST - Override default host\n"
              << "  SERVER_PORT - Override default port\n"
              << "  TLS_CA_CERT - CA certificate path\n";
}

int main(int argc, char **argv) {
    // Parse command-line arguments according to documented interface
    std::string host = kDefaultHost;
    int port = kDefaultPort;
    std::string doc_id = kDefaultDoc;
    std::string ca_path = kDefaultCaCert;
    bool verify = false;

    if (argc > 1) {
        if (std::strcmp(argv[1], "-h") == 0 || std::strcmp(argv[1], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
        host = argv[1];
    }
    if (argc > 2) {
        port = std::atoi(argv[2]);
        if (port <= 0 || port > 65535) {
            std::cerr << "Invalid port number: " << argv[2] << std::endl;
            return EXIT_FAILURE;
        }
    }
    if (argc > 3) {
        doc_id = argv[3];
    }
    if (argc > 4) {
        ca_path = argv[4];
    }
    if (argc > 5) {
        verify = (std::strcmp(argv[5], "1") == 0 || std::strcmp(argv[5], "true") == 0);
    }

    // Environment variables can still override
    const char *host_env = std::getenv("SERVER_HOST");
    const char *port_env = std::getenv("SERVER_PORT");
    const char *ca_env = std::getenv("TLS_CA_CERT");

    if (host_env) host = host_env;
    if (port_env) {
        port = std::atoi(port_env);
        if (port <= 0 || port > 65535) {
            std::cerr << "Invalid SERVER_PORT: " << port_env << std::endl;
            return EXIT_FAILURE;
        }
    }
    if (ca_env && std::strlen(ca_env) > 0) {
        ca_path = ca_env;
        verify = true;
    }

    OPENSSL_init_ssl(0, nullptr);

    UniqueSSLCtx ctx = create_client_context(ca_path, verify);

    int sock = connect_tcp(host, port);
    if (sock < 0) {
        std::cerr << "Failed to connect to " << host << ":" << port << std::endl;
        return EXIT_FAILURE;
    }
    set_socket_timeouts(sock);

    SSL *raw_ssl = SSL_new(ctx.get());
    if (!raw_ssl) {
        log_ssl_errors("SSL_new");
        close(sock);
        return EXIT_FAILURE;
    }

    UniqueSSL ssl(raw_ssl);
    SSL_set_fd(ssl.get(), sock);
    SSL_set_tlsext_host_name(ssl.get(), host.c_str());

    if (verify) {
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl.get());
        X509_VERIFY_PARAM_set1_host(param, host.c_str(), 0);
    }

    // Track timing for performance display
    auto start_time = std::chrono::steady_clock::now();

    if (SSL_connect(ssl.get()) <= 0) {
        log_ssl_errors("SSL_connect");
        close(sock);
        return EXIT_FAILURE;
    }

    // Display connection success with colors
    std::cout << Color::BRIGHT_GREEN << "✓ " << Color::RESET
              << Color::BOLD << "Connected to " << host << ":" << port << Color::RESET << std::endl;

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl.get());
    bool resumed = SSL_session_reused(ssl.get());

    // Display TLS info with lock emoji and colors
    std::cout << Color::BRIGHT_CYAN << "🔒 " << Color::RESET
              << Color::BOLD << SSL_get_version(ssl.get()) << Color::RESET << " "
              << Color::CYAN << "(" << SSL_CIPHER_get_name(cipher) << ")" << Color::RESET;
    if (resumed) {
        std::cout << Color::YELLOW << " [Session: Resumed]" << Color::RESET;
    } else {
        std::cout << Color::GREEN << " [Session: New]" << Color::RESET;
    }
    std::cout << std::endl;

    std::string request = "GET " + doc_id + "\n";
    if (SSL_write(ssl.get(), request.data(), static_cast<int>(request.size())) <= 0) {
        log_ssl_errors("SSL_write");
        close(sock);
        return EXIT_FAILURE;
    }

    std::string header;
    if (!recv_line(ssl.get(), header)) {
        close(sock);
        return EXIT_FAILURE;
    }

    if (header.rfind("OK ", 0) != 0) {
        std::cerr << Color::RED << "✗ Server error: " << Color::RESET << header << std::endl;
        close(sock);
        return EXIT_FAILURE;
    }

    std::istringstream iss(header.substr(3));
    std::string mime;
    size_t content_len = 0;
    iss >> mime >> content_len;

    // Validate parsing succeeded
    if (iss.fail() || mime.empty()) {
        std::cerr << Color::RED << "✗ Malformed header: " << Color::RESET << header << std::endl;
        close(sock);
        return EXIT_FAILURE;
    }

    if (content_len == 0) {
        std::cout << Color::YELLOW << "⚠ Received empty document (" << mime << ")" << Color::RESET << std::endl;
        close(sock);
        return EXIT_SUCCESS;
    }

    if (content_len > kMaxContentLength) {
        std::cerr << Color::RED << "✗ Content length exceeds cap (" << content_len << " > " << kMaxContentLength << ")" << Color::RESET << std::endl;
        close(sock);
        return EXIT_FAILURE;
    }

    std::string body;
    if (!recv_exact(ssl.get(), body, content_len)) {
        close(sock);
        return EXIT_FAILURE;
    }

    auto end_time = std::chrono::steady_clock::now();
    auto duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end_time - start_time).count();

    // Display document info with emoji and colors
    std::cout << Color::BRIGHT_BLUE << "📄 " << Color::RESET
              << Color::BOLD << "Document: " << doc_id << Color::RESET
              << " " << Color::DIM << "(" << mime << ", " << format_size(content_len) << ")" << Color::RESET << std::endl;

    // Show content preview with syntax highlighting
    std::cout << std::endl;
    print_content_preview(body, mime);
    std::cout << std::endl;

    // Performance metrics
    std::cout << Color::BRIGHT_YELLOW << "⏱  " << Color::RESET
              << Color::BOLD << "Response time: " << Color::RESET
              << Color::GREEN << duration_ms << " ms" << Color::RESET << std::endl;

    // Calculate and display throughput
    double throughput_mbps = (content_len * 8.0 / 1024.0 / 1024.0) / (duration_ms / 1000.0);
    std::cout << Color::BRIGHT_YELLOW << "📊 " << Color::RESET
              << Color::BOLD << "Throughput: " << Color::RESET
              << Color::GREEN << std::fixed << std::setprecision(2) << throughput_mbps << " Mbps" << Color::RESET << std::endl;

    // Cleanup handled automatically by RAII
    close(sock);
    return EXIT_SUCCESS;
}
