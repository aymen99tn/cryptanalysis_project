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
        std::cerr << ctx << ": " << buf << std::endl;
    }
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

    if (SSL_connect(ssl.get()) <= 0) {
        log_ssl_errors("SSL_connect");
        close(sock);
        return EXIT_FAILURE;
    }

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl.get());
    bool resumed = SSL_session_reused(ssl.get());
    std::cout << "Negotiated " << SSL_get_version(ssl.get()) << " / " << SSL_CIPHER_get_name(cipher);
    if (resumed) {
        std::cout << " (session resumed)";
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
        std::cerr << "Server error: " << header << std::endl;
        close(sock);
        return EXIT_FAILURE;
    }

    std::istringstream iss(header.substr(3));
    std::string mime;
    size_t content_len = 0;
    iss >> mime >> content_len;

    // Validate parsing succeeded
    if (iss.fail() || mime.empty()) {
        std::cerr << "Malformed header: " << header << std::endl;
        close(sock);
        return EXIT_FAILURE;
    }

    if (content_len == 0) {
        std::cout << "Received empty document (" << mime << ")" << std::endl;
        close(sock);
        return EXIT_SUCCESS;
    }

    if (content_len > kMaxContentLength) {
        std::cerr << "Content length exceeds cap (" << content_len << " > " << kMaxContentLength << ")" << std::endl;
        close(sock);
        return EXIT_FAILURE;
    }

    std::string body;
    if (!recv_exact(ssl.get(), body, content_len)) {
        close(sock);
        return EXIT_FAILURE;
    }

    std::cout << "Received " << content_len << " bytes (" << mime << "):\n" << body << std::endl;

    // Cleanup handled automatically by RAII
    close(sock);
    return EXIT_SUCCESS;
}
