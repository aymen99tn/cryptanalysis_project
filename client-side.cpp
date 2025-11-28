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
#include <sstream>
#include <string>

constexpr int kDefaultPort = 8080;
constexpr const char *kDefaultHost = "127.0.0.1";
constexpr const char *kDefaultDoc = "welcome";
constexpr size_t kMaxContentLength = 1 << 20;  // 1 MiB cap to avoid runaway allocations
constexpr int kSocketTimeoutSeconds = 5;

static void log_ssl_errors(const std::string &ctx) {
    unsigned long err;
    while ((err = ERR_get_error()) != 0) {
        char buf[256];
        ERR_error_string_n(err, buf, sizeof(buf));
        std::cerr << ctx << ": " << buf << std::endl;
    }
}

static SSL_CTX *create_client_context(const std::string &ca_path, bool verify) {
    const SSL_METHOD *method = TLS_client_method();
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

    if (SSL_CTX_set_ciphersuites(ctx, "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256") != 1) {
        log_ssl_errors("set_ciphersuites");
        std::exit(EXIT_FAILURE);
    }

    if (verify) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, nullptr);
        SSL_CTX_set_default_verify_paths(ctx);
        if (SSL_CTX_load_verify_locations(ctx, ca_path.c_str(), nullptr) != 1) {
            log_ssl_errors("load_verify_locations");
            std::exit(EXIT_FAILURE);
        }
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
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
    setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
    setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
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

int main(int argc, char **argv) {
    std::string host = std::getenv("SERVER_HOST") ? std::getenv("SERVER_HOST") : kDefaultHost;
    int port = std::getenv("SERVER_PORT") ? std::atoi(std::getenv("SERVER_PORT")) : kDefaultPort;
    std::string doc_id = (argc >= 2) ? argv[1] : kDefaultDoc;
    const char *ca_env = std::getenv("TLS_CA_CERT");
    bool verify = ca_env && std::strlen(ca_env) > 0;
    std::string ca_path = ca_env ? ca_env : "";

    OPENSSL_init_ssl(0, nullptr);

    SSL_CTX *ctx = create_client_context(ca_path, verify);

    int sock = connect_tcp(host, port);
    if (sock < 0) {
        std::cerr << "Failed to connect to " << host << ":" << port << std::endl;
        return EXIT_FAILURE;
    }
    set_socket_timeouts(sock);

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);
    SSL_set_tlsext_host_name(ssl, host.c_str());

    if (verify) {
        X509_VERIFY_PARAM *param = SSL_get0_param(ssl);
        X509_VERIFY_PARAM_set1_host(param, host.c_str(), 0);
    }

    if (SSL_connect(ssl) <= 0) {
        log_ssl_errors("SSL_connect");
        SSL_free(ssl);
        close(sock);
        return EXIT_FAILURE;
    }

    const SSL_CIPHER *cipher = SSL_get_current_cipher(ssl);
    std::cout << "Negotiated " << SSL_get_version(ssl) << " / " << SSL_CIPHER_get_name(cipher) << std::endl;

    std::string request = "GET " + doc_id + "\n";
    if (SSL_write(ssl, request.data(), static_cast<int>(request.size())) <= 0) {
        log_ssl_errors("SSL_write");
        SSL_free(ssl);
        close(sock);
        return EXIT_FAILURE;
    }

    std::string header;
    if (!recv_line(ssl, header)) {
        SSL_free(ssl);
        close(sock);
        return EXIT_FAILURE;
    }

    if (header.rfind("OK ", 0) != 0) {
        std::cerr << "Server error: " << header << std::endl;
        SSL_free(ssl);
        close(sock);
        return EXIT_FAILURE;
    }

    std::istringstream iss(header.substr(3));
    std::string mime;
    size_t content_len = 0;
    iss >> mime >> content_len;
    if (mime.empty() || content_len == 0) {
        std::cerr << "Malformed header: " << header << std::endl;
        SSL_free(ssl);
        close(sock);
        return EXIT_FAILURE;
    }

    if (content_len > kMaxContentLength) {
        std::cerr << "Content length exceeds cap (" << content_len << " > " << kMaxContentLength << ")" << std::endl;
        SSL_free(ssl);
        close(sock);
        return EXIT_FAILURE;
    }

    std::string body;
    if (!recv_exact(ssl, body, content_len)) {
        SSL_free(ssl);
        close(sock);
        return EXIT_FAILURE;
    }

    std::cout << "Received " << content_len << " bytes (" << mime << "):\n" << body << std::endl;

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    return 0;
}
