#include "openssl/ssl.h"
#include "openssl/err.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string.h>

#include <openssl/applink.c>

#define PORT 8080

void initialize_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

void cleanup_openssl() {
    EVP_cleanup();
}

SSL_CTX *create_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = TLS_server_method();

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, "cert.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, "key.pem", SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    const char *ciphersuites = "TLS_AES_256_GCM_SHA384:TLS_AES_128_GCM_SHA256";
    if (SSL_CTX_set_ciphersuites(ctx, ciphersuites) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
}

void log_ssl_error() {
    unsigned long err_code;
    char err_buf[256];
    while ((err_code = ERR_get_error()) != 0) {
        ERR_error_string_n(err_code, err_buf, sizeof(err_buf));
        std::cerr << "SSL error: " << err_buf << std::endl;
    }
}

int main(int argc, char **argv) {
    int sock;
    SSL_CTX *ctx;

    WSADATA wsaData;
    int wsaerr = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (wsaerr != 0) {
        std::cerr << "WSAStartup failed: " << wsaerr << std::endl;
        return EXIT_FAILURE;
    }

    initialize_openssl();
    ctx = create_context();

    configure_context(ctx);

    struct sockaddr_in addr;
    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        log_ssl_error();
        return EXIT_FAILURE;
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        log_ssl_error();
        return EXIT_FAILURE;
    }

    if (listen(sock, 1) < 0) {
        perror("Unable to listen");
        log_ssl_error();
        return EXIT_FAILURE;
    }

    while (1) {
        struct sockaddr_in addr;
        int len = sizeof(addr);
        SSL *ssl;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            perror("Unable to accept");
            log_ssl_error();
            return EXIT_FAILURE;
        }

        std::cout << "Accepted connection from client" << std::endl;

        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            log_ssl_error();
            SSL_free(ssl);
            closesocket(client);
            continue;
        }

        std::cout << "SSL Handshake completed" << std::endl;

        const char reply[] = "Hello, secure Pico W!";
        int ret = SSL_write(ssl, reply, strlen(reply));
        if (ret <= 0) {
            log_ssl_error();
        } else {
            std::cout << "Sent message: " << reply << std::endl;
        }

        char buf[1024];
        while (1) {
            ret = SSL_read(ssl, buf, sizeof(buf) - 1);
            if (ret <= 0) {
                if (ret < 0) {
                    log_ssl_error();
                }
                break;
            }
            buf[ret] = '\0';
            std::cout << "Received message: " << buf << std::endl;

            // Optional: Echo the received message back to the client
            ret = SSL_write(ssl, buf, ret);
            if (ret <= 0) {
                log_ssl_error();
                break;
            }
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        closesocket(client);
    }

    closesocket(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();
    WSACleanup();

    return 0;
}















