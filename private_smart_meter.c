#include <stdio.h>
#include <string.h>
#include "pico/stdlib.h"
#include "pico/cyw43_arch.h"
#include "lwip/ip4_addr.h"
#include "lwip/tcp.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"

#define WIFI_SSID "Room 401"
#define WIFI_PASS "Frederict0n"
#define SERVER_IP "172.19.162.130" // Replace with your PC's IP address
#define SERVER_PORT 8080

static struct tcp_pcb *client_pcb;
static struct pbuf *recv_pbuf = NULL;

#define MY_ERR_NET_SEND_FAILED -0x1000
#define MY_ERR_NET_RECV_FAILED -0x2000

// Custom network send function
int my_net_send(void *ctx, const unsigned char *buf, size_t len) {
    struct tcp_pcb *pcb = (struct tcp_pcb *)ctx;
    err_t err = tcp_write(pcb, buf, len, TCP_WRITE_FLAG_COPY);
    if (err != ERR_OK) {
        return MY_ERR_NET_SEND_FAILED;
    }
    tcp_output(pcb);
    return len;
}

// Custom network receive function
int my_net_recv(void *ctx, unsigned char *buf, size_t len) {
    struct pbuf *p = recv_pbuf;
    if (!p) {
        return MBEDTLS_ERR_SSL_WANT_READ;
    }

    int copy_len = p->len;
    if (len < copy_len) {
        copy_len = len;
    }
    memcpy(buf, p->payload, copy_len);
    recv_pbuf = pbuf_free_header(recv_pbuf, copy_len);

    return copy_len;
}

// TCP receive callback
static err_t tcp_client_recv(void *arg, struct tcp_pcb *tpcb, struct pbuf *p, err_t err) {
    if (p == NULL) {
        // Connection closed
        tcp_close(tpcb);
        return ERR_OK;
    }
    if (recv_pbuf == NULL) {
        recv_pbuf = p;
    } else {
        pbuf_cat(recv_pbuf, p);
    }
    return ERR_OK;
}

static void tls_client(void);

int main() {
    stdio_init_all();
    if (cyw43_arch_init()) {
        printf("WiFi init failed\n");
        return -1;
    }
    cyw43_arch_enable_sta_mode();

    while (cyw43_arch_wifi_connect_timeout_ms(WIFI_SSID, WIFI_PASS, CYW43_AUTH_WPA2_AES_PSK, 10000)) {
        printf("Failed to connect to Wi-Fi, retrying...\n");
        sleep_ms(5000); // Wait for 5 seconds before retrying
    }

    printf("Connected to Wi-Fi.\n");

    while (true) {
        tls_client();
        cyw43_arch_poll();
    }

    return 0;
}

static void tls_client(void) {
    int ret;
    mbedtls_ssl_context ssl;
    mbedtls_ssl_config conf;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    const char *pers = "tls_client";
    unsigned char buf[1024];

    mbedtls_ssl_init(&ssl);
    mbedtls_ssl_config_init(&conf);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_entropy_init(&entropy);

    if ((ret = mbedtls_ctr_drbg_seed(&ctr_drbg, mbedtls_entropy_func, &entropy,
                                     (const unsigned char *)pers, strlen(pers))) != 0) {
        printf("mbedtls_ctr_drbg_seed failed: -0x%x\n", -ret);
        return;
    }

    ip4_addr_t server_ip;
    ip4addr_aton(SERVER_IP, &server_ip);

    while (true) {
        client_pcb = tcp_new_ip_type(IPADDR_TYPE_V4);
        if (!client_pcb) {
            printf("Failed to create PCB\n");
            sleep_ms(5000); // Wait for 5 seconds before retrying
            continue;
        }

        if (tcp_connect(client_pcb, &server_ip, SERVER_PORT, NULL) != ERR_OK) {
            printf("Failed to connect to server, retrying...\n");
            tcp_close(client_pcb);
            sleep_ms(5000); // Wait for 5 seconds before retrying
            continue;
        }

        break;
    }

    tcp_recv(client_pcb, tcp_client_recv);

    if ((ret = mbedtls_ssl_config_defaults(&conf, MBEDTLS_SSL_IS_CLIENT,
                                           MBEDTLS_SSL_TRANSPORT_STREAM,
                                           MBEDTLS_SSL_PRESET_DEFAULT)) != 0) {
        printf("mbedtls_ssl_config_defaults failed: -0x%x\n", -ret);
        return;
    }

    mbedtls_ssl_conf_authmode(&conf, MBEDTLS_SSL_VERIFY_NONE);
    mbedtls_ssl_conf_rng(&conf, mbedtls_ctr_drbg_random, &ctr_drbg);

    // Specify cipher suites
    const int ciphersuites[] = {
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
        MBEDTLS_TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
        0
    };
    mbedtls_ssl_conf_ciphersuites(&conf, ciphersuites);

    if ((ret = mbedtls_ssl_setup(&ssl, &conf)) != 0) {
        printf("mbedtls_ssl_setup failed: -0x%x\n", -ret);
        return;
    }

    if ((ret = mbedtls_ssl_set_hostname(&ssl, "localhost")) != 0) {
        printf("mbedtls_ssl_set_hostname failed: -0x%x\n", -ret);
        return;
    }

    mbedtls_ssl_set_bio(&ssl, client_pcb, my_net_send, my_net_recv, NULL);

    while ((ret = mbedtls_ssl_handshake(&ssl)) != 0) {
        if (ret != MBEDTLS_ERR_SSL_WANT_READ && ret != MBEDTLS_ERR_SSL_WANT_WRITE) {
            printf("mbedtls_ssl_handshake failed: -0x%x\n", -ret);
            return;
        }
    }

    printf("Connected to server\n");

    const char *message = "Hello, secure Pico W!";
    if ((ret = mbedtls_ssl_write(&ssl, (const unsigned char *)message, strlen(message))) <= 0) {
        printf("mbedtls_ssl_write failed: -0x%x\n", -ret);
        return;
    }

    // Read response from the server
    do {
        ret = mbedtls_ssl_read(&ssl, buf, sizeof(buf) - 1);
        if (ret == MBEDTLS_ERR_SSL_WANT_READ || ret == MBEDTLS_ERR_SSL_WANT_WRITE) {
            continue;
        }

        if (ret == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY) {
            printf("Connection was closed gracefully\n");
            break;
        }

        if (ret < 0) {
            printf("mbedtls_ssl_read failed: -0x%x\n", -ret);
            break;
        }

        if (ret == 0) {
            printf("Connection was closed by server\n");
            break;
        }

        buf[ret] = '\0';
        printf("Received: %s\n", buf);
    } while (1);

    mbedtls_ssl_close_notify(&ssl);

    mbedtls_ssl_free(&ssl);
    mbedtls_ssl_config_free(&conf);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_entropy_free(&entropy);
}