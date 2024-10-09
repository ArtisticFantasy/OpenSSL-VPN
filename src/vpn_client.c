#include "vpn_common.h"

#define SERVER_IP "127.0.0.1"

int main() {

    setup_signal_handler();

    int sock;
    struct sockaddr_in server_addr;
    SSL_CTX *ctx;
    SSL *ssl;

    init_openssl();
    ctx = create_client_context();
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("Invalid address/ Address not supported");
        exit(EXIT_FAILURE);
    }

    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0) {
        ERR_print_errors_fp(stderr);
    } else {
        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));
        SSL_write(ssl, "Hello, SSL VPN server!", strlen("Hello, SSL VPN server!"));
    }

    char buf[1000];
    int bytes = SSL_read(ssl, buf, 500);
    if (bytes > 0) {
        buf[bytes] = 0;
        char *slash = strchr(buf, '/');
        if (!slash) {
            fprintf(stderr, "Address received from server is broken\n");
            exit(EXIT_FAILURE);
        }
        printf("Assigned ipv4 address by server: %s\n", buf);
        *slash = '\0';
        setup_tun("vpn-clt-tun", inet_addr(buf), atoi(slash + 1), &tun_fd, &sk_fd);
        atexit(clean_up_all);
    } else {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    while(1);

    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}