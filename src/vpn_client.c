#include "vpn_common.h"

int prefix_len;

void *tun_to_ssl(SSL *ssl) {
    char buf[70000];
    in_addr_t subnet_addr = ip_addr & get_netmask(prefix_len);
    while (1) {
        int bytes = read(tun_fd, buf, sizeof(buf));

        if (bytes <= 0) {
            return NULL;
        }

        if (bytes < sizeof(struct iphdr)) {
            continue;
        }

        struct iphdr *iph = (struct iphdr *)buf;
        if ((iph->daddr & get_netmask(prefix_len)) != subnet_addr) {
            continue;
        }
        
        if (iph->daddr == ip_addr) {
            continue;
        }

        SSL_write(ssl, buf, bytes);
    }
}

void *ssl_to_tun(SSL *ssl) {
    char buf[70000];
    while (1) {
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes > 0) {
            write(tun_fd, buf, bytes);
        }
        else {
            return NULL;
        }
    }
}

void *keep_alive(SSL *ssl) {
    while (1) {
        sleep(200);
        SSL_write(ssl, "hello", strlen("hello"));
    }
}

int main(int argc, char **argv) {

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <server_public_address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];

    setup_signal_handler();
    atexit(clean_up_all);

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
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
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
    }

    char buf[1000];
    int bytes = SSL_read(ssl, buf, 500);
    if (bytes > 0) {
        buf[bytes] = 0;
        char *slash = strchr(buf, '/');
        if (!slash) {
            fprintf(stderr, "Address received from server is broken\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);
            exit(EXIT_FAILURE);
        }
        *slash = '\0';
        ip_addr = inet_addr(buf);
        if (ip_addr == INADDR_NONE) {
            fprintf(stderr, "Address received from server is broken\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);
            exit(EXIT_FAILURE);
        }
        prefix_len = atoi(slash + 1);
        *slash = '/';
        printf("Assigned ipv4 address by server: %s\n", buf);
        setup_tun("vpn-clt-tun", ip_addr, prefix_len, &tun_fd, &sk_fd);
        
        in_addr_t subnet_addr = ip_addr & get_netmask(prefix_len);
        sprintf(subnet_str, "%s/%d", inet_ntoa(*(struct in_addr *)&subnet_addr), prefix_len);
        add_route(subnet_str, inet_ntoa(*(struct in_addr *)&ip_addr), "vpn-clt-tun");
        vpn_tun_name = "vpn-clt-tun";
    } else {
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }


    // There will be two threads, one for reading from tun and writing to ssl, the other for reading from ssl and writing to tun
    pthread_t tun_to_ssl_thread, ssl_to_tun_thread, keep_alive_thread;
    pthread_create(&tun_to_ssl_thread, NULL, (void*)tun_to_ssl, ssl);
    pthread_create(&ssl_to_tun_thread, NULL, (void*)ssl_to_tun, ssl);
    pthread_create(&keep_alive_thread, NULL, (void*)keep_alive, ssl);
    pthread_join(ssl_to_tun_thread, NULL);
    pthread_cancel(tun_to_ssl_thread);
    pthread_cancel(keep_alive_thread);
    pthread_join(tun_to_ssl_thread, NULL);
    pthread_join(keep_alive_thread, NULL);
    

    fprintf(stderr, "Connection closed by server\n");

    // Do the cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}