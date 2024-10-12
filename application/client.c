#include "common/common.h"
#include "common/signal.h"
#include "common/application.h"
#include "network/subnet.h"
#include "network/setup.h"
#include "utils/ssl.h"

#define CLIENT_KEEP_ALIVE_INTERVAL 100

int tun_fd = -1, sk_fd = -1;
char *vpn_tun_name;
int route_added = 0;
in_addr_t ip_addr;
char subnet_str[100];
int prefix_len;

REGISTER_CLEAN_UP

void *tun_to_ssl(SSL *ssl) {
    char buf[70000];
    in_addr_t subnet_addr = ip_addr & get_netmask(prefix_len);
    while (1) {
#ifdef __linux__
        int bytes = read(tun_fd, buf, sizeof(buf));
#elif __APPLE__
        int bytes = mac_read_tun(tun_fd, buf, sizeof(buf));
#endif

        if (bytes <= 0) {
            return NULL;
        }

#ifdef __linux__
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
#elif __APPLE__
        if (bytes < sizeof(struct ip)) {
            continue;
        }
        struct ip *iph = (struct ip *)buf;
        if ((iph->ip_dst.s_addr & get_netmask(prefix_len)) != subnet_addr) {
            continue;
        }
        
        if (iph->ip_dst.s_addr == ip_addr) {
            continue;
        }
#endif
        SSL_write(ssl, buf, bytes);
    }
}

void *ssl_to_tun(SSL *ssl) {
    char buf[70000];
    while (1) {
        int bytes = SSL_read(ssl, buf, sizeof(buf));
        if (bytes > 0) {
#ifdef __linux__
            write(tun_fd, buf, bytes);
#elif __APPLE__
            mac_write_tun(tun_fd, buf, bytes);
#endif
        }
        else {
            return NULL;
        }
    }
}

void *keep_alive(SSL *ssl) {
    while (1) {
        sleep(CLIENT_KEEP_ALIVE_INTERVAL);
        SSL_write(ssl, "hello", strlen("hello"));
    }
}

int sock;
SSL_CTX *ctx;
SSL *ssl;

void handle_alarm(int signal) {
    application_log(stderr, "Time expired when connecting server!\n");
    close(sock);
    SSL_CTX_free(ctx);
    exit(EXIT_FAILURE);
}

int main(int argc, char **argv) {

    if (argc < 2) {
        application_log(stderr, "Usage: %s <server_public_address>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    char *server_ip = argv[1];

    setup_signal_handler();
    atexit(clean_up_all);

    struct sockaddr_in server_addr;

    init_openssl();
    ctx = create_client_context();
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        application_log(stderr, "Unable to create socket");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, server_ip, &server_addr.sin_addr) <= 0) {
        application_log(stderr, "Invalid address / Address not supported");
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    signal(SIGALRM, handle_alarm);
    struct itimerval timer;
    timer.it_value.tv_sec = 5;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, NULL);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        application_log(stderr, "Connecting to server failed");
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    timer.it_value.tv_sec = 0;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, NULL);

    ssl = SSL_new(ctx);
    SSL_set_fd(ssl, sock);

    if (SSL_connect(ssl) <= 0 || SSL_get_verify_result(ssl) != X509_V_OK) {
        application_log(stderr, "Cannot verify server's identity, connection closed.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    char buf[1000];
    int bytes = SSL_read(ssl, buf, 500);
    if (bytes > 0) {
        application_log(stdout, "Connected with %s encryption.\n", SSL_get_cipher(ssl));
        buf[bytes] = 0;
        char *slash = strchr(buf, '/');
        if (!slash) {
            application_log(stderr, "Address received from server is broken\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
        *slash = '\0';
        ip_addr = inet_addr(buf);
        if (ip_addr == INADDR_NONE) {
            application_log(stderr, "Address received from server is broken\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
        prefix_len = atoi(slash + 1);
        *slash = '/';
        application_log(stdout, "Assigned IPv4 address by server: %s\n", buf);
        setup_tun(&vpn_tun_name, ip_addr, prefix_len, &tun_fd, &sk_fd);
        in_addr_t subnet_addr = ip_addr & get_netmask(prefix_len);
        sprintf(subnet_str, "%s/%d", inet_ntoa(*(struct in_addr *)&subnet_addr), prefix_len);
        add_route(subnet_str, inet_ntoa(*(struct in_addr *)&ip_addr), vpn_tun_name);
        route_added = 1;
    } else {
        application_log(stderr, "Connection rejected by server.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
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
    

    application_log(stderr, "Connection closed by server.\n");

    // Do the cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}