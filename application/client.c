#include "common/common.h"
#include "common/signal.h"
#include "common/application.h"
#include "network/subnet.h"
#include "network/setup.h"
#include "utils/ssl.h"

#define CLIENT_KEEP_ALIVE_INTERVAL 200

extern uint16_t PORT;
extern uint16_t EXPECTED_HOST_ID;
extern in_addr_t SERVER_IP;
extern int TRAFFIC_CONFUSE;
extern int host_type;
int tun_fd = -1, sk_fd = -1;
char *vpn_tun_name;
int route_added = 0;
in_addr_t ip_addr;
char subnet_str[100];
int prefix_len;
int pkt_mean = 10;
struct timespec last_send;

REGISTER_CLEAN_UP

void *tun_to_ssl(SSL *ssl) {
    char *buf = (char*)malloc(MAX_PKT_SIZE * 2 + 20);
    in_addr_t subnet_addr = ip_addr & get_netmask(prefix_len);
    while (1) {
        int bytes = read_tun(tun_fd, buf, MAX_PKT_SIZE);

        if (bytes <= 0) {
            free(buf);
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
        int len = SSL_send_packet(ssl, buf, bytes, 1, TRAFFIC_CONFUSE ? random() % (bytes / 2 + 1) : 0);
        pkt_mean = 0.3 * len + 0.7 * pkt_mean;
        clock_gettime(CLOCK_MONOTONIC, &last_send);
    }
    free(buf);
}

void *ssl_to_tun(SSL *ssl) {
    char *buf = (char*)malloc(MAX_PKT_SIZE * 2 + 20);
    while (1) {
        int bytes = SSL_receive_packet(ssl, buf, MAX_PKT_SIZE * 2 + 20, 1);
        if (bytes != KEEP_ALIVE_CODE && bytes > 0) {
            write_tun(tun_fd, buf, bytes);
        }
        else if (bytes < 0) {
            free(buf);
            return NULL;
        }
    }
    free(buf);
}

void *keep_alive(SSL *ssl) {
    while (1) {
        sleep(CLIENT_KEEP_ALIVE_INTERVAL);
        SSL_send_packet(ssl, "hello", strlen("hello"), 1, 0);
    }
}

void *confuse(SSL *ssl) {
    struct timespec now;
    while (1) {
        double interval = (CONFUSE_MAX_INTERVAL - CONFUSE_MIN_INTERVAL) * (random() / (double)RAND_MAX) + CONFUSE_MIN_INTERVAL;
        sleep(interval);
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (!TRAFFIC_CONFUSE) {
            continue;
        }
        if (now.tv_sec - last_send.tv_sec <= ACTIVE_INTERVAL && pkt_mean > 0) {
            SSL_send_packet(ssl, "confuse", strlen("confuse"), 1, pkt_mean + random() % (pkt_mean / 10 + 1) - pkt_mean / 20);
        }
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
    host_type = CLIENT;

    setup_signal_handler();
    atexit(clean_up_all);

    struct option long_options[] = {
        {"config", required_argument, 0, 'c'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };

    char *config_file = NULL;

    int opt;
    while ((opt = getopt_long(argc, argv, "c:h", long_options, NULL)) != -1) {
        switch (opt) {
            case 'c':
                if (config_file) {
                    fprintf(stderr, "Multiple config files specified.\n");
                    exit(EXIT_FAILURE);
                }
                config_file = optarg;
                break;
            case 'h':
                printf("Usage: %s [-c <config_file>]\n", argv[0]);
                exit(EXIT_SUCCESS);
            default:
                fprintf(stderr, "Usage: %s [-c <config_file>]\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    if (optind < argc) {
        fprintf(stderr, "Invalid argument. Use option -h to get help.\n");
        exit(EXIT_FAILURE);
    }

    if (!config_file) {
        config_file = CONFIG_PATH "/config";
        application_log(stdout, "Using default config file: %s\n", config_file);
    }

    parse_config_file(config_file, 0);

    struct sockaddr_in server_addr;

    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        application_log(stderr, "Unable to create socket.\n");
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = SERVER_IP;

    signal(SIGALRM, handle_alarm);
    struct itimerval timer;
    timer.it_value.tv_sec = 5;
    timer.it_value.tv_usec = 0;
    timer.it_interval.tv_sec = 0;
    timer.it_interval.tv_usec = 0;
    setitimer(ITIMER_REAL, &timer, NULL);

    application_log(stdout, "Connecting to server %s:%d...\n", inet_ntoa(server_addr.sin_addr), PORT);
    if (connect(sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        application_log(stderr, "Connecting to server failed.\n");
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

    clock_gettime(CLOCK_MONOTONIC, &last_send);

    char traffic_confuse_str[MAX_PKT_SIZE * 2 + 20];
    int bytes = SSL_receive_packet(ssl, traffic_confuse_str, sizeof(traffic_confuse_str), 1);
    if (bytes <= 0) {
        application_log(stderr, "Connection rejected by server.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    application_log(stdout, "Connected with %s encryption.\n", SSL_get_cipher(ssl));

    if (bytes <= strlen(TRAFFIC_CONFUSE_HEADER) || strncmp(traffic_confuse_str, TRAFFIC_CONFUSE_HEADER, strlen(TRAFFIC_CONFUSE_HEADER)) != 0) {
        application_log(stderr, "Invalid response message from server, close connection.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }
    
    TRAFFIC_CONFUSE = atoi(traffic_confuse_str + strlen(TRAFFIC_CONFUSE_HEADER));

    if (TRAFFIC_CONFUSE < 0 || TRAFFIC_CONFUSE > 1) {
        application_log(stderr, "Invalid TRAFFIC_CONFUSE value received from server, close connection.\n");
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
        SSL_CTX_free(ctx);
        exit(EXIT_FAILURE);
    }

    application_log(stdout, "Setting traffic confuse: %d\n", TRAFFIC_CONFUSE);

    char buf[MAX_PKT_SIZE * 2 + 20];
    // Request the expected host id from server
    sprintf(buf, REQUEST_ADDR_HEADER "%d", EXPECTED_HOST_ID);
    SSL_send_packet(ssl, buf, strlen(buf), 1, 0);

    bytes = SSL_receive_packet(ssl, buf, sizeof(buf), 1);
    if (bytes > 0) {
        if (bytes <= strlen(RESPONSE_ADDR_HEADER) || strncmp(buf, RESPONSE_ADDR_HEADER, strlen(RESPONSE_ADDR_HEADER)) != 0) {
            application_log(stderr, "Invalid response message from server, close connection.\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
        buf[bytes] = 0;
        char *slash = strchr(buf + strlen(RESPONSE_ADDR_HEADER), '/');
        if (!slash) {
            application_log(stderr, "Address received from server is broken, close connection.\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }
        *slash = '\0';
        ip_addr = inet_addr(buf + strlen(RESPONSE_ADDR_HEADER));
        if (ip_addr == INADDR_NONE) {
            application_log(stderr, "Address received from server is broken, close connection.\n");
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);
            SSL_CTX_free(ctx);
            exit(EXIT_FAILURE);
        }

        prefix_len = atoi(slash + 1);
        *slash = '/';

        if (EXPECTED_HOST_ID && EXPECTED_HOST_ID != ntohl(ip_addr & ~get_netmask(prefix_len))) {
            application_log(stdout, "Server cannot satisfy requested host id, assigned host id: %d instead.\n", ntohl(ip_addr & ~get_netmask(prefix_len)));
        }
        
        application_log(stdout, "Assigned IPv4 address by server: %s\n", buf + strlen(RESPONSE_ADDR_HEADER));
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
    pthread_t tun_to_ssl_thread, ssl_to_tun_thread, keep_alive_thread, confuse_thread;
    pthread_create(&tun_to_ssl_thread, NULL, (void*)tun_to_ssl, ssl);
    pthread_create(&ssl_to_tun_thread, NULL, (void*)ssl_to_tun, ssl);
    pthread_create(&keep_alive_thread, NULL, (void*)keep_alive, ssl);
    pthread_create(&confuse_thread, NULL, (void*)confuse, ssl);
    
    pthread_join(ssl_to_tun_thread, NULL);
    pthread_cancel(tun_to_ssl_thread);
    pthread_cancel(keep_alive_thread);
    pthread_cancel(confuse_thread);
    pthread_join(tun_to_ssl_thread, NULL);
    pthread_join(keep_alive_thread, NULL);
    pthread_join(confuse_thread, NULL);

    application_log(stderr, "Connection closed by server.\n");

    // Do the cleanup
    SSL_shutdown(ssl);
    SSL_free(ssl);
    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}