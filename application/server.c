#include "common/common.h"
#include "common/signal.h"
#include "common/application.h"
#include "network/subnet.h"
#include "network/setup.h"
#include "utils/ssl.h"

#define CLIENT_TIMEOUT 500
#define CHECK_CLIENT_ALIVE_INTERVAL 200

extern uint16_t PORT;
extern uint16_t EXPECTED_HOST_ID;
extern int TRAFFIC_CONFUSE;
extern int host_type;
int tun_fd = -1, sk_fd = -1;
char *vpn_tun_name;
int route_added = 0;
in_addr_t ip_addr;
char subnet_str[100];
in_addr_t subnet_addr;
int prefix_len;

char *valid_prefixes[3] = {"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"};

int used_ips[MAX_HOSTS] = {0};
in_addr_t real_iptable[MAX_HOSTS] = {0};
uint16_t real_ports[MAX_HOSTS] = {0};
int clients[MAX_HOSTS] = {0};
SSL *ssl_ctxs[MAX_HOSTS] = {0};
pthread_t threads[MAX_HOSTS] = {0};
pthread_t confuse_threads[MAX_HOSTS] = {0};
struct timespec last_active[MAX_HOSTS] = {0};
struct timespec last_send[MAX_HOSTS] = {0};
int pkt_mean[MAX_HOSTS] = {0};

REGISTER_CLEAN_UP

void reset_conn(int host_id) {
    in_addr_t host_addr = subnet_addr + htonl(host_id);
    application_log(stdout, "Close connection with %s:%d ", 
        inet_ntoa(*(struct in_addr *)&real_iptable[host_id]), real_ports[host_id]);
    printf("(%s/%d)\n",
        inet_ntoa(*(struct in_addr *)&host_addr), prefix_len);
    if (used_ips[host_id] == 0) {
        return;
    }
    used_ips[host_id] = 0;
    real_iptable[host_id] = 0;
    real_ports[host_id] = 0;
    SSL_shutdown(ssl_ctxs[host_id]);
    SSL_free(ssl_ctxs[host_id]);
    close(clients[host_id]);
    ssl_ctxs[host_id] = 0;
    clients[host_id] = 0;
    threads[host_id] = 0;
    confuse_threads[host_id] = 0;
}

int get_ip(long desired) {

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    if (desired != EXPECTED_HOST_ID && desired >= 1 && desired < (1 << (32 - prefix_len))) {
        if (!used_ips[desired]) {
            return desired;
        }
        else if (now.tv_sec - last_active[desired].tv_sec >= CLIENT_TIMEOUT) {
            pthread_cancel(threads[desired]);
            pthread_cancel(confuse_threads[desired]);
            pthread_join(threads[desired], NULL);
            pthread_join(confuse_threads[desired], NULL);
            reset_conn(desired);
            return desired;
        }
        else {
            if (pthread_kill(threads[desired], 0) != 0) {
                pthread_cancel(confuse_threads[desired]);
                pthread_join(threads[desired], NULL);
                pthread_join(confuse_threads[desired], NULL);
                reset_conn(desired);
                return desired;
            }
        }
    }

    for (int i = 1; i < (1 << (32 - prefix_len)); ++i) {
        if (i == EXPECTED_HOST_ID) {
            continue;
        }

        if (!used_ips[i]) {
            return i;
        }
        else if (now.tv_sec - last_active[i].tv_sec >= CLIENT_TIMEOUT) {
            pthread_cancel(threads[i]);
            pthread_cancel(confuse_threads[i]);
            pthread_join(threads[i], NULL);
            pthread_join(confuse_threads[i], NULL);
            reset_conn(i);
            return i;
        }
        else {
            if (pthread_kill(threads[i], 0) != 0) {
                pthread_cancel(confuse_threads[i]);
                pthread_join(threads[i], NULL);
                pthread_join(confuse_threads[i], NULL);
                reset_conn(i);
                return i;
            }
        }
    }
    return -1;
}

void *listen_and_deliver_packets(int *hostid) {
    int host_id = *hostid;
    char *buf = (char *)malloc(MAX_PKT_SIZE * 2 + 10);
    while (1) {
        int bytes = SSL_receive_packet(ssl_ctxs[host_id], buf, sizeof(buf), 0);
        in_addr_t host_addr = subnet_addr + htonl(host_id);

        if (bytes == KEEP_ALIVE_CODE){
            clock_gettime(CLOCK_MONOTONIC, &last_active[host_id]);
            application_log(stdout, "Received keep-alive message from %s:%d ", 
                inet_ntoa(*(struct in_addr *)&real_iptable[host_id]), real_ports[host_id]);
            printf("(%s/%d)\n",
                inet_ntoa(*(struct in_addr *)&host_addr), prefix_len);
            continue;
        }
        else if (bytes < 0) {
            pthread_cancel(confuse_threads[host_id]);
            pthread_join(confuse_threads[host_id], NULL);
            reset_conn(host_id);
            free(buf);
            return NULL;
        }
        else if (bytes == 0) {
            continue;
        }

#ifdef __linux__
        if (bytes < sizeof(struct iphdr)) {
            continue;
        }
        struct iphdr *iph = (struct iphdr *)(buf + sizeof(struct vpn_hdr));
        if ((iph->saddr != host_addr) || (iph->daddr & get_netmask(prefix_len)) != subnet_addr) {
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &last_active[host_id]);

        if (iph->daddr == ip_addr) {
            write_tun(tun_fd, buf + sizeof(struct vpn_hdr), bytes);
            continue;
        }

        if (!check_in_subnet(iph->daddr, subnet_addr, prefix_len)) {
            continue;
        }

        int target_host_id = ntohl(iph->daddr - subnet_addr);
#elif __APPLE__
        if (bytes < sizeof(struct ip)) {
            continue;
        }
        struct ip *iph = (struct ip *)(buf + sizeof(struct vpn_hdr));
        if ((iph->ip_src.s_addr != host_addr) || (iph->ip_dst.s_addr & get_netmask(prefix_len)) != subnet_addr) {
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &last_active[host_id]);

        if (iph->ip_dst.s_addr == ip_addr) {
            write_tun(tun_fd, buf + sizeof(struct vpn_hdr), bytes);
            continue;
        }

        if(!check_in_subnet(iph->ip_dst.s_addr, subnet_addr, prefix_len)) {
            continue;
        }

        int target_host_id = ntohl(iph->ip_dst.s_addr - subnet_addr);
#endif

        if (used_ips[target_host_id] == 0) {
            continue;
        }

        if (pthread_kill(threads[target_host_id], 0) != 0) {
            pthread_cancel(confuse_threads[target_host_id]);
            pthread_join(threads[target_host_id], NULL);
            pthread_join(confuse_threads[target_host_id], NULL);
            reset_conn(target_host_id);
            free(buf);
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &last_active[target_host_id]);

        struct vpn_hdr *vhdr = (struct vpn_hdr *)buf;
        SSL_send_packet(ssl_ctxs[target_host_id], buf, sizeof(struct vpn_hdr) + vhdr->data_length + vhdr->padding_length, 0, 0);
    }
    free(buf);
}

void *clean_timeout_conns() {
    struct timespec now;
    while (1) {
        sleep(CHECK_CLIENT_ALIVE_INTERVAL);
        clock_gettime(CLOCK_MONOTONIC, &now);
        for (int i = 1; i < (1 << (32 - prefix_len)); ++ i) {
            if (i == EXPECTED_HOST_ID) {
                continue;
            }

            if (used_ips[i] && now.tv_sec - last_active[i].tv_sec >= CLIENT_TIMEOUT) {
                pthread_cancel(threads[i]);
                pthread_cancel(confuse_threads[i]);
                pthread_join(threads[i], NULL);
                pthread_join(confuse_threads[i], NULL);
                reset_conn(i);
            }
        }
    }
}

void *tun_to_ssl(void) {
    char *buf = (char *)malloc(MAX_PKT_SIZE + 10);
    while (1) {
        int bytes = read_tun(tun_fd, buf, sizeof(buf));

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

        if (iph->saddr != ip_addr) {
            continue;
        }

        int target_host_id = ntohl(iph->daddr - subnet_addr);
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

        if (iph->ip_src.s_addr != ip_addr) {
            continue;
        }

        int target_host_id = ntohl(iph->ip_dst.s_addr - subnet_addr);
#endif

        if (used_ips[target_host_id] == 0) {
            continue;
        }

        if (pthread_kill(threads[target_host_id], 0) != 0) {
            pthread_cancel(confuse_threads[target_host_id]);
            pthread_join(threads[target_host_id], NULL);
            pthread_join(confuse_threads[target_host_id], NULL);
            reset_conn(target_host_id);
            free(buf);
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &last_active[target_host_id]);

        int len = SSL_send_packet(ssl_ctxs[target_host_id], buf, bytes, 1, TRAFFIC_CONFUSE ? random() % (bytes / 2 + 1) : 0);
        pkt_mean[target_host_id] = 0.3 * len + 0.7 * pkt_mean[target_host_id];
        clock_gettime(CLOCK_MONOTONIC, &last_send[target_host_id]);
    }
    free(buf);
}

void *confuse(int *hostid) {
    struct timespec now;
    while (1) {
        double interval = (CONFUSE_MAX_INTERVAL - CONFUSE_MIN_INTERVAL) * (random() / (double)RAND_MAX) + CONFUSE_MIN_INTERVAL;
        sleep(interval);
        clock_gettime(CLOCK_MONOTONIC, &now);
        if (!TRAFFIC_CONFUSE) {
            continue;
        }
        if (now.tv_sec - last_send[*hostid].tv_sec <= ACTIVE_INTERVAL && pkt_mean[*hostid] > 0) {
            SSL_send_packet(ssl_ctxs[*hostid], "confuse", strlen("confuse"), 1, pkt_mean[*hostid] + random() % (pkt_mean[*hostid] / 10 + 1) - pkt_mean[*hostid] / 20);
        }
    }
}

int main(int argc, char **argv) {
    host_type = SERVER;

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
                printf("Usage: %s [-c <config_file>] <vpn_subnet_address/prefix_len>\n", argv[0]);
                exit(EXIT_SUCCESS);
            default:
                fprintf(stderr, "Usage: %s [-c <config_file>] <vpn_subnet_address/prefix_len>\n", argv[0]);
                exit(EXIT_FAILURE);
        }
    }

    char *config_subnet_addr = NULL;

    if (optind >= argc) {
        config_subnet_addr = "192.168.20.0/24";
        application_log(stdout, "Using default subnet address: %s\n", config_subnet_addr);
    }
    else if (optind == argc - 1) {
        config_subnet_addr = argv[optind];
    }
    else {
        fprintf(stderr, "Invalid argument. Use option -h to get help.\n");
        exit(EXIT_FAILURE);
    }

    get_subnet(config_subnet_addr, &subnet_addr, &prefix_len);

    if (subnet_addr == INADDR_NONE) {
        application_log(stderr, "Invalid subnet address.\n");
        exit(EXIT_FAILURE);
    }

    if (!config_file) {
        config_file = CONFIG_PATH "/config";
        application_log(stdout, "Using default config file: %s\n", config_file);
    }
    
    for (int i=0; i<3; i++) {
        in_addr_t subnet_addr_tmp;
        int prefix_len_tmp;
        char cur_valid_prefix[100];
        strcpy(cur_valid_prefix, valid_prefixes[i]);
        char *slash = strchr(cur_valid_prefix, '/');
        assert(slash && "Valid prefix is broken.");
        *slash = '\0';
        subnet_addr_tmp = inet_addr(cur_valid_prefix);
        prefix_len_tmp = atoi(slash + 1);
        if (check_in_subnet(subnet_addr, subnet_addr_tmp, prefix_len_tmp) && prefix_len >= prefix_len_tmp) {
            break;
        }
        if (i == 2) {
            application_log(stderr, "Not a local subnet.\n");
            exit(EXIT_FAILURE);
        }
    }

    parse_config_file(config_file, 1 << (32 - prefix_len));

    // Server ip
    used_ips[EXPECTED_HOST_ID] = 1;
    real_iptable[EXPECTED_HOST_ID] = inet_addr("127.0.0.1");
    real_ports[EXPECTED_HOST_ID] = PORT;
    ip_addr = subnet_addr + htonl(EXPECTED_HOST_ID);

    application_log(stdout, "Server's IPv4 address in VPN: %s/%d\n", inet_ntoa(*(struct in_addr *)&ip_addr), prefix_len);

    setup_tun(&vpn_tun_name, ip_addr, prefix_len, &tun_fd, &sk_fd);
    sprintf(subnet_str, "%s/%d", inet_ntoa(*(struct in_addr *)&subnet_addr), prefix_len);
    add_route(subnet_str, inet_ntoa(*(struct in_addr *)&ip_addr), vpn_tun_name);
    route_added = 1;

    // Now we can start the server
    int sock;
    struct sockaddr_in addr;
    SSL_CTX *ctx;

    init_openssl();
    ctx = create_context();
    configure_context(ctx);

    sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        application_log(stderr, "Unable to create socket.\n");
        exit(EXIT_FAILURE);
    }

    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)) < 0) {
        application_log(stderr, "Unable to set socket option.\n");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        application_log(stderr, "Unable to bind socket.\n");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0) {
        application_log(stderr, "Unable to listen on port.\n");
        exit(EXIT_FAILURE);
    }

    application_log(stdout, "Listening on port %d...\n", PORT);

    pthread_t timeout_thread, tun_to_ssl_thread;
    pthread_create(&timeout_thread, NULL, (void*)clean_timeout_conns, NULL);
    pthread_create(&tun_to_ssl_thread, NULL, (void*)tun_to_ssl, NULL);

    while (1) {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            application_log(stderr, "Unable to accept connection from client.\n");
            exit(EXIT_FAILURE);
        }
        
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0 || SSL_get_verify_result(ssl) != X509_V_OK) {
            application_log(stderr, "Invalid connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(client);
            continue;
        }
        else {
            application_log(stdout, "Received connection from %s:%d\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
            char traffic_confuse_str[100];
            sprintf(traffic_confuse_str, TRAFFIC_CONFUSE_HEADER "%d", TRAFFIC_CONFUSE);
            SSL_send_packet(ssl, traffic_confuse_str, strlen(traffic_confuse_str), 1, 0);
            // Assign IP for client
            char buf[1000];
            int bytes = SSL_receive_packet(ssl, buf, sizeof(buf) - 10, 1);
            if (bytes <= 0) {
                application_log(stderr, "Connection with client crashed.\n");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client);
                continue;
            }
            if (bytes <= strlen(REQUEST_ADDR_HEADER) || strncmp(buf, REQUEST_ADDR_HEADER, strlen(REQUEST_ADDR_HEADER)) != 0) {
                application_log(stderr, "Invalid request message from client, close connection.\n");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client);
                continue;
            }
            buf[bytes] = 0;
            long tmp = parse_value(buf + strlen(REQUEST_ADDR_HEADER));
            if (tmp < 0) {
                application_log(stderr, "Invalid request message from client, close connection.\n");
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client);
                continue;
            }

            int host_id = get_ip(tmp);
            if (host_id > 0) {
                struct in_addr host_ip_addr;
                host_ip_addr.s_addr = subnet_addr + htonl(host_id);
                char ip_str[1000];
                sprintf(ip_str, "%s/%d", inet_ntoa(host_ip_addr), prefix_len);
                char actual_msg[2000];
                sprintf(actual_msg, RESPONSE_ADDR_HEADER "%s", ip_str);
                clock_gettime(CLOCK_MONOTONIC, &last_active[host_id]);
                clock_gettime(CLOCK_MONOTONIC, &last_send[host_id]);
                used_ips[host_id] = 1;
                real_iptable[host_id] = addr.sin_addr.s_addr;
                real_ports[host_id] = ntohs(addr.sin_port);
                ssl_ctxs[host_id] = ssl;
                clients[host_id] = client;
                pkt_mean[host_id] = 10;

                SSL_send_packet(ssl, actual_msg, strlen(actual_msg), 1, 0);

                application_log(stdout, "Assigned %s:%d as %s\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), ip_str);

                pthread_create(&threads[host_id], NULL, (void*)listen_and_deliver_packets, &host_id);
                pthread_create(&confuse_threads[host_id], NULL, (void*)confuse, &host_id);
            }
            else {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client);
                continue;
            }
        }
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}