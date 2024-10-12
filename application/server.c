#include "common/common.h"
#include "common/signal.h"
#include "common/application.h"
#include "network/subnet.h"
#include "network/setup.h"
#include "utils/ssl.h"

#define MAX_HOSTS 1<<16
#define CLIENT_TIMEOUT 500
#define CHECK_CLIENT_ALIVE_INTERVAL 200

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
struct timespec last_active[MAX_HOSTS] = {0};

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
}

int get_ip() {

    struct timespec now;
    clock_gettime(CLOCK_MONOTONIC, &now);

    for (int i = 2; i < (1 << (32 - prefix_len)); i++) {
        if (!used_ips[i]) {
            return i;
        }
        else if (now.tv_sec - last_active[i].tv_sec >= CLIENT_TIMEOUT) {
            pthread_cancel(threads[i]);
            pthread_join(threads[i], NULL);
            reset_conn(i);
            return i;
        }
        else {
            if (pthread_kill(threads[i], 0) != 0) {
                pthread_join(threads[i], NULL);
                reset_conn(i);
                return i;
            }
        }
    }
    return -1;
}

void *listen_and_deliver_packets(int *hostid) {
    int host_id = *hostid;
    char buf[70000];
    while (1) {
        int bytes = SSL_read(ssl_ctxs[host_id], buf, sizeof(buf));

        if (bytes <= 0) {
            reset_conn(host_id);
            return NULL;
        }

        //keep alive
        in_addr_t host_addr = subnet_addr + htonl(host_id);
        if (bytes == strlen("hello")) {
            if (strncmp(buf, "hello", strlen("hello")) == 0) {
                clock_gettime(CLOCK_MONOTONIC, &last_active[host_id]);
                application_log(stdout, "Received keep-alive message from %s:%d ", 
                    inet_ntoa(*(struct in_addr *)&real_iptable[host_id]), real_ports[host_id]);
                printf("(%s/%d)\n",
                    inet_ntoa(*(struct in_addr *)&host_addr), prefix_len);
            }
            continue;
        }

#ifdef __linux__
        if (bytes < sizeof(struct iphdr)) {
            continue;
        }
        struct iphdr *iph = (struct iphdr *)buf;
        if ((iph->saddr != host_addr) || (iph->daddr & get_netmask(prefix_len)) != subnet_addr) {
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &last_active[host_id]);

        if (iph->daddr == ip_addr) {
            write(tun_fd, buf, bytes);
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
        struct ip *iph = (struct ip *)buf;
        if ((iph->ip_src.s_addr != host_addr) || (iph->ip_dst.s_addr & get_netmask(prefix_len)) != subnet_addr) {
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &last_active[host_id]);

        if (iph->ip_dst.s_addr == ip_addr) {
            mac_write_tun(tun_fd, buf, bytes);
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
            pthread_join(threads[target_host_id], NULL);
            reset_conn(target_host_id);
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &last_active[target_host_id]);

        SSL_write(ssl_ctxs[target_host_id], buf, bytes);
    }
}

void *clean_timeout_conns() {
    struct timespec now;
    while (1) {
        sleep(CHECK_CLIENT_ALIVE_INTERVAL);
        clock_gettime(CLOCK_MONOTONIC, &now);
        for (int i = 2; i < (1 << (32 - prefix_len)); i++) {
            if (used_ips[i] && now.tv_sec - last_active[i].tv_sec >= CLIENT_TIMEOUT) {
                pthread_cancel(threads[i]);
                pthread_join(threads[i], NULL);
                reset_conn(i);
            }
        }
    }
}

void *tun_to_ssl(void) {
    char buf[70000];
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
            pthread_join(threads[target_host_id], NULL);
            reset_conn(target_host_id);
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &last_active[target_host_id]);

        SSL_write(ssl_ctxs[target_host_id], buf, bytes);
    }
}

int main(int argc, char **argv) {

    setup_signal_handler();
    atexit(clean_up_all);

    if (argc < 2) {
        argv[1] = "192.168.20.0/24";
    }
    
    get_subnet(argv[1], &subnet_addr, &prefix_len);

    if (subnet_addr == INADDR_NONE) {
        application_log(stderr, "Invalid subnet address.\n");
        exit(EXIT_FAILURE);
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

    // Server ip
    used_ips[1] = 1;
    real_iptable[1] = inet_addr("127.0.0.1");
    real_ports[1] = PORT;
    ip_addr = subnet_addr + htonl(1);

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
    ctx = create_server_context();
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

    pthread_t timeout_thread, tun_to_ssl_thread;
    pthread_create(&timeout_thread, NULL, (void*)clean_timeout_conns, NULL);
    pthread_create(&tun_to_ssl_thread, NULL, (void*)tun_to_ssl, NULL);

    while (1) {
        struct sockaddr_in addr;
        uint len = sizeof(addr);
        SSL *ssl;

        int client = accept(sock, (struct sockaddr*)&addr, &len);
        if (client < 0) {
            application_log(stderr, "Unable to accept connection from client.\n");
            exit(EXIT_FAILURE);
        }
        
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0 || SSL_get_verify_result(ssl) != X509_V_OK) {
            application_log(stderr, "Invalid connection from %s:%d.\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        } else {
            // Assign IP for client
            int host_id = get_ip();
            if (host_id > 0) {
                struct in_addr host_ip_addr;
                host_ip_addr.s_addr = subnet_addr + htonl(host_id);
                char ip_str[1000];
                sprintf(ip_str, "%s/%d", inet_ntoa(host_ip_addr), prefix_len);
                clock_gettime(CLOCK_MONOTONIC, &last_active[host_id]);
                used_ips[host_id] = 1;
                real_iptable[host_id] = addr.sin_addr.s_addr;
                real_ports[host_id] = ntohs(addr.sin_port);
                ssl_ctxs[host_id] = ssl;
                clients[host_id] = client;

                application_log(stdout, "Received connection from %s:%d, assigned as %s\n", inet_ntoa(addr.sin_addr), ntohs(addr.sin_port), ip_str);

                if (SSL_write(ssl, ip_str, strlen(ip_str)) <= 0) {
                    application_log(stderr, "Maybe the client cannot verify your identity, connection closed.\n");
                    reset_conn(host_id);
                    continue;
                }
                pthread_create(&threads[host_id], NULL, (void*)listen_and_deliver_packets, &host_id);
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