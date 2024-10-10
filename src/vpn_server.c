#include "vpn_common.h"

#define MAX_HOSTS 1<<16

in_addr_t subnet_addr;
int prefix_len;

char *valid_prefixes[3] = {"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"};

int used_ips[MAX_HOSTS] = {0};
in_addr_t real_iptable[MAX_HOSTS] = {0};
int clients[MAX_HOSTS] = {0};
SSL *ssl_ctxs[MAX_HOSTS] = {0};
pthread_t threads[MAX_HOSTS] = {0};
struct timespec last_active[MAX_HOSTS] = {0};

int check_in_subnet(in_addr_t addr) {
    return (addr & htonl(((0xffffffff) << (32 - prefix_len)))) == subnet_addr;
}

void reset_conn(int host_id) {
    if (used_ips[host_id] == 0) {
        return;
    }
    used_ips[host_id] = 0;
    real_iptable[host_id] = 0;
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

    for (int i = 2; i < (1 << 32 - prefix_len); i++) {
        if (!used_ips[i]) {
            return i;
        }
        else if (now.tv_sec - last_active[i].tv_sec >= 2000) {
            pthread_cancel(threads[i]);
            pthread_join(threads[i], NULL);
            reset_conn(i);
            return i;
        }
        else {
            if (pthread_tryjoin_np(threads[i], NULL) == 0) {
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
    in_addr_t subnet_addr = ip_addr & get_netmask(prefix_len);
    while (1) {
        int bytes = SSL_read(ssl_ctxs[host_id], buf, sizeof(buf));

        if (bytes <= 0) {
            reset_conn(host_id);
            return NULL;
        }

        //keep alive
        if (bytes == strlen("hello")) {
            if (strncmp(buf, "hello", strlen("hello")) == 0) {
                clock_gettime(CLOCK_MONOTONIC, &last_active[host_id]);
            }
            continue;
        }

        if (bytes < sizeof(struct iphdr)) {
            continue;
        }

        struct iphdr *iph = (struct iphdr *)buf;
        if ((iph->saddr != subnet_addr + htonl(host_id)) || (iph->daddr & get_netmask(prefix_len)) != subnet_addr) {
            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &last_active[host_id]);

        if (iph->daddr == ip_addr) {
            write(tun_fd, buf, bytes);
            continue;
        }
        
        int target_host_id = ntohl(iph->daddr - subnet_addr);

        if (used_ips[target_host_id] == 0) {
            continue;
        }

        if (pthread_tryjoin_np(threads[target_host_id], NULL) == 0) {
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
        sleep(500);
        clock_gettime(CLOCK_MONOTONIC, &now);
        for (int i = 2; i < (1 << 32 - prefix_len); i++) {
            if (used_ips[i] && now.tv_sec - last_active[i].tv_sec >= 2000) {
                pthread_cancel(threads[i]);
                pthread_join(threads[i], NULL);
                reset_conn(i);
            }
        }
    }
}

void *tun_to_ssl(void) {
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

        if (iph->saddr != ip_addr) {
            continue;
        }

        int target_host_id = ntohl(iph->daddr - subnet_addr);

        if (used_ips[target_host_id] == 0) {
            continue;
        }

        if (pthread_tryjoin_np(threads[target_host_id], NULL) == 0) {
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
        fprintf(stderr, "Invalid subnet address\n");
        exit(EXIT_FAILURE);
    }
    
    for (int i=0; i<3; i++) {
        in_addr_t subnet_addr_tmp;
        int prefix_len_tmp;
        get_subnet(valid_prefixes[i], &subnet_addr_tmp, &prefix_len_tmp);
        if ((subnet_addr & get_netmask(prefix_len_tmp)) == subnet_addr_tmp && prefix_len >= prefix_len_tmp) {
            break;
        }
        if (i == 2) {
            fprintf(stderr, "Not a local subnet\n");
            exit(EXIT_FAILURE);
        }
    }

    // Server ip
    used_ips[1] = 1;
    real_iptable[1] = inet_addr("127.0.0.1");
    ip_addr = subnet_addr + htonl(1);

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
        perror("Unable to create socket");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_port = htons(PORT);
    addr.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Unable to bind");
        exit(EXIT_FAILURE);
    }

    if (listen(sock, 1) < 0) {
        perror("Unable to listen");
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
            perror("Unable to accept");
            exit(EXIT_FAILURE);
        }
        
        ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client);

        if (SSL_accept(ssl) <= 0) {
            ERR_print_errors_fp(stderr);
        } else {
            //SSL_write(ssl, "Hello, SSL VPN client!", strlen("Hello, SSL VPN client!"));
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
                ssl_ctxs[host_id] = ssl;
                clients[host_id] = client;

                SSL_write(ssl, ip_str, strlen(ip_str));
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