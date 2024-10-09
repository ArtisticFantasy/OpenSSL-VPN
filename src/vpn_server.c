#include "vpn_common.h"

in_addr_t subnet_addr;
int prefix_len;
int tun_fd = -1, sk_fd = -1;

char *valid_prefixes[3] = {"192.168.0.0/16", "172.16.0.0/12", "10.0.0.0/8"};

int used_ips[1<<16] = {0};
in_addr_t real_iptable[1<<16] = {0};
SSL *ssl_ctxs[1<<16] = {0};

int check_in_subnet(in_addr_t addr) {
    return (addr & htonl(((0xffffffff) << (32 - prefix_len)))) == subnet_addr;
}

int get_ip() {
    for (int i = 1; i < (1 << 32 - prefix_len); i++) {
        if (!used_ips[i]) {
            used_ips[i] = 1;
            return i;
        }
    }
    return -1;
}

int main(int argc, char **argv) {

    setup_signal_handler();

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
        if ((subnet_addr & subnet_addr_tmp) == subnet_addr_tmp && prefix_len >= prefix_len_tmp) {
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

    setup_tun("vpn-srv-tun", subnet_addr + htonl(1), prefix_len, &tun_fd, &sk_fd);
    atexit(clean_up_all);

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
                struct in_addr ip_addr;
                ip_addr.s_addr = subnet_addr + htonl(host_id);
                char ip_str[1000];
                sprintf(ip_str, "%s/%d", inet_ntoa(ip_addr), prefix_len);
                real_iptable[host_id] = addr.sin_addr.s_addr;
                ssl_ctxs[host_id] = ssl;
                
                SSL_write(ssl, ip_str, strlen(ip_str));
            }
            else {
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(client);
                continue;
            }
        }
        char buffer[1024] = {0};
        int bytes = SSL_read(ssl, buffer, sizeof(buffer));
        if (bytes > 0) {
            buffer[bytes] = '\0';
            printf("Received message from client: %s\n", buffer);
        } else {
            ERR_print_errors_fp(stderr);
        }
    }

    close(sock);
    SSL_CTX_free(ctx);
    cleanup_openssl();

    return 0;
}