#include "vpn_common.h"

void init_openssl() {
    SSL_load_error_strings();
    OpenSSL_add_ssl_algorithms();
}

SSL_CTX *create_server_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_server_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

SSL_CTX *create_client_context() {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    method = SSLv23_client_method();
    ctx = SSL_CTX_new(method);
    if (!ctx) {
        perror("Unable to create SSL context");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_load_verify_locations(ctx, CA_CERT_FILE, NULL) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
}

void cleanup_openssl() {
    EVP_cleanup();
}

void get_subnet(char *input_addr, in_addr_t *subnet, int *prefix_len) {
    char net_addr[100];
    memcpy(net_addr, input_addr, strlen(input_addr));
    net_addr[strlen(input_addr)] = '\0';
    char *slash = strchr(net_addr, '/');
    if (!slash) {
        fprintf(stderr, "Invalid subnet address\n");
        *subnet = INADDR_NONE;
        return;
    }
    *slash = '\0';
    *prefix_len = atoi(slash + 1);
    if (*prefix_len < 8 || *prefix_len >= 32) {
        fprintf(stderr, "Invalid prefix length\n");
        *subnet = INADDR_NONE;
        return;
    }
    *subnet = inet_addr(net_addr);
    if (*subnet == INADDR_NONE) {
        fprintf(stderr, "Invalid subnet address\n");
        return;
    }
    if (*subnet == INADDR_ANY || *subnet & ~get_netmask(*prefix_len)) {
        fprintf(stderr, "Invalid subnet address\n");
        *subnet = INADDR_NONE;
        return;
    }
}

in_addr_t get_netmask(int prefix_len) {
    return htonl(~((1 << (32 - prefix_len)) - 1));
}


void setup_tun(char *tun_name, in_addr_t ip_addr, int prefix_len, int *tun_fd, int *sk_fd) {
    // Create TUN
    struct ifreq ifr;
    *tun_fd = open("/dev/net/tun", O_RDWR);
    if (*tun_fd < 0) {
        perror("Opening /dev/net/tun");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, tun_name, IFNAMSIZ);

    if (ioctl(*tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(*tun_fd);
        exit(EXIT_FAILURE);
    }

    // Set IP address
    *sk_fd = socket(AF_INET, SOCK_RAW, htons(ETH_P_IP));

    ifr.ifr_flags |= IFF_UP | IFF_RUNNING;

    if (ioctl(*sk_fd, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl(SIOCSIFFLAGS)");
        close(*tun_fd);
        close(*sk_fd);
        exit(EXIT_FAILURE);
    }

    struct sockaddr_in tun_addr;
    memset(&tun_addr, 0, sizeof(struct sockaddr_in));
    tun_addr.sin_family = AF_INET;
    tun_addr.sin_addr.s_addr = ip_addr;
    
    memcpy(&ifr.ifr_addr, &tun_addr, sizeof(struct sockaddr_in));

    if (ioctl(*sk_fd, SIOCSIFADDR, &ifr) < 0) {
        perror("ioctl(SIOCSIFADDR)");
        close(*tun_fd);
        close(*sk_fd);
        exit(EXIT_FAILURE);
    }

    tun_addr.sin_addr.s_addr = get_netmask(prefix_len);
    
    memcpy(&ifr.ifr_addr, &tun_addr, sizeof(struct sockaddr_in));

    if (ioctl(*sk_fd, SIOCSIFNETMASK, &ifr) < 0) {
        perror("ioctl(SIOCSIFNETMASK)");
        close(*tun_fd);
        close(*sk_fd);
        exit(EXIT_FAILURE);
    }

}

void clean_up_all(void) {
    if (tun_fd != -1) {
        close(tun_fd);
    }
    if (sk_fd != -1) {
        close(sk_fd);
    }
    cleanup_openssl();
}
void handle_signal(int signal) {
    if (signal == SIGINT) {
        clean_up_all();
        exit(EXIT_SUCCESS);
    }
}

void setup_signal_handler() {
    struct sigaction sa;
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    if (sigaction(SIGINT, &sa, NULL) == -1) {
        perror("sigaction");
        exit(EXIT_FAILURE);
    }
}