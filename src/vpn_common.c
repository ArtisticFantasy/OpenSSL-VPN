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
    if (*prefix_len < 16 || *prefix_len >= 32) {
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


void setup_tun(char **tun_name, in_addr_t ip_addr, int prefix_len, int *tun_fd, int *sk_fd) {

#ifdef __linux__

    struct ifreq ifr;
    *tun_fd = open("/dev/net/tun", O_RDWR);
    if (*tun_fd < 0) {
        perror("Opening /dev/net/tun");
        exit(EXIT_FAILURE);
    }

    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    ifr.ifr_name[0] = '\0';

    if (ioctl(*tun_fd, TUNSETIFF, (void *)&ifr) < 0) {
        perror("ioctl(TUNSETIFF)");
        close(*tun_fd);
        exit(EXIT_FAILURE);
    }

    *tun_name = (char*)malloc(IFNAMSIZ + 10);
    strncpy(*tun_name, ifr.ifr_name, IFNAMSIZ);
    (*tun_name)[IFNAMSIZ] = '\0';

    *sk_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

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

#endif
}

void clean_up_all(void) {
    if (route_added && vpn_tun_name) {
        del_route(subnet_str, inet_ntoa(*(struct in_addr *)&ip_addr), vpn_tun_name);
        route_added = 0;
    }
    if (tun_fd != -1) {
        close(tun_fd);
        tun_fd = -1;
        if (vpn_tun_name) {
            free(vpn_tun_name);
            vpn_tun_name = NULL;
        }
    }

    if (sk_fd != -1) {
        close(sk_fd);
        sk_fd = -1;
    }
    cleanup_openssl();
}
void handle_signal(int signal) {
    if (signal == SIGINT) {
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

void modify_route(const char *dest, const char *gateway, const char *interface, int flags, int type) {
    struct {
        struct nlmsghdr nlh;
        struct rtmsg rt;
        char buf[8192];
    } req;

    memset(&req, 0, sizeof(req));

    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlh.nlmsg_flags = flags;
    req.nlh.nlmsg_type = type;
    req.rt.rtm_family = AF_INET;
    req.rt.rtm_table = RT_TABLE_MAIN;
    req.rt.rtm_protocol = RTPROT_BOOT;
    req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
    req.rt.rtm_type = RTN_UNICAST;

    char dest_copy[100];
    strncpy(dest_copy, dest, sizeof(dest_copy));
    char *slash = strchr(dest_copy, '/');
    if (slash) {
        *slash = '\0';
        req.rt.rtm_dst_len = atoi(slash + 1);
    } else {
        req.rt.rtm_dst_len = 32;
    }

    struct rtattr *rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    int rta_len = RTA_LENGTH(4);
    rta->rta_type = RTA_DST;
    rta->rta_len = rta_len;
    inet_pton(AF_INET, dest_copy, RTA_DATA(rta));
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + rta_len;

    rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta_len = RTA_LENGTH(4);
    rta->rta_type = RTA_GATEWAY;
    rta->rta_len = rta_len;
    inet_pton(AF_INET, gateway, RTA_DATA(rta));
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + rta_len;

    rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta_len = RTA_LENGTH(strlen(interface) + 1);
    rta->rta_type = RTA_OIF;
    rta->rta_len = rta_len;
    memcpy(RTA_DATA(rta), interface, strlen(interface) + 1);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + rta_len;

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("socket");
        exit(EXIT_FAILURE);
    }

    struct sockaddr_nl sa;
    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (sendto(sock, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("sendto");
        close(sock);
        exit(EXIT_FAILURE);
    }

    close(sock);
}

void add_route(const char *dest, const char *gateway, const char *interface) {
    modify_route(dest, gateway, interface, NLM_F_REQUEST | NLM_F_CREATE, RTM_NEWROUTE);
}

void del_route(const char *dest, const char *gateway, const char *interface) {
    modify_route(dest, gateway, interface, NLM_F_REQUEST, RTM_DELROUTE);
}