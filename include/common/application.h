#ifndef VPN_APPLICATION_H
#define VPN_APPLICATION_H

#include <stdint.h>
#include <errno.h>
#include <ctype.h>
#include <arpa/inet.h>

#define MAX_HOSTS 1 << 16

#define REQUEST_ADDR_HEADER "Expected host id: "
#define RESPONSE_ADDR_HEADER "Your ip address is: "

#define REGISTER_CLEAN_UP \
void clean_up_all(void) { \
    if (route_added && vpn_tun_name) { \
        del_route(subnet_str, inet_ntoa(*(struct in_addr *)&ip_addr), vpn_tun_name); \
        route_added = 0; \
    } \
    if (tun_fd != -1) { \
        close(tun_fd); \
        tun_fd = -1; \
        if (vpn_tun_name) { \
            free(vpn_tun_name); \
            vpn_tun_name = NULL; \
        } \
    } \
\
    if (sk_fd != -1) { \
        close(sk_fd); \
        sk_fd = -1; \
    } \
    cleanup_openssl(); \
}

long parse_value(char *value);

void parse_config_file(const char *file_path, int max_hosts);

#endif
/* VPN_APPLICATION_H */