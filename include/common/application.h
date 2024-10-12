#ifndef VPN_APPLICATION_H
#define VPN_APPLICATION_H

#include <stdarg.h>

#define PORT 54433

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

void application_log(FILE *restrict stream, const char *restrict format, ...);

#endif
/* VPN_APPLICATION_H */