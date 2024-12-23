#ifndef VPN_NET_SETUP_H
#define VPN_NET_SETUP_H

#include "network/common.h"

void setup_tun(char **tun_name, in_addr_t subnet_addr, int prefix_len, int *tun_fd, int *sk_fd);

void add_route(const char *dest, const char *gateway, const char *interface);

void del_route(const char *dest, const char *gateway, const char *interface);

#ifdef __APPLE__
int mac_read_tun(int tun_fd, char *buf, int len);

int mac_write_tun(int tun_fd, char *buf, int len);
#endif

int read_tun(int tun_fd, char *buf, int len);

int write_tun(int tun_fd, char *buf, int len);

#endif
/* VPN_NET_SETUP_H */