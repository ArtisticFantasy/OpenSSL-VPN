#ifndef VPN_NET_SUBNET_H
#define VPN_NET_SUBNET_H

#include "network/common.h"

void get_subnet(char* net_addr, in_addr_t *subnet, int *prefix_len);

in_addr_t get_netmask(int prefix_len);

int check_in_subnet(in_addr_t addr, in_addr_t subnet_addr, int prefix_len);

#endif
/* VPN_NET_SUBNET_H */