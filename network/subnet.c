#include "common/common.h"
#include "network/subnet.h"

void get_subnet(char *input_addr, in_addr_t *subnet, int *prefix_len) {
    char net_addr[100];
    memcpy(net_addr, input_addr, strlen(input_addr));
    net_addr[strlen(input_addr)] = '\0';
    char *slash = strchr(net_addr, '/');
    if (!slash) {
        *subnet = INADDR_NONE;
        return;
    }
    *slash = '\0';
    *prefix_len = atoi(slash + 1);
    if (*prefix_len < 16 || *prefix_len >= 32) {
        *subnet = INADDR_NONE;
        return;
    }
    *subnet = inet_addr(net_addr);
    if (*subnet == INADDR_NONE) {
        return;
    }
    if (*subnet == INADDR_ANY || *subnet & ~get_netmask(*prefix_len)) {
        *subnet = INADDR_NONE;
        return;
    }
}

in_addr_t get_netmask(int prefix_len) {
    return htonl(~((1 << (32 - prefix_len)) - 1));
}

int check_in_subnet(in_addr_t addr, in_addr_t subnet_addr, int prefix_len) {
    return (addr & get_netmask(prefix_len)) == subnet_addr;
}