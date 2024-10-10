#ifndef VPN_COMMON_H
#define VPN_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <time.h>
#include <sys/socket.h>

#ifdef __linux__
#include <linux/if_tun.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#elif __APPLE__
#include <sys/kern_control.h>
#include <sys/kern_event.h>
#include <sys/kern_control.h>
#include <net/if_utun.h>
#include <net/if_dl.h>
#include <net/route.h>
#endif

#define PORT 54433
#define CA_CERT_FILE CERT_PATH "/../ca_file/ca.crt"
#define CERT_FILE CERT_PATH "/host.crt"
#define KEY_FILE CERT_PATH "/host.key"

int tun_fd = -1, sk_fd = -1;
char *vpn_tun_name;
int route_added = 0;
in_addr_t ip_addr;
char subnet_str[100];

void init_openssl(void);

SSL_CTX *create_server_context(void);

SSL_CTX *create_client_context(void);

void configure_context(SSL_CTX *ctx);

void cleanup_openssl(void);

void get_subnet(char* net_addr, in_addr_t *subnet, int *prefix_len);

in_addr_t get_netmask(int prefix_len);

void setup_tun(char **tun_name, in_addr_t subnet_addr, int prefix_len, int *tun_fd, int *sk_fd);

void clean_up_all(void);

void handle_signal(int signal);

void setup_signal_handler(void);

void add_route(const char *dest, const char *gateway, const char *interface);

void del_route(const char *dest, const char *gateway, const char *interface);

#ifdef __APPLE__
int mac_read_tun(int tun_fd, char *buf, int len);

int mac_write_tun(int tun_fd, char *buf, int len);
#endif

#endif
/* VPN_COMMON_H */