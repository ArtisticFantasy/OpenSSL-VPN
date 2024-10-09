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
#include <linux/if_tun.h>
#include <signal.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <pthread.h>
#include <time.h>

#define PORT 4433
#define CA_CERT_FILE CERT_PATH "/../ca_file/ca.crt"
#define CERT_FILE CERT_PATH "/host.crt"
#define KEY_FILE CERT_PATH "/host.key"

int tun_fd, sk_fd;

void init_openssl(void);

SSL_CTX *create_server_context(void);

SSL_CTX *create_client_context(void);

void configure_context(SSL_CTX *ctx);

void cleanup_openssl(void);

void get_subnet(char* net_addr, in_addr_t *subnet, int *prefix_len);

in_addr_t get_netmask(int prefix_len);

void setup_tun(char *tun_name, in_addr_t subnet_addr, int prefix_len, int *tun_fd, int *sk_fd);

void clean_up_all(void);

void handle_signal(int signal);

void setup_signal_handler(void);

#endif
/* VPN_COMMON_H */