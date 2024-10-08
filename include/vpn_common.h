#ifndef VPN_COMMON_H
#define VPN_COMMON_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define PORT 4433
#define CA_CERT_FILE CERT_PATH "/../ca_file/ca.crt"
#define CERT_FILE CERT_PATH "/host.crt"
#define KEY_FILE CERT_PATH "/host.key"

void init_openssl(void);

SSL_CTX *create_server_context(void);

SSL_CTX *create_client_context(void);

void configure_context(SSL_CTX *ctx);

void cleanup_openssl(void);

#endif
/* VPN_COMMON_H */