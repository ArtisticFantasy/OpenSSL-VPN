#ifndef VPN_SSL_H
#define VPN_SSL_H

#include <openssl/ssl.h>
#include <openssl/err.h>

void init_openssl(void);

SSL_CTX *create_context(void);

void configure_context(SSL_CTX *ctx);

void cleanup_openssl(void);

int SSL_send_packet(SSL *ssl, char *buf, int bytes, unsigned char encode, int confuse_len);

int SSL_receive_packet(SSL *ssl, char *buf, int buf_len, unsigned char decode);

struct vpn_hdr {
    unsigned char type:1;
    unsigned int padding_length:15;
    unsigned int data_length:16;
};

#endif
/* VPN_SSL_H */