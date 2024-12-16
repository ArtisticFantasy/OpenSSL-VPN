#ifndef VPN_SSL_H
#define VPN_SSL_H


#include <openssl/ssl.h>
#include <openssl/err.h>

void init_openssl(void);

SSL_CTX *create_context(void);

void configure_context(SSL_CTX *ctx);

void cleanup_openssl(void);

int SSL_send_packet(SSL *ssl, char *buf, int bytes);

int SSL_receive_packet(SSL *ssl, char *buf, int buf_len);
#endif
/* VPN_SSL_H */