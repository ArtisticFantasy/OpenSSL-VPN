#include "common/common.h"
#include "utils/ssl.h"

#define TRUSTED_DIR CERT_PATH "/../trusted"
#define CERT_FILE CERT_PATH "/host.crt"
#define KEY_FILE CERT_PATH "/host.key"

extern int host_type;

void init_openssl(void) {
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
}

SSL_CTX *create_context(void) {
    const SSL_METHOD *method;
    SSL_CTX *ctx;

    if (host_type == SERVER) {
        method = SSLv23_server_method();
    } 
    else if (host_type == CLIENT) {
        method = SSLv23_client_method();
    }

    ctx = SSL_CTX_new(method);
    if (!ctx) {
        application_log(stderr, "Unable to create SSL context.\n");
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    return ctx;
}

void configure_context(SSL_CTX *ctx) {
    if (SSL_CTX_use_certificate_file(ctx, CERT_FILE, SSL_FILETYPE_PEM) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, KEY_FILE, SSL_FILETYPE_PEM) <= 0 ) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    if (!SSL_CTX_check_private_key(ctx)) {
        application_log(stderr, "Private key does not match the certificate public key.\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_load_verify_locations(ctx, NULL, TRUSTED_DIR) <= 0) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_set_verify_depth(ctx, 1);
}

void cleanup_openssl(void) {
    EVP_cleanup();
}