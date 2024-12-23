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

int SSL_send_packet(SSL *ssl, char *buf, int bytes, unsigned char encode, int confuse_len) {
    if (!encode) {
        return SSL_write(ssl, buf, bytes);
    }
    if (bytes == strlen("hello")) {
        if (strncmp(buf, "hello", strlen("hello")) == 0) {
            int nlen = sizeof(struct vpn_hdr) + bytes;
            char *nbuf = (char*)malloc(nlen + 10);
            struct vpn_hdr *vhdr = (struct vpn_hdr*)nbuf;
            vhdr->type = 0;
            vhdr->padding_length = 0;
            vhdr->data_length = bytes;
            memcpy(nbuf + sizeof(struct vpn_hdr), buf, bytes);
            nlen = SSL_write(ssl, nbuf, nlen);
            free(nbuf);
            return nlen;
        }
    }
    else if (bytes == strlen("confuse")) {
        if (strncmp(buf, "confuse", strlen("confuse")) == 0) {
            int padding_size = confuse_len;
            int nlen = sizeof(struct vpn_hdr) + padding_size;
            char *nbuf = (char*)malloc(nlen + 10);
            struct vpn_hdr *vhdr = (struct vpn_hdr*)nbuf;
            vhdr->type = 1;
            vhdr->padding_length = padding_size;
            vhdr->data_length = 0;
            for (int i = 0; i < padding_size; i++) {
                nbuf[sizeof(struct vpn_hdr) + i] = random() % 256;
            }
            nlen = SSL_write(ssl, nbuf, nlen);
            return nlen;
        }
    } else {
        int padding_size = confuse_len;
        int nlen = sizeof(struct vpn_hdr) + padding_size + bytes;
        char *nbuf = (char*)malloc(nlen + 10);
        struct vpn_hdr *vhdr = (struct vpn_hdr*)nbuf;
        vhdr->type = 1;
        vhdr->padding_length = padding_size;
        vhdr->data_length = bytes;
        memcpy(nbuf + sizeof(struct vpn_hdr), buf, bytes);
        for (int i = 0; i < padding_size; i++) {
            nbuf[sizeof(struct vpn_hdr) + bytes + i] = random() % 256;
        }
        nlen = SSL_write(ssl, nbuf, nlen);
        return nlen;
    }
}

int SSL_receive_packet(SSL *ssl, char *buf, int buf_len, unsigned char decode) {
    // read the vpn_hdr first
    char *hdr_buf = (char*)malloc(sizeof(struct vpn_hdr) + 10);
    int tot = 0;
    do {
        int x = SSL_read(ssl, hdr_buf + tot, sizeof(struct vpn_hdr) - tot);
        if (x < 0) {
            return x;
        }
        tot += x;
    }
    while(tot < sizeof(struct vpn_hdr));
    struct vpn_hdr *vhdr = (struct vpn_hdr*)hdr_buf;
    int len = vhdr->padding_length + vhdr->data_length;
    //read the data
    char *data_buf = (char*)malloc(len + 10);
    tot = 0;
    do {
        int x = SSL_read(ssl, data_buf + tot, len - tot);
        if (x < 0) {
            return x;
        }
        tot += x;
    }
    while(tot < len);
    if (!decode) {
        assert(sizeof(struct vpn_hdr) + len <= buf_len && "Buffer is too small.");
        memcpy(buf, vhdr, sizeof(struct vpn_hdr));
        memcpy(buf + sizeof(struct vpn_hdr), data_buf, len);
    }
    int ret = 0;
    switch(vhdr->type) {
    case 0:
        if (vhdr->padding_length == 0 && vhdr->data_length == strlen("hello") && strncmp(data_buf, "hello", strlen("hello")) == 0) {
            ret = KEEP_ALIVE_CODE;
        } else {
            ret = 0;
        }
        break;
    case 1:
        if (decode) {
            assert(vhdr->data_length <= buf_len && "Buffer is too small.");
            memcpy(buf, data_buf, vhdr->data_length);
        }
        ret = vhdr->data_length;
        break;
    default:
        ret = 0;
    }

    free(hdr_buf);
    free(data_buf);
    return ret;
}