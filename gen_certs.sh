#!/bin/bash
PROJ_DIR=$(realpath $(dirname $0))
OPENSSL=$PROJ_DIR/tools/openssl/bin/openssl
OPENSSL_LIB=$PROJ_DIR/tools/openssl/lib64:$PROJ_DIR/tools/openssl/lib

yes "" | LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL genpkey -algorithm RSA -out $PROJ_DIR/certs/host.key -pkeyopt rsa_keygen_bits:2048
yes "" | LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL req -new -key $PROJ_DIR/certs/host.key -out $PROJ_DIR/certs/host.csr
yes "" | LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL x509 -req -days 365 -in $PROJ_DIR/certs/host.csr -signkey $PROJ_DIR/certs/host.key -out $PROJ_DIR/certs/host.crt