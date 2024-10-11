#!/bin/bash
PROJ_DIR=$(realpath $(dirname $0))
OPENSSL=$PROJ_DIR/tools/openssl/bin/openssl
OPENSSL_LIB=$PROJ_DIR/tools/openssl/lib64:$PROJ_DIR/tools/openssl/lib

RANDOM_STR1=$(LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL rand -hex 1)
RANDOM_STR2=$(LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL rand -hex 4)
RANDOM_STR3=$(LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL rand -hex 4)
RANDOM_STR4=$(LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL rand -hex 4)
RANDOM_STR5=$(LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL rand -hex 4)
RANDOM_STR6=$(LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL rand -hex 4)

rm -rf $PROJ_DIR/certs
mkdir -p $PROJ_DIR/certs

LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL genpkey -algorithm RSA -out $PROJ_DIR/certs/host.key -pkeyopt rsa_keygen_bits:2048
LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL req -new -key $PROJ_DIR/certs/host.key -out $PROJ_DIR/certs/host.csr -subj "/C=$RANDOM_STR1/ST=$RANDOM_STR2/L=$RANDOM_STR3/O=$RANDOM_STR4/OU=$RANDOM_STR5/CN=$RANDOM_STR6"
LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL x509 -req -days 365 -in $PROJ_DIR/certs/host.csr -signkey $PROJ_DIR/certs/host.key -out $PROJ_DIR/certs/host.crt