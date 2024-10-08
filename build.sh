#!/bin/bash
PROJ_DIR=$(realpath $(dirname $0))

# Build openssl
cd $PROJ_DIR
if [ ! -d $PROJ_DIR/openssl ]; then
    wget https://github.com/openssl/openssl/releases/download/openssl-3.3.2/openssl-3.3.2.tar.gz
    tar -zxvf openssl-3.3.2.tar.gz
    mv openssl-3.3.2 openssl
fi

if [ ! -d $PROJ_DIR/tools/openssl ]; then
    cd $PROJ_DIR/openssl
    rm -rf build
    mkdir build
    cd build
    ../Configure --prefix=$PROJ_DIR/tools/openssl --openssldir=$PROJ_DIR/tools/openssl || exit 1
    make -j`nproc` || exit 1
    make install || exit 1
fi

OPENSSL=$PROJ_DIR/tools/openssl/bin/openssl
OPENSSL_LIB=$PROJ_DIR/tools/openssl/lib64:$PROJ_DIR/tools/openssl/lib

# Generate certificate files
rm -rf $PROJ_DIR/certs
mkdir $PROJ_DIR/certs
cd $PROJ_DIR/certs

yes "" | LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL genpkey -algorithm RSA -out host.key -pkeyopt rsa_keygen_bits:2048
yes "" | LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL req -new -key host.key -out host.csr
yes "" | LD_LIBRARY_PATH=$OPENSSL_LIB $OPENSSL x509 -req -in host.csr -CA $PROJ_DIR/ca_file/ca.crt -CAkey $PROJ_DIR/ca_file/ca.key -CAcreateserial -out host.crt -days 365 -sha256

# Build sources
cd $PROJ_DIR
rm -rf build
mkdir build
cd build
cmake .. || exit 1
make -j`nproc` || exit 1