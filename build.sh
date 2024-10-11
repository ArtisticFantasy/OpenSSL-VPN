#!/bin/bash
PROJ_DIR=$(realpath $(dirname $0))
OS_TYPE=$(uname)

# Build openssl
if [ ! -d $PROJ_DIR/tools/openssl ]; then
    if [ ! -d $PROJ_DIR/openssl ]; then
        cd $PROJ_DIR
        wget https://github.com/openssl/openssl/releases/download/openssl-3.3.2/openssl-3.3.2.tar.gz || exit 1
        tar -zxvf openssl-3.3.2.tar.gz || exit 1
        mv openssl-3.3.2 openssl || exit 1
        rm -rf openssl-3.3.2.tar.gz
    fi
    cd $PROJ_DIR/openssl
    rm -rf build
    mkdir build
    cd build
    ../Configure --prefix=$PROJ_DIR/tools/openssl --openssldir=$PROJ_DIR/tools/openssl || exit 1
    if [ "$OS_TYPE" == "Linux" ]; then
        make -j`nproc` || exit 1
    elif [ "$OS_TYPE" == "Darwin" ]; then
        make -j`sysctl -n hw.ncpu` || exit 1
    fi
    make install || exit 1
    rm -rf $PROJ_DIR/openssl
fi

OPENSSL=$PROJ_DIR/tools/openssl/bin/openssl
OPENSSL_LIB=$PROJ_DIR/tools/openssl/lib64:$PROJ_DIR/tools/openssl/lib

# Make trusted directory
if [ ! -d $PROJ_DIR/trusted ]; then
    mkdir $PROJ_DIR/trusted
fi

# Generate certificate files
if [ ! -d $PROJ_DIR/certs ]; then
    $PROJ_DIR/gen_certs.sh
fi

# Build sources
cd $PROJ_DIR
rm -rf build
mkdir build
cd build
cmake .. || exit 1

if [ "$OS_TYPE" == "Linux" ]; then
    make -j`nproc` || exit 1
elif [ "$OS_TYPE" == "Darwin" ]; then
    make -j`sysctl -n hw.ncpu` || exit 1
fi
