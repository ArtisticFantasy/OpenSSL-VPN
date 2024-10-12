#!/bin/bash
PROJ_DIR=$(realpath $(dirname $0)/..)
OS_TYPE=$(uname)
OPENSSL_IN_TOOL=0

download_and_install_openssl() {
    INSTALL_OPENSSL_VERSION="3.3.2"
    echo "Installing OpenSSL-$INSTALL_OPENSSL_VERSION ..."
    if [ ! -d $PROJ_DIR/openssl ]; then
        cd $PROJ_DIR
        if [ ! -f openssl-$INSTALL_OPENSSL_VERSION.tar.gz ]; then
            wget https://github.com/openssl/openssl/releases/download/openssl-3.3.2/openssl-3.3.2.tar.gz || exit 1
        fi
        tar -zxvf openssl-$INSTALL_OPENSSL_VERSION.tar.gz || exit 1
        mv openssl-$INSTALL_OPENSSL_VERSION openssl || exit 1
        rm -rf openssl-$INSTALL_OPENSSL_VERSION.tar.gz
    fi
    cd $PROJ_DIR/openssl
    rm -rf build
    mkdir build
    cd build
    read -p "Do you want to install OpenSSL-$INSTALL_OPENSSL_VERSION on your machine environment(superuser needed) or just in the project directory (y/n)? (dafault n)" choice
    if [[ "$choice" == [Yy]* ]]; then
        ../Configure || exit 1
    else
        ../Configure --prefix=$PROJ_DIR/tools/openssl --openssldir=$PROJ_DIR/tools/openssl || exit 1
    fi
    if [ "$OS_TYPE" == "Linux" ]; then
        make -j`nproc` || exit 1
    elif [ "$OS_TYPE" == "Darwin" ]; then
        make -j`sysctl -n hw.ncpu` || exit 1
    fi
    if [[ "$choice" == [Yy]* ]]; then
        sudo make install || exit 1
        OPENSSL=$(command -v openssl)
        OPENSSL_LIB=""
    else
        make install || exit 1
        OPENSSL=$PROJ_DIR/tools/openssl/bin/openssl
        OPENSSL_LIB=$PROJ_DIR/tools/openssl/lib64:$PROJ_DIR/tools/openssl/lib
        OPENSSL_IN_TOOL=1
    fi
    rm -rf $PROJ_DIR/openssl
    echo "Installed OpenSSL-$INSTALL_OPENSSL_VERSION successfully."
}

check_openssl_installed() {
    if [ -d $PROJ_DIR/tools/openssl ]; then
        echo "Found OpenSSL in the project tool directory."
        OPENSSL=$PROJ_DIR/tools/openssl/bin/openssl
        OPENSSL_LIB=$PROJ_DIR/tools/openssl/lib64:$PROJ_DIR/tools/openssl/lib
        OPENSSL_IN_TOOL=1
    else
        OPENSSL=$(command -v openssl)
        NEED_TO_INSTALL_OPENSSL=0
        if [ -z $OPENSSL ]; then
            echo "OpenSSL does not exist on your machine."
            NEED_TO_INSTALL_OPENSSL=0
        else
            OPENSSL_VERSION=$($OPENSSL version | awk '{print $2}')
            REQUIRED_VERSION="3.0.13"
            version_gt() { test "$(printf '%s\n' "$@" | sort -V | head -n 1)" != "$1"; }
            if version_gt $REQUIRED_VERSION $OPENSSL_VERSION; then
                echo "System OpenSSL version: $OPENSSL_VERSION"
                echo "Need OpenSSL version >= $REQUIRED_VERSION"
                NEED_TO_INSTALL_OPENSSL=1
            fi
        fi
        if [ $NEED_TO_INSTALL_OPENSSL -eq 1 ]; then
            download_and_install_openssl || exit 1
        else
            echo "Found OpenSSL-$OPENSSL_VERSION on your machine."
            OPENSSL_LIB=""
        fi
    fi
}

check_openssl_installed