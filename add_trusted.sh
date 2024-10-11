#!/bin/bash
PROJ_DIR=$(realpath $(dirname $0))
C_REHASH=$PROJ_DIR/tools/openssl/bin/c_rehash
OPENSSL_LIB=$PROJ_DIR/tools/openssl/lib64:$PROJ_DIR/tools/openssl/lib

if [ $# -ne 1 ]; then
    echo "Usage: $0 <certificate>"
    exit 1
fi

mkdir -p $PROJ_DIR/trusted
cp -f $1 $PROJ_DIR/trusted/

cd $PROJ_DIR/trusted/ && LD_LIBRARY_PATH=$OPENSSL_LIB $C_REHASH .