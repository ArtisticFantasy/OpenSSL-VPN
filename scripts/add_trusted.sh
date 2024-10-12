#!/bin/bash
source $(dirname $0)/env_check.sh || exit 1

if [ ! -d $PROJ_DIR/build ]; then
    echo "Please run build.sh first."
    exit 1
fi

if [ $# -ne 1 ]; then
    echo "Usage: $0 <certificate>"
    exit 1
fi

mkdir -p $PROJ_DIR/trusted
cp -f $1 $PROJ_DIR/trusted/

cd $PROJ_DIR/trusted/ && LD_LIBRARY_PATH=$OPENSSL_LIB $(command -v c_rehash) .