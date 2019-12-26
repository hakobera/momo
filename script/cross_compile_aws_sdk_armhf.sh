#!/bin/bash

AWS_SDK_SOURCE_DIR=$1
OUTPUT_DIR=$2

CROSS_COMPILE_BIN_PREFIX=arm-linux-gnueabihf

export CROSS_COMPILE_HOME=$AWS_SDK_SOURCE_DIR/build
export CC=$CROSS_COMPILE_BIN_PREFIX-gcc
export LD=$CROSS_COMPILE_BIN_PREFIX-ld
export AR=$CROSS_COMPILE_BIN_PREFIX-ar
export AS=$CROSS_COMPILE_BIN_PREFIX-as
export NM=$CROSS_COMPILE_BIN_PREFIX-nm
export RANLIB=$CROSS_COMPILE_BIN_PREFIX-ranlib
export CPPFLAGS="-I$CROSS_COMPILE_HOME/include/"
export CROSS_INSTALL_PREFIX=$OUTPUT_DIR
export LDFLAGS="-L$CROSS_COMPILE_HOME/lib/ -L$CROSS_COMPILE_HOME/lib64/ -L$CROSS_INSTALL_PREFIX/lib/"
export PATH=$CROSS_COMPILE_HOME/bin:$PATH

rm -rf $CROSS_COMPILE_HOME
mkdir -p $CROSS_COMPILE_HOME

rm -rf $CROSS_INSTALL_PREFIX
mkdir -p $CROSS_INSTALL_PREFIX

pushd $AWS_SDK_SOURCE_DIR
  # Cross compile zlib
  ZLIB_VERSION=1.2.11
  curl -LO https://zlib.net/zlib-$ZLIB_VERSION.tar.gz
  tar xvzf zlib-$ZLIB_VERSION.tar.gz
  pushd zlib-$ZLIB_VERSION
    ./configure --prefix=$CROSS_INSTALL_PREFIX
    make && make install
  popd

  # Cross compile openssl
  OPENSSL_VERSION=1.1.1d
  curl -LO https://www.openssl.org/source/openssl-$OPENSSL_VERSION.tar.gz
  tar xvzf openssl-$OPENSSL_VERSION.tar.gz
  pushd openssl-$OPENSSL_VERSION
    ./Configure --prefix=$CROSS_INSTALL_PREFIX linux-armv4
    make -j && make install
  popd

  # Cross compile curl
  CURL_VERSION=7.65.1
  curl -LO https://curl.haxx.se/download/curl-$CURL_VERSION.tar.gz
  tar xvzf curl-$CURL_VERSION.tar.gz
  pushd curl-$CURL_VERSION
    ./configure --prefix=$CROSS_INSTALL_PREFIX --target=$CROSS_COMPILE_BIN_PREFIX --host=$CROSS_COMPILE_BIN_PREFIX --with-ssl=$CROSS_INSTALL_PREFIX --with-zlib=$CROSS_INSTALL_PREFIX
    make -j && make install
  popd
popd