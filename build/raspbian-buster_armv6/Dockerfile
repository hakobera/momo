# syntax = docker/dockerfile:1.1.1-experimental
FROM ubuntu:18.04

ARG PACKAGE_NAME

LABEL jp.shiguredo.momo=$PACKAGE_NAME

RUN rm -f /etc/apt/apt.conf.d/docker-clean; echo 'Binary::apt::APT::Keep-Downloaded-Packages "true";' > /etc/apt/apt.conf.d/keep-cache

# パッケージのインストール

COPY script/apt_install_arm.sh /root/
RUN --mount=type=cache,id=$PACKAGE_NAME,target=/var/cache/apt --mount=type=cache,id=$PACKAGE_NAME,target=/var/lib/apt \
  /root/apt_install_arm.sh

# RootFS の構築

COPY script/init_rootfs_armhf.sh /root/
COPY patch/rpi-raspbian.conf /root/
RUN --mount=type=cache,id=$PACKAGE_NAME,target=/var/cache/apt --mount=type=cache,id=$PACKAGE_NAME,target=/var/lib/apt \
  /root/init_rootfs_armhf.sh /root/rootfs /root/rpi-raspbian.conf

# WebRTC の取得

ARG WEBRTC_BUILD_VERSION

COPY script/get_webrtc.sh /root/
RUN /root/get_webrtc.sh "$WEBRTC_BUILD_VERSION" raspbian-buster_armv6 /root

# コンパイラの取得

COPY script/get_llvm.sh /root/
RUN /root/get_llvm.sh /root/webrtc /root

# Boost のビルド

ARG BOOST_VERSION

COPY script/setup_boost.sh /root/
RUN \
  set -ex \
  && /root/setup_boost.sh "$BOOST_VERSION" /root/boost-source \
  && cd /root/boost-source/source \
  && echo 'using clang : : /root/llvm/clang/bin/clang++ : ;' > project-config.jam \
  && ./b2 \
    cxxflags=' \
      -D_LIBCPP_ABI_UNSTABLE \
      -nostdinc++ \
      -isystem/root/llvm/libcxx/include \
      --target=arm-linux-gnueabihf \
      --sysroot=/root/rootfs \
      -I/root/rootfs/usr/include/arm-linux-gnueabihf \
    ' \
    linkflags=' \
      -L/root/rootfs/usr/lib/arm-linux-gnueabihf \
      -B/root/rootfs/usr/lib/arm-linux-gnueabihf \
    ' \
    toolset=clang \
    visibility=global \
    target-os=linux \
    architecture=arm \
    address-model=32 \
    link=static \
    variant=release \
    install \
    -j`nproc` \
    --ignore-site-config \
    --prefix=/root/boost \
    --with-filesystem

# nlohmann/json の取得

ARG JSON_VERSION
RUN git clone --branch v$JSON_VERSION --depth 1 https://github.com/nlohmann/json.git /root/json

# CLI11 の取得

ARG CLI11_VERSION
RUN git clone --branch v$CLI11_VERSION --depth 1 https://github.com/CLIUtils/CLI11.git /root/CLI11

# AWS SDK のビルド
ARG AWS_SDK_VERSION
COPY script/setup_aws_sdk.sh /root/
RUN \
  set -ex \
  && /root/setup_aws_sdk.sh "$AWS_SDK_VERSION" /root/aws-sdk-cpp-source

#COPY script/cross_compile_aws_sdk_armhf.sh /root/
#RUN \
#  set -ex \
#  && /root/cross_compile_aws_sdk_armhf.sh /root/aws-sdk-cpp-source /root/aws-sdk-cpp

COPY armv6.toolchain.cmake /root/aws-sdk-cpp-source/

RUN mkdir -p /root/aws-sdk-cpp-source/build \
  && cd /root/aws-sdk-cpp-source/build \
  && cmake \
     -DCMAKE_TOOLCHAIN_FILE="/root/aws-sdk-cpp-source/armv6.toolchain.cmake" \
     -DBUILD_ONLY="kinesisvideo" \
     -DBUILD_SHARED_LIBS=OFF \
     -DCPP_STANDARD=14 \
     -DCMAKE_INSTALL_PREFIX=/root/aws-sdk-cpp \
     -DCMAKE_PREFIX_PATH=/root/aws-sdk-cpp \
     -DAUTORUN_UNIT_TESTS=OFF \
     -DENABLE_TESTING=OFF \
     ../source \
  && make -j`nproc` \
  && make install
