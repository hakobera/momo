#!/bin/bash

# 指定した AWS SDK for C++ をダウンロードして、make を実行できる状態にする
#
# ソースコードは $2/source に配置されるので、ここに cd した上で make を実行してビルドすること
#
# 引数:
#   $1: AWS SDK for C++ のタグ、もしくはブランチ
#   $2: 出力ディレクトリa

if [ $# -lt 2 ]; then
  echo "$0 <aws_sdk_version> <output_dir>"
  exit 1
fi

AWS_SDK_VERSION=$1
OUTPUT_DIR=$2

set -ex

mkdir -p $OUTPUT_DIR
pushd $OUTPUT_DIR
  if [ ! -e aws-sdk-cpp ]; then
    git clone https://github.com/aws/aws-sdk-cpp.git
  fi
  pushd aws-sdk-cpp
    git reset HEAD --hard
    git checkout master
    git pull
    git checkout $AWS_SDK_VERSION
  popd
popd
