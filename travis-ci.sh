#!/usr/bin/env sh
set -ex
set | sort
mkdir build-gtest
cd build-gtest
curl -L -o release-1.8.0.zip \
   https://github.com/google/googletest/archive/release-1.8.0.zip
unzip release-1.8.0.zip
cmake -DCMAKE_PREFIX_PATH=.. .
make
make install
cd ..
mkdir build
cd build
cmake ..
make
make test
