#!/usr/bin/env sh
set -ex
set | sort
curl -L -o release-1.8.0.zip \
   https://github.com/google/googletest/archive/release-1.8.0.zip
unzip release-1.8.0.zip
cd googletest-release-1.8.0
cmake -DCMAKE_INSTALL_PREFIX=.. .
make
make install
cd ..
mkdir build
cd build
cmake ..
make
make test
