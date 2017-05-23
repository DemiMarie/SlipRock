#!/usr/bin/env sh
set -ex
set | sort
rm -r build
mkdir build
cd build
cmake ..
make
src/mytest