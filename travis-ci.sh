#!/usr/bin/env sh
set -ex
set | sort
rm -rf build
mkdir build
cd build
cmake ..
make
make src/mytest
src/mytest