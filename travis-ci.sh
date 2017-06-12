#!/usr/bin/env sh
set -ex
set | sort
rm -rf build
mkdir build
cd build
if command -v ninja; then
    cmake .. -GNinja -DCMAKE_BUILD_TYPE=Debug
    ninja
else
    cmake .. -DCMAKE_BUILD_TYPE=Debug
    make
fi
src/mytest
