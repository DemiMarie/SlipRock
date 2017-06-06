#!/usr/bin/env sh
set -ex
set | sort
rm -rf build
mkdir build
cd build
if command -v ninja; then
    cmake .. -GNinja
    ninja
else
    cmake ..
    make
fi
src/mytest
