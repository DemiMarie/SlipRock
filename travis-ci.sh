#!/usr/bin/env sh
case $0 in
    */*) cd "${0%/*}/";;
esac
set -ex
set | sort
rm -rf build
mkdir build
cd build
cc=cc
if command -v ninja; then
    cmake .. -GNinja -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER="$cc"
    ninja
else
    cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_COMPILER="$cc"
    make
fi
src/mytest
