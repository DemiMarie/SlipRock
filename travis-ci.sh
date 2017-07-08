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
run_cmake () {
   cmake .. -DCMAKE_BUILD_TYPE=Release -DCMAKE_C_COMPILER="$cc" -DCMAKE_INSTALL_PREFIX="$HOME/.local" "$@"
}
if command -v ninja; then
    run_cmake -GNinja
    ninja
else
    run_cmake
    make
fi
src/mytest
