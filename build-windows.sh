#!/bin/sh
set -e
rm -rf build
mkdir build
cd build
mingw64-cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON
sed -i 's/ -isystem / -I /g' Makefile src/CMakeFiles/mytest.dir/includes_CXX.rsp compile_commands.json
make
