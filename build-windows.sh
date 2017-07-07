#!/bin/sh
dir=build-windows
set -e
rm -rf -- "$dir"
mkdir -- "$dir"
cd -- "$dir"
mingw64-cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON
sed -i 's/ -isystem / -I /g' Makefile src/CMakeFiles/mytest.dir/includes_CXX.rsp compile_commands.json
make
wine src/mytest
