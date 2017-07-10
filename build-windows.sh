#!/bin/sh
dir=build-windows
set -e
rm -rf -- "$dir"
mkdir -- "$dir"
cd -- "$dir"
mingw64-cmake .. -DCMAKE_EXPORT_COMPILE_COMMANDS:BOOL=ON -GNinja
sed -i 's/ -isystem / -I /g' build.ninja  compile_commands.json
ninja
TERM=dumb wine src/mytest
