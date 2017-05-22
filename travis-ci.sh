#!/usr/bin/env sh
set -ex
set | sort
mkdir build
cd build
cmake ..
make
make test
