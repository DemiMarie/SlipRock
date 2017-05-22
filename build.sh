#!/bin/sh
set -e
newline='
' buildtype=Debug target=unix mydir=$(dirname "$0"; echo a) mydir=${mydir%"${newline}a"}
sanitizeflags='-fsanitize=address -pthread'
case $mydir in
   /*) cd "$mydir";;
    *) cd "./$mydir";;
esac
for i; do
   case $i in
      unix) target=unix;;
      windows) target=windows;;
      debug) buildtype=Debug;;
      release) buildtype=Release;;
   esac
done
mydir=$PWD
tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT
cd -- "$tmpdir"
if test "$target" = unix; then
   run_with_checks () {
      scan-build $(cat "$mydir/checkers.txt") "$@"
   }
else
   run_with_checks () {
      val=`basename "$1"` shift
      case $val in
         cmake|configure|pkg-config|env|make) mingw64-$val "$@" ;;
         *) "$val" "$@";;
      esac
   }
fi

run_with_checks cmake -G'Eclipse CDT4 - Unix Makefiles' \
   -DCMAKE_BUILD_TYPE="$buildtype" \
   -DCMAKE_C_FLAGS="$sanitizeflags" \
   -DCMAKE_CXX_FLAGS="$sanitizeflags" \
   "$mydir" "$@"
run_with_checks make -j10 
LD_PRELOAD=/usr/lib64/libasan.so.4.0.0 src/mytest || gdb --tui test/mytest
