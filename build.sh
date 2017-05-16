#!/bin/sh
case $#,$1 in
   0,) target=unix;;
   1,unix) target=unix shift;;
   1,windows) target=windows shift;;
   *) echo 'Usage: build.sh [unix|windows]' >&2; exit 1;;
esac
set -e
mydir=$(dirname "$0")
#mydir=${mydir%'
#a'}
case $mydir in
   /*) cd "$mydir";;
    *) cd "./$mydir";;
esac
mydir=$PWD
tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT
cd -- "$tmpdir"
if test "$target" = unix; then
   run_with_checks () {
      CFLAGS=-fsanitize=address  scan-build $(cat "$mydir/checkers.txt") "$@"
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

run_with_checks cmake -G'Eclipse CDT4 - Unix Makefiles' -DCMAKE_BUILD_TYPE=Debug "$mydir" "$@"
run_with_checks make -j10 
LD_PRELOAD=/usr/lib64/libasan.so.4.0.0 src/mytest || gdb --tui test/mytest
