#!/bin/zsh
set -e
newline='
' buildtype=Debug target=unix mydir=$(dirname "$0"; echo a)
mydir=${mydir%"${newline}a"}
sanitizeflags='-fsanitize=address -pthread -fsanitize=undefined'
case $mydir in
   /*) cd "$mydir";;
    *) cd "./$mydir";;
esac
typeset -a definitions
for i; do
   case $i in
      unix) target=unix;;
      windows) target=windows sanitizeflags='';;
      debug) buildtype=Debug;;
      release) buildtype=Release;;
      cc=*) definitions+=(-DCMAKE_C_COMPILER=${i#cc=});;
      cxx=*) definitions+=(-DCMAKE_CXX_COMPILER=${i#cxx=});;
      -[DG]*) definitions+=($i);;
   esac
done
mydir=$PWD
tmpdir=$(mktemp -d)
trap 'rm -rf -- "$tmpdir"' EXIT
cd -- "$tmpdir"
if [[ $target = unix ]]; then
   run_with_checks () {
      #scan-build $(awk -f "$mydir/getbuild.awk") "$@"
      "$@"
   }
else
   for i in C CXX; do
      definitions+=("-DCMAKE_${i}_IMPLICIT_INCLUDE_DIRS=/usr/x86_64-w64-mingw32/sys-root/mingw/include")
   done
   run_with_checks () {
      print -r "$1"
      val=`basename "$1"`
      shift
      case $val in
         cmake|configure|pkg-config|env|make) mingw64-$val "$@" ;;
         *) printf %s\\n "$val"; "$val" "$@";;
      esac
   }
fi

run_with_checks cmake -G'Eclipse CDT4 - Unix Makefiles' \
   -DCMAKE_BUILD_TYPE="$buildtype" \
   -DCMAKE_C_FLAGS="$sanitizeflags" \
   -DCMAKE_CXX_FLAGS="$sanitizeflags" \
   -GNinja \
   "${definitions[@]}" \
   "$mydir"
for i in build.ninja \
         src/CMakeFiles/mytest.dir/includes_CXX.rsp \
         compile_commands.json
do
  #sed -i 's/ -isystem / -I /g' "$i" || :
done
run_with_checks ninja -j10 
if [[ $target = unix ]]; then
   LD_PRELOAD=/usr/lib64/libasan.so.4.0.0 src/mytest || gdb --tui test/mytest
else
   wine src/mytest.exe
fi
