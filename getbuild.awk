#!/usr/bin/mawk -Wexec
BEGIN {
   cmd = "scan-build --help"
   while (cmd | getline) {
      if (/^NOTES/) flag = 0
      if (flag) {
         var = $1 == "+" ? $2 : $1
         if (var ~ /\./ && var !~ /(osx|debug)\./)
            print "-enable-checker", var
      }
      if (/^AVAILABLE CHECKERS/) flag = 1
   }
   exit
}
END {
   exit close(cmd)
}
