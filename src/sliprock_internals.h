#ifndef SLIPROCK_INTERNALS_H_INCLUDED
#define SLIPROCK_INTERNALS_H_INCLUDED SLIPROCK_INTERNALS_H_INCLUDED

#ifdef _WIN32
#include <windows.h>
typedef wchar_t MyChar;
typedef HANDLE OsHandle;
#else

#include <sys/types.h>
#include <sys/un.h>
typedef char MyChar;
typedef int OsHandle;
#endif

#if 4294967295ULL + 1 != 1ULL << 32
#error impossible
#endif
struct SliprockConnection {
  size_t namelen;
  // const char path[SOCKET_PATH_LEN];
  struct StringBuf *path;
  char passwd[32];
  OsHandle fd;
#ifdef _WIN32
  wchar_t pipename[sizeof "\\\\?\\pipe\\SlipRock\\4294967295\\" + 16];
#else
  struct sockaddr_un address;
#endif
  char has_socket;
  char name[];
};
#ifdef _WIN32
#include "sliprock_windows.h"
#else
#include "sliprock_unix.h"
#endif
#endif
