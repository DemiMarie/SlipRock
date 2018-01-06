#ifndef SLIPROCK_INTERNALS_H_INCLUDED
#define SLIPROCK_INTERNALS_H_INCLUDED SLIPROCK_INTERNALS_H_INCLUDED

#include "config.h"
#include <stdarg.h>
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
typedef int sliprock_os_socket_t;
#else
#include <winsock2.h>
typedef SOCKET sliprock_os_socket_t;
#ifdef _MSC_VER
#ifdef _WIN64
typedef __int64 ssize_t;
#else
typedef __int32 ssize_t;
#endif
#endif
#endif
#define MAGIC_SIZE (sizeof SLIPROCK_MAGIC - 1)
#ifdef SLIPROCK_TRACE
#include <stdio.h>
#define MADE_IT                                                           \
  (sliprock_trace("File %s, line %d reached\n", __FILE__, __LINE__))
#else
#define MADE_IT ((void)0)
#endif
#if defined __GNUC__ || defined __INTEL_COMPILER
__attribute__((format(printf, 1, 2)))
#endif
static inline void
sliprock_trace(const char *str, ...) {
#ifdef SLIPROCK_TRACE
  va_list args;
  va_start(args, str);
  vfprintf(stderr, str, args);
  va_end(args);
  fflush(stderr);
#else
  (void)str;
#endif
}

struct SliprockAnyConnection {
  unsigned char key[32];
  union {
    struct sockaddr_storage reserved;
#ifdef _WIN32
    struct sockaddr_in addr;
#else
    struct sockaddr_un addr;
#endif
  } sockaddr;
};
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
#include "stringbuf.h"

#ifdef _WIN32
#define MAX_SOCK_LEN (sizeof "\\\\?\\pipe\\SlipRock\\4294967295-" + 16)
#endif
/* The actual connection struct */
struct SliprockConnection {
  struct SliprockAnyConnection prefix;
  size_t namelen;
  /* const char path[SOCKET_PATH_LEN]; */
  struct StringBuf path;
  OsHandle fd;
  sliprock_os_socket_t socket;
  char has_socket;
  char name[];
};

#if defined __STDC_VERSION__ && __STDC_VERSION__ >= 199901L
#define STATIC_ARR static
#else
#define STATIC_ARR
#endif
/* A receiver for SlipRock connections */
struct SliprockReceiver {
  struct SliprockAnyConnection prefix;
  int pid;
};

#define NOINLINE SLIPROCK_NOINLINE

/* The "fuel" mechanism, used to test for robustness in error conditions.
 */
#ifdef SLIPROCK_DEBUG_FUEL
_Atomic ssize_t sliprock_fuel;
#define CHECK_FUEL(x)                                                     \
  if (__atomic_fetch_add(&sliprock_fuel, -1) < 0) {                       \
    x;                                                                    \
  } else                                                                  \
    do {                                                                  \
    } while (0)

#define CHECK_FUEL_EXPR(error, expr)                                      \
  (__atomic_fetch_add(&sliprock_fuel, -1) < 0 ? (error) : (expr))

inline void *sliprock_malloc(size_t size) {
  CHECK_FUEL(return NULL);
  return malloc(size);
}

inline void *sliprock_calloc(size_t size1, size_t size2) {
  CHECK_FUEL(return NULL);
  return calloc(size1, size2);
}

inline void *sliprock_realloc(void *ptr, size_t size) {
  CHECK_FUEL(return NULL);
  return realloc(ptr, size);
}

#define malloc sliprock_malloc
#define realloc sliprock_realloc
#define calloc sliprock_calloc

#else /* !defined SLIPROCK_DEBUG_FUEL */
#define CHECK_FUEL(x)                                                     \
  do {                                                                    \
  } while (0)
#define CHECK_FUEL_EXPR(x, y) (y)
#endif /* SLIPROCK_DEBUG_FUEL */

#endif
