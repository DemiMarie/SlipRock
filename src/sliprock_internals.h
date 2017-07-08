#ifndef SLIPROCK_INTERNALS_H_INCLUDED
#define SLIPROCK_INTERNALS_H_INCLUDED SLIPROCK_INTERNALS_H_INCLUDED

#include <stdint.h>
#ifndef _WIN32
#include <sys/types.h>
#elif defined _MSC_VER
#ifdef _WIN64
/* typedef __int64 ssize_t; */
#define ssize_t __int64
#else
/* typedef __int32 ssize_t; */
#define ssize_t __int32
#endif
#endif
#define MAGIC_SIZE (sizeof SLIPROCK_MAGIC - 1)
#ifdef SLIPROCK_TRACE
#define MADE_IT                                                           \
  ((void)(printf("File %s, line %d reached\n", __FILE__, __LINE__),       \
          fflush(stdout)))
#else
#define MADE_IT ((void)0)
#endif
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
#define MAX_SOCK_LEN (sizeof "\\\\?\\pipe\\SlipRock\\4294967295\\" + 16)
#endif
/* The actual connection struct */
struct SliprockConnection {
  size_t namelen;
  /* const char path[SOCKET_PATH_LEN]; */
  struct StringBuf path;
  unsigned char passwd[32];
  OsHandle fd;
#ifdef _WIN32
  wchar_t pipename[MAX_SOCK_LEN];
#else
  struct sockaddr_un address;
#endif
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
  unsigned char passcode[32]; /**< The passcode of the connection */
  int pid;
#ifndef _WIN32
  struct sockaddr_un sock; /**< The pathname of the socket */
#else
  wchar_t sock[MAX_SOCK_LEN];
#endif
};

/* Cryptographic random number generation */
#if defined __GNUC__ || defined __INTEL_COMPILER
__attribute__((warn_unused_result))
#endif
 int
sliprock_randombytes_sysrandom_buf(void *const buf, const size_t size);

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
