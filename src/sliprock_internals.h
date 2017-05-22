#ifndef SLIPROCK_INTERNALS_H_INCLUDED
#define SLIPROCK_INTERNALS_H_INCLUDED SLIPROCK_INTERNALS_H_INCLUDED
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
#define PIPE_SIZE (sizeof "\\\\?\\pipe\\SlipRock\\4294967295\\" + 16)
/* The actual connection struct */
struct SliprockConnection {
  size_t namelen;
  /* const char path[SOCKET_PATH_LEN]; */
  struct StringBuf path;
  char passwd[32];
  OsHandle fd;
#ifdef _WIN32
  wchar_t pipename[PIPE_SIZE];
#else
  struct sockaddr_un address;
#endif
  char has_socket;
  char name[];
};

/* A receiver for SlipRock connections */
struct SliprockReceiver {
  unsigned char passcode[32]; /**< The passcode of the connection */
  int pid;
#ifndef _WIN32
  struct sockaddr_un sock; /**< The pathname of the socket */
#else
  wchar_t sock[PIPE_SIZE];
#endif
};

/* Cryptographic random number generation */
__attribute__((warn_unused_result)) int
sliprock_randombytes_sysrandom_buf(void *const buf, const size_t size);

/* The "fuel" mechanism, used to test for robustness in error conditions.
 */
#ifdef SLIPROCK_DEBUG_FUEL
#include <stdatomic.h>
_Atomic ssize_t sliprock_fuel;
#define CHECK_FUEL(x)                                                     \
  if (atomic_fetch_add(&sliprock_fuel, -1) < 0) {                         \
    x;                                                                    \
  } else                                                                  \
    do {                                                                  \
    } while (0)
#define CHECK_FUEL_EXPR(error, expr)                                      \
  (atomic_fetch_add(&sliprock_fuel, -1) < 0 ? (error) : (expr))
#define malloc sliprock_malloc
#define realloc sliprock_realloc
#define calloc sliprock_calloc
static void *sliprock_malloc(size_t size) {
  CHECK_FUEL(return NULL);
  return malloc(size);
}
static void *sliprock_calloc(size_t size1, size_t size2) {
  CHECK_FUEL(return NULL);
  return calloc(size1, size2);
}
static void *sliprock_realloc(void *ptr, size_t size) {
  CHECK_FUEL(return NULL);
  return realloc(ptr, size);
}

#else
#define CHECK_FUEL(x)                                                     \
  do {                                                                    \
  } while (0)
#define CHECK_FUEL_EXPR(x, y) (y)
#endif
#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#elif defined __GNUC__
#define NOINLINE __attribute__((noinline))
#else
#error dont know how to tell the compiler not to inline this
#endif
NOINLINE int
sliprock_secure_compare_memory(const volatile unsigned char *const buf1,
                               const volatile unsigned char *const buf2,
                               size_t len);

#endif
