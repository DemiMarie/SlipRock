#include <errno.h>
#include <fcntl.h>

#include <libgen.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <pwd.h>
#include <sys/un.h>

// Sodium
#include <sodium.h>
static pthread_once_t once = PTHREAD_ONCE_INIT;
#define SLIPROCK_MAGIC "\0SlipRock\n\rUNIX"
#ifndef SOCK_CLOEXEC
#define SLIPROCK_NO_SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#warning Cannot atomically set close-on-exec
#endif

struct SliprockConnection {
  size_t namelen;
  int fd;
  // const char path[SOCKET_PATH_LEN];
  char *path;
  struct sockaddr_un address;
  char passwd[32];
  char has_socket;
  char name[];
};

/* The maximum length of socket path (including terminating NUL) */
#define UNIX_PATH_LEN                                                          \
  (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

typedef int SliprockInternalHandle;
