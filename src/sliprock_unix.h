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
#include <assert.h>

// Sodium
#include <sodium.h>
static pthread_once_t once = PTHREAD_ONCE_INIT;
#define SLIPROCK_MAGIC "\0SlipRock\n\rUNIX"
#ifndef SOCK_CLOEXEC
#define SLIPROCK_NO_SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#warning Cannot atomically set close-on-exec
#endif

typedef char MyChar;

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

static const char *sliprock_get_home_directory(void **freeptr) {
  int e = errno;
  struct passwd *buf = NULL;
  size_t size = 28;
  struct passwd *pw_ptr;
  *freeptr = NULL;
  do {
    assert(size < (SIZE_MAX >> 1));
    if ((buf = realloc(buf, (size <<= 1) + sizeof(struct passwd))) == NULL) {
      // Yes, we need to handle running out of memory.
      return NULL;
    }
    pw_ptr = (struct passwd *)buf;
    memset(pw_ptr, 0, sizeof(struct passwd));
  } while (
      (e = getpwuid_r(getuid(), pw_ptr, (char *)buf + sizeof(struct passwd),
                      size, &pw_ptr)) &&
      e == ERANGE);
  if (pw_ptr == NULL) {
    free(buf);
    assert(e);
    errno = e;
    return NULL;
  }
  *freeptr = pw_ptr;
  return pw_ptr->pw_dir;
}
