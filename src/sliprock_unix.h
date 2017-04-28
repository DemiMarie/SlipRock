#include <errno.h>
#include <fcntl.h>

#include <assert.h>
#include <libgen.h>
#include <pthread.h>
#include <pwd.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/un.h>
#include <unistd.h>

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
  // const char path[SOCKET_PATH_LEN];
  char *path;
  char passwd[32];
  int fd;
  struct sockaddr_un address;
  char has_socket;
  char padding__[5];
  char name[];
};

/* The maximum length of socket path (including terminating NUL) */
#define UNIX_PATH_LEN                                                          \
  (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

typedef int SliprockInternalHandle;

// Get the user's home directory.
static const char *sliprock_get_home_directory(void **freeptr) {
  int e;
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
static int is_sodium_initialized;
static void init_libsodium(void) { is_sodium_initialized = sodium_init(); }

// Initialize libsodium
static int init_func(void) {
  int initialized = pthread_once(&once, &init_libsodium);
  if (initialized) {
    errno = initialized;
    return -1;
  }
  if (is_sodium_initialized == -1)
    return -1;
  return 0;
}

static int fill_randombuf(void *p, size_t size) {
   randombytes_buf(p, size);
   return 0;
}
#if 0
static int create_directory_and_file(MyChar *buf) {
   char *const terminus = strrchr(buf, '/');
   int dir_fd;
   int succeeded = 0;
   int file_fd = -1;
   assert(NULL != terminus && "create_directory_and_file passed a pathname with no path separator!");
   *terminus = '\0';
   if (mkdir(buf, 0700) && errno != EEXIST) {
      *terminus = '/';
      return -1;
   }
   if ((dir_fd = open(buf, O_DIRECTORY)) < 0) {
      *terminus = '/';
      return -1;
   }
   *terminus = '/';
   close(dir_fd);
   if (-1 != file_fd && !succeeded)
      close(file_fd);

}
#endif
