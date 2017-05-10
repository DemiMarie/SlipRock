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

#include "stringbuf.h"
struct SliprockReceiver {
  char passcode[32]; ///< The passcode of the connection
  int pid;
  struct sockaddr_un sock; ///< The pathname of the socket
};

#define sliprock_unlink unlink
#define INVALID_HANDLE_VALUE -1
static pthread_once_t once = PTHREAD_ONCE_INIT;
#define SLIPROCK_MAGIC "\0SlipRock\n\rUNIX\x1a"
#ifndef SOCK_CLOEXEC
#define SLIPROCK_NO_SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#warning Cannot atomically set close-on-exec
#endif

#define T(x) ("" x)
typedef char MyChar;
typedef int OsHandle;

#ifndef SLIPROCK_UNIX_H_INCLUDED
#define SLIPROCK_UNIX_H_INCLUDED SLIPROCK_UNIX_H_INCLUDED
/* The maximum length of socket path (including terminating NUL) */
#define UNIX_PATH_LEN                                                     \
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
    if ((buf = (struct passwd *)realloc(
             buf, (size <<= 1) + sizeof(struct passwd))) == NULL) {
      // Yes, we need to handle running out of memory.
      return NULL;
    }
    pw_ptr = (struct passwd *)buf;
    memset(pw_ptr, 0, sizeof(struct passwd));
  } while ((e = getpwuid_r(getuid(), pw_ptr,
                           (char *)buf + sizeof(struct passwd), size,
                           &pw_ptr)) &&
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
// Returns nonzero on success
static int fill_randombuf(void *p, size_t size) {
  randombytes_buf(p, size);
  return 1;
}
#define CON_PATH(con) ((con)->address.sun_path)
static int makedir(MyChar *ptr) { return mkdir(ptr, 0700); }

static OsHandle openfile(MyChar *ptr, int mode) {
  return open(ptr, mode, 0700);
}

static int create_directory_and_file(struct StringBuf *buf) {
  char *const terminus = strrchr(buf->buf, '/');
  int dir_fd = -1, file_fd = -1;
  assert(NULL != terminus && "create_directory_and_file passed a pathname "
                             "with no path separator!");
  *terminus = '\0';
  if (mkdir(buf->buf, 0700) && errno != EEXIST)
    goto fail;
  if ((dir_fd = open(buf->buf, O_DIRECTORY | O_RDONLY | O_CLOEXEC)) < 0)
    goto fail;
  *terminus = '/';
  file_fd = openat(dir_fd, terminus + 1,
                   O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  if (file_fd < 0)
    goto fail;
  if (fsync(dir_fd) < 0)
    goto fail;
  if (close(dir_fd) < 0) {
    dir_fd = -1;
    goto fail;
  }
  return file_fd;
fail:
  if (file_fd != -1)
    close(file_fd);
  if (dir_fd != -1)
    close(dir_fd);
  *terminus = '/';
  return -1;
}
#define CopyIdent(x, y) (x)
#define FreeIdent(x) ((void)0)
static int write_connection(OsHandle fd, struct SliprockConnection *con) {
  struct iovec vec[] = {
      {SLIPROCK_MAGIC, sizeof SLIPROCK_MAGIC - 1},
      {con->passwd, sizeof con->passwd},
      {&con->address, sizeof con->address},
  };
  return writev(fd, vec, 3);
}

static int read_receiver(OsHandle fd, struct SliprockReceiver *receiver,
                         char magic[static sizeof SLIPROCK_MAGIC - 1]) {
  struct iovec vecs[] = {
      {magic, sizeof SLIPROCK_MAGIC - 1},
      {receiver->passcode, sizeof receiver->passcode},
      {&receiver->sock, sizeof receiver->sock},
  };
  return readv(fd, vecs, 3);
}

#define hclose close

static void delete_socket(char *buf) {
  unlink(buf);
  rmdir(dirname(buf));
}
#ifndef __linux__
static void set_cloexec(OsHandle fd) { fcntl(fd, F_SETFD, FD_CLOEXEC); }
#endif

static int sliprock_fsync(int fd) { return fsync(fd); }

static int make_sockdir(struct SliprockConnection *connection) {
  // Temporary buffer used for random numbers
  unsigned char tmp[16];
  (void)SLIPROCK_STATIC_ASSERT(sizeof CON_PATH(connection) >
                               sizeof "/tmp/sliprock." - 1 + 20 + 1 + 16 +
                                   1 + 16 + 1);

retry:
  if (fill_randombuf(tmp, sizeof tmp) == 0)
    return -1;
  int count = snprintf(CON_PATH(connection), sizeof CON_PATH(connection),
                       "/tmp/sliprock.%d.", getpid());
  if (count < 0)
    return -1;
  char *off = CON_PATH(connection) + count;
  size_t remaining = sizeof CON_PATH(connection) - (size_t)count;
  char *res = sodium_bin2hex(off, remaining, tmp, 8);
  assert(res == off);
  res += 16;
  remaining -= 16;
  if (makedir(CON_PATH(connection)) < 0) {
    if (errno == EEXIST)
      goto retry;
    return -1;
  }
  connection->has_socket = 1;
  res[0] = '/';
  sodium_bin2hex(res + 1, remaining - 1, tmp + 8, 8);
  return 0;
}

#define MyStrlen strlen

static void remove_file(const char *filename) { unlink(filename); }


SliprockHandle sliprock_connect(const struct SliprockReceiver *receiver) {
  int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sock < 0)
    return (SliprockHandle)SLIPROCK_EOSERR;
#ifdef SLIPROCK_NO_SOCK_CLOEXEC
  set_cloexec(sock);
#endif
  if (connect(sock, &receiver->sock, sizeof(struct sockaddr_un)) < 0)
    goto oserr;
  char pw_received[32];
  if (read(sock, pw_received, sizeof pw_received) < 32)
    goto badpass;
  if (sodium_memcmp(pw_received, receiver->passcode, 32))
    goto badpass;
  return (SliprockHandle)sock;
badpass:
  hclose(sock);
  return (SliprockHandle)SLIPROCK_EBADPASS;
oserr:
  hclose(sock);
  return (SliprockHandle)SLIPROCK_EOSERR;
}
#define UNIX_CONST const
#endif
