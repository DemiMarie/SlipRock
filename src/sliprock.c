#ifdef NDEBUG
#error "Must be compiled with assertions enabled"
#endif
#define _GNU_SOURCE
#include <ctype.h>
#include <stdio.h>
#include <stdlib.h>

#include "sliprock.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <pthread.h>
#include <pwd.h>
#include <sodium.h>
#include <stddef.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

static pthread_once_t once = PTHREAD_ONCE_INIT;
#define SLIPROCK_MAGIC "\0SlipRock\n\rUNIX"

#define CON_PATH(con) ((con)->address.sun_path)
#include "sliprock.h"
#ifndef SOCK_CLOEXEC
#define SLIPROCK_NO_SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#error Cannot atomically set close-on-exec
#endif

struct fd {
  int fd;
};

struct SliprockConnection {
  const size_t namelen;
  struct fd fd;
  // const char path[SOCKET_PATH_LEN];
  const char *path;
  union {
    struct sockaddr_un address;
    struct sockaddr dontuse;
  };
  char passwd[32];
  char name[];
};

#ifdef __GNUC__
#pragma GCC poison dontuse
#endif

/* The maximum length of socket path (including terminating NUL) */
#define UNIX_PATH_LEN                                                          \
  (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))
static void init_libsodium(void) {
  int x = sodium_init();
  assert(x == 0);
}

void sliprock_close(struct SliprockConnection *connection) {
  if (NULL == connection) {
    return;
  }
  assert(connection->fd.fd >= 0);
  if (NULL != connection->path) {
    unlink(connection->path);
    free((void *)connection->path);
  }
  close(connection->fd.fd);
  unlink(CON_PATH(connection));
  rmdir(dirname(CON_PATH(connection)));
  free(connection);
}

static struct SliprockConnection *sliprock_new(const char *const name,
                                               const size_t namelen) {

  assert(namelen < (1UL << 16UL)); // arbitrary limit, but enough for anyone

  // Initialize libsodium
  {
    int initialized = pthread_once(&once, &init_libsodium) == 0;
    assert(initialized);
  }

  struct SliprockConnection *connection =
      calloc(1, namelen + sizeof(struct SliprockConnection));

  if (NULL == connection)
    return NULL;

  connection->address.sun_family = AF_UNIX;

  // We have (by construction) enough space for the name
  memcpy(&connection->name, name, namelen);

  return connection;
}

static struct passwd *get_password_entry(void) {
  error_t e = errno;
  char *buf = NULL;
  size_t size = 28;
  struct passwd *pw_ptr;
  do {
    assert(size < (SIZE_MAX >> 1));
    if ((buf = realloc(buf, (size <<= 1) + sizeof(struct passwd))) == NULL) {
      // Yes, we need to handle running out of memory.
      return NULL;
    }
    pw_ptr = (struct passwd *)buf;
    memset(pw_ptr, 0, sizeof(struct passwd));
  } while ((e = getpwuid_r(getuid(), pw_ptr, buf + sizeof(struct passwd), size,
                           &pw_ptr)) &&
           e == ERANGE);
  if (pw_ptr == NULL) {
    free(buf);
    assert(e);
    errno = e;
    return NULL;
  }
  return pw_ptr;
}
static char *get_fname(const char *srcname, size_t len, int pid, int *innerlen,
                       int *outerlen) {
  char *fname_buf = NULL;
  int innerlen_;
  struct passwd *const pw = get_password_entry();
  if (NULL == pw)
    goto fail;

  size_t newsize = len + sizeof "/.sliprock/..sock" + 20 + strlen(pw->pw_dir);

  fname_buf = malloc(newsize);
  if (!fname_buf)
    goto fail;
  /* Create the sliprock directory.  It’s okay if this directory already exists
   */
  /* This directory is deliberately leaked */
  innerlen_ = snprintf(fname_buf, newsize, "%s/.sliprock/", pw->pw_dir);
  if (innerlen_ < 0)
    goto fail;
  assert((size_t)innerlen_ < newsize);
  if (mkdir(fname_buf, 0700) < 0 && errno != EEXIST)
    goto fail;
  errno = 0;
  int newlength = snprintf(fname_buf + innerlen_, newsize - innerlen_,
                           "%d.%s.sock", pid, srcname);
  if (newlength < 0)
    goto fail;
  if (outerlen)
    *outerlen = newlength;
  if (innerlen)
    *innerlen = innerlen_;
  free(pw);
  return fname_buf;
fail:
  free(pw);
  if (innerlen)
    *innerlen = 0;
  if (outerlen)
    *outerlen = 0;
  free(fname_buf);
  return NULL;
}

static int sliprock_bind(struct SliprockConnection *con) {
  error_t e = errno;
  int succeeded = 0;
  int fd = -1, dir_fd = -1;
  int newlength, res;
  char *fname_buf =
      get_fname(con->name, con->namelen, getpid(), &res, &newlength);
  if (NULL == fname_buf)
    goto fail;
  fname_buf[res - 1] = '\0';
  dir_fd = open(fname_buf, O_DIRECTORY | O_CLOEXEC, 0700);
  if (dir_fd < 0)
    goto fail;
  fname_buf[res - 1] = '/';
  con->path = fname_buf;

  /* We have an FD on the directory, so use openat(2) instead of open(2) */
  fd = openat(dir_fd, fname_buf + res, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
              0600);
  if (fd < 0)
    goto fail;

  randombytes_buf(con->passwd, sizeof con->passwd);
  struct iovec vec[] = {
      {SLIPROCK_MAGIC, sizeof SLIPROCK_MAGIC},
      {con->passwd, sizeof con->passwd},
      {&con->address, sizeof con->address},
  };
  if (writev(fd, vec, 3) < 0)
    goto fail; // Write failed

  // Ensure that the file's contents are valid.
  if (close(fd) < 0) {
    // Don't double-close – the state of the FD is unspecified.  Better to
    // leak an FD than close an FD that other code could be using.
    fd = -1;
    goto fail;
  }
  fd = -1;

  // Ensure that the newly created file is visible to other programs
  if (fsync(dir_fd) < 0)
    goto fail;
  errno = 0;
  succeeded = 1;
fail:
  e = errno;
  if (!succeeded) {
    free(fname_buf);
    con->path = NULL;
  }
  if (fd != -1)
    close(fd);
  if (dir_fd != -1)
    close(dir_fd);
  return errno = e;
}
#include "charset.c"

struct SliprockConnection *sliprock_socket(const char *const name,
                                           size_t const namelen) {
  assert(name != NULL);
#if 0
  if (!sliprock_is_valid_filename(name, namelen)) {
    errno = EINVAL;
    return NULL;
  }
#endif
  // TODO allow unicode
  for (size_t i = 0; i < namelen; ++i) {
    if (!isalnum(name[i]) && name[i] != '-' && name[i] != '.' &&
        name[i] != '_') {
      errno = EILSEQ;
      return NULL;
    }
  }
  unsigned char tmp[16];
  // Allocate the connection
  struct SliprockConnection *connection = sliprock_new(name, namelen);
  char created_directory = 0;
  if (NULL == connection)
    return NULL;
  (void)SLIPROCK_STATIC_ASSERT(sizeof connection->address.sun_path >
                               sizeof "/tmp/sliprock." - 1 + 20 + 1 + 16 + 1 +
                                   16 + 1);

  // Establish the socket
  connection->fd.fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (connection->fd.fd < 0)
    goto fail;

// Set close-on-exec if it could not have been done atomically.
#ifdef SLIPROCK_NO_SOCK_CLOEXEC
  int res = fcntl(connection->fd.fd, F_SETFD, FD_CLOEXEC);
  assert(res == 0);
#endif

// Temporary buffer used for random numbers
retry:
  randombytes_buf(tmp, sizeof tmp);

  int count = snprintf(connection->address.sun_path,
                       sizeof connection->address.sun_path, "/tmp/sliprock.%d.",
                       getpid());
  char *off = connection->address.sun_path + count;
  size_t remaining = sizeof connection->address.sun_path - count;
  char *res = sodium_bin2hex(off, remaining, tmp, 8);
  assert(res == off);
  res += 16;
  remaining -= 16;
  if (mkdir(connection->address.sun_path, 0700) < 0) {
    if (errno == EEXIST)
      goto retry;
    goto fail;
  }
  created_directory = 1;
  res[0] = '/';
  sodium_bin2hex(res + 1, remaining - 1, tmp + 8, 8);
  /* Bind the socket */
  if (bind(connection->fd.fd, &connection->address,
           sizeof(struct sockaddr_un)) < 0)
    goto fail;
  if (listen(connection->fd.fd, INT_MAX) < 0)
    goto fail;
  if ((errno = sliprock_bind(connection))) {
    sliprock_close(connection);
    return NULL;
  }

  return connection;
fail:
  if (connection != NULL) {
    if (connection->fd.fd != -1) {
      close(connection->fd.fd);
    }
    if (created_directory) {
      rmdir(dirname(connection->address.sun_path));
    }
    free(connection);
  }
  return NULL;
}

struct SliprockReceiver {
  struct sockaddr_un sock; //< The pathname of the socket
  char passcode[32];       //< The passcode of the connection
  int pid;
};

void sliprock_close_receiver(SliprockReceiver *receiver) { free(receiver); }

struct SliprockReceiver *sliprock_open(const char *const filename, size_t size,
                                       pid_t pid) {
  assert(strlen(filename) == size);
  errno = 0;
  struct SliprockReceiver *receiver = NULL;
  char *fname = get_fname(filename, size, pid, NULL, NULL);
  if (!fname)
    return NULL;
  errno = 0;
  int fd = open(fname, O_RDONLY);
  if (fd < 0)
    goto fail;
  receiver = calloc(1, sizeof(struct SliprockReceiver));
  if (NULL == receiver)
    goto fail;

  char magic[sizeof(SLIPROCK_MAGIC)];
  struct iovec vecs[] = {
      {magic, sizeof magic},
      {receiver->passcode, sizeof receiver->passcode},
      {&receiver->sock, sizeof receiver->sock},
  };
  ssize_t res = readv(fd, vecs, 3);
  if (res < (ssize_t)(sizeof magic + sizeof receiver->passcode +
                      sizeof receiver->sock))
    goto fail;
  assert(receiver->sock.sun_family == AF_UNIX);
  close(fd);
  free(fname);
  return receiver;
  int err;
fail:
  err = errno;
  if (fd >= 0)
    close(fd);
  free(fname);
  sliprock_close_receiver(receiver);
  errno = err;
  return NULL;
}

int sliprock_accept(SliprockConnection *connection) {
  struct sockaddr_un _dummy;
  socklen_t _dummy2 = sizeof(struct sockaddr_un);
#ifdef __linux__
  int fd = accept4(connection->fd.fd, &_dummy, &_dummy2, SOCK_CLOEXEC);
  if (fd < 0)
    return -1;
#else
  int fd = accept(connection->fd.fd, &_dummy, &_dummy2);
  if (fd < 0)
    return -1;
  fcntl(fd, F_SETFD, FD_CLOEXEC);
#endif
  if (write(fd, connection->passwd, sizeof connection->passwd) < 32) {
    close(fd);
    return -1;
  }
  return fd;
}

int sliprock_connect(struct SliprockReceiver *receiver) {
  int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (sock < 0)
    return SLIPROCK_EOSERR;
#ifdef SLIPROCK_NO_SOCK_CLOEXEC
  if (fcntl(sock, FD_CLOEXEC))
    goto oserr;
#endif
  if (connect(sock, &receiver->sock, sizeof(struct sockaddr_un)) < 0)
    goto oserr;
  char pw_received[32];
  if (read(sock, pw_received, sizeof pw_received) < 32)
    goto badpass;
  if (sodium_memcmp(pw_received, receiver->passcode, 32))
    goto badpass;
  return sock;
badpass:
  close(sock);
  return SLIPROCK_EBADPASS;
oserr:
  close(sock);
  return SLIPROCK_EOSERR;
}
