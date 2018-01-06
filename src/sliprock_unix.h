#ifndef SLIPROCK_UNIX_H_INCLUDED
#define SLIPROCK_UNIX_H_INCLUDED
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include <assert.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <sys/un.h>
#include <unistd.h>

#include "sliprock_poll.h"
#include <include/sliprock.h>
#include <src/sliprock_internals.h>
#include <src/stringbuf.h>
#define hclose close

#define sliprock_unlink unlink
#define INVALID_HANDLE_VALUE ((SliprockHandle)-1)

#define SLIPROCK_MAGIC "\0SlipRock\n\rUNIX\x1a"
#ifndef SOCK_CLOEXEC
#define SLIPROCK_NO_SOCK_CLOEXEC
#define SOCK_CLOEXEC 0
#warning Cannot atomically set close-on-exec
#endif

#define T(x) ("" x)

#define MAX_SOCK_LEN                                                      \
  (sizeof "/tmp/sliprock." - 1 /* terminating NUL */ +                    \
   20 /* PID as int */ + 1 /* '.' */ + 16 /* 16 random bytes */ +         \
   1 /* '/' */ + 16 /* 16 random bytes */ + 1 /* terminating NUL */)

/* The maximum length of socket path (including terminating NUL) */
#define UNIX_PATH_LEN                                                     \
  (sizeof(struct sockaddr_un) - offsetof(struct sockaddr_un, sun_path))

typedef int SliprockInternalHandle;

static int sliprock_get_home_directory(void **freeptr,
                                       const char **homedir);

static int sliprock_make_sockdir(struct SliprockConnection *connection);

#define CON_PATH(con) ((con)->prefix.sockaddr.addr.sun_path)

int sliprock_bind_os(struct SliprockConnection *connection);

SLIPROCK_API int sliprock_accept(struct SliprockConnection *connection,
                                 SliprockHandle *handle) {
  struct sliprock_pending_connection con;
  struct sockaddr_un _dummy;
  socklen_t _dummy2 = sizeof(struct sockaddr_un);
  int fd;

  memset(&_dummy, 0, sizeof(_dummy));
  memset(&con, 0, sizeof(con));
  assert(-1 != connection->fd);
#if SLIPROCK_HAVE_ACCEPT4
  fd = accept4(connection->fd, &_dummy, &_dummy2, SOCK_CLOEXEC);
  *handle = (SliprockHandle)fd;
  if (fd < 0)
    return SLIPROCK_EOSERR;
#else
  fd = accept(connection->fd, &_dummy, &_dummy2);
  *handle = (SliprockHandle)fd;
  if (fd < 0)
    return SLIPROCK_EOSERR;
  sliprock_set_cloexec(fd);
#endif
  sliprock__init_pending_connection(&con, connection->prefix.key);
  int retval = sliprock__poll(&con, fd, 500);
  if (retval < 0) {
    close(fd);
    return retval;
  }
  return 0;
}

int sliprock_bind_os(struct SliprockConnection *connection) {
  if (sliprock_make_sockdir(connection) < 0)
    return -1;

  /* Establish the socket */
  connection->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (connection->fd >= 0) {

#ifdef SLIPROCK_NO_SOCK_CLOEXEC
    /* Set close-on-exec if it could not have been done atomically. */
    sliprock_set_cloexec(connection->fd);
#endif

    /* Bind the socket */
    if (bind(connection->fd,
             (struct sockaddr *)&connection->prefix.sockaddr.addr,
             sizeof(struct sockaddr_un)) == 0) {
      if (listen(connection->fd, INT_MAX) == 0) {
        return 0;
      }
      unlink(CON_PATH(connection));
    }
    hclose(connection->fd);
  }
  rmdir(strrchr(CON_PATH(connection), '/'));
  return -1;
}

/**
 * Get the user's home directory.  A void* will be placed in freeptr
 * that must be passed to free(3) when needed.  Doing so invalidates
 * the returned pointer.
 *
 * On error, returns NULL and set errno.
 */
static int sliprock_get_home_directory(void **freeptr,
                                       const char **homedir) {
  int e;
  char *buf = NULL;
  size_t size = 28;
  struct passwd pw, *pw_ptr;
  memset(&pw, 0, sizeof(pw));
  assert(homedir != NULL);
  *homedir = NULL;
  *freeptr = NULL;
  do {
    char *old_buf = buf;
    assert(size < (SIZE_MAX >> 1));
    if ((buf = realloc(buf, (size <<= 1))) == NULL) {
      /* Yes, we need to handle running out of memory. */
      free(old_buf);
      return SLIPROCK_ENOMEM;
    }
    pw_ptr = &pw;
    memset(pw_ptr, 0, sizeof(struct passwd));
  } while (CHECK_FUEL_EXPR(
      (pw_ptr = NULL, e = ENOSYS),
      ((e = getpwuid_r(getuid(), pw_ptr, buf, size, &pw_ptr)) &&
       e == ERANGE)));
  if (pw_ptr == NULL) {
    free(buf);
    assert(e);
    errno = e;
    return SLIPROCK_EOSERR;
  }
  *freeptr = buf;
  *homedir = pw_ptr->pw_dir;
  return 0;
}

/* Open a file */
static OsHandle openfile(MyChar *ptr, int mode) {
  return open(ptr, mode, 0600);
}

/* Create a file, and (if necessary) the containing directory.
 * Don't fail if the containing directory already exists. */
static int create_directory_and_file(struct StringBuf *buf) {
  char *const terminus = strrchr(buf->buf, '/');
  char *dummybuf = NULL;
  int dir_fd = -1, file_fd = -1;
  assert(buf->buf_capacity - buf->buf_length > 17);
  assert(NULL != terminus && "create_directory_and_file passed a pathname "
                             "with no path separator!");
  *terminus = '\0';
  if (mkdir(buf->buf, 0700) && errno != EEXIST)
    goto fail;
  if ((dir_fd = open(buf->buf, O_DIRECTORY | O_RDONLY | O_CLOEXEC)) < 0)
    goto fail;
  if (fchmod(dir_fd, 0700) < 0)
    goto fail;
  *terminus = '/';
#if SLIPROCK_HAVE_RENAMEAT
  dummybuf = strdup(terminus + 1);
#else
  dummybuf = strdup(buf->buf);
#endif
  if (dummybuf == NULL)
    goto fail;

  while (1) {
    uint64_t rnd;
    if (sliprock_randombytes_sysrandom_buf(&rnd, sizeof rnd) < 0)
      goto fail;
    StringBuf_add_hex(buf, rnd);
#if SLIPROCK_HAVE_OPENAT
    file_fd = openat(dir_fd, terminus + 1,
                     O_RDWR | O_CREAT | O_CLOEXEC | O_EXCL, 0600);
#else
    file_fd = open(buf->buf, O_RDWR | O_CREAT | O_CLOEXEC | O_EXCL, 0600);
#endif
    assert(file_fd >= 0);
    if (file_fd >= 0 || EEXIST != errno)
      break;
    buf->buf -= 16;
  }
#if SLIPROCK_HAVE_RENAMEAT
  if (renameat(dir_fd, terminus + 1, dir_fd, dummybuf) < 0) {
    goto fail;
  }
#else
  if (rename(buf->buf, dummybuf) < 0) {
    goto fail;
  }
#endif
  if (file_fd >= 0) {
    /* According to the man page, this is necessary to ensure that other
     * processes see the newly-created file */
    if (fsync(dir_fd) >= 0) {
      if (close(dir_fd) >= 0) {
        free(dummybuf);
        return file_fd;
      }
      /* darn… */
      dir_fd = -1;
    }
    close(file_fd);
  }
fail:
  free(dummybuf);
  if (dir_fd != -1)
    close(dir_fd);
  *terminus = '/';
  return -1;
}
#define CopyIdent(x, y) (x)
#define FreeIdent(x) ((void)0)
static int write_connection(OsHandle fd, struct SliprockConnection *con) {
  static const ssize_t len =
      MAX_SOCK_LEN + sizeof con->prefix.key + sizeof SLIPROCK_MAGIC - 1;
  struct iovec vec[] = {
      {SLIPROCK_MAGIC, sizeof SLIPROCK_MAGIC - 1},
      {con->prefix.key, sizeof con->prefix.key},
      {con->prefix.sockaddr.addr.sun_path, MAX_SOCK_LEN},
  };
  return writev(fd, vec, 3) == len ? 0 : -1;
}

/* Delete both the socket and the containing directory */
static void delete_socket(struct SliprockConnection *connection) {
  if (connection->has_socket) {
    sliprock_unlink(CON_PATH(connection));
    rmdir(dirname(CON_PATH(connection)));
  } else {
    rmdir(CON_PATH(connection));
  }
}

/* Read a receiver into a SliprockReceiver struct */
static ssize_t sliprock_read_receiver(OsHandle fd,
                                      struct SliprockReceiver *receiver,
                                      char magic[STATIC_ARR MAGIC_SIZE]) {
  struct iovec vecs[] = {
      {magic, sizeof SLIPROCK_MAGIC - 1},
      {receiver->prefix.key, sizeof receiver->prefix.key},
      {&receiver->prefix.sockaddr.addr.sun_path, MAX_SOCK_LEN},
  };
  memset(receiver, 0, sizeof *receiver);
  receiver->prefix.sockaddr.addr.sun_family = AF_UNIX;
  return readv(fd, vecs, 3);
}

#if !SLIPROCK_HAVE_ACCEPT4
static void sliprock_set_cloexec(OsHandle fd) {
  fcntl(fd, F_SETFD, FD_CLOEXEC);
}
#endif

static int sliprock_fsync(int fd) { return fsync(fd); }

/* Make a directory to hold a socket, and fill connection with the path */
static int sliprock_make_sockdir(struct SliprockConnection *connection) {
  /* Temporary buffer used for random numbers */
  uint64_t tmp[2];
  struct stat stat_buf;
  struct StringBuf buf;
  memset(&stat_buf, 0, sizeof stat_buf);
  SLIPROCK_STATIC_ASSERT(sizeof CON_PATH(connection) > MAX_SOCK_LEN);
  SLIPROCK_STATIC_ASSERT(MAX_SOCK_LEN == 69);
  /* Check to make sure that /tmp is sticky and owned by root. */
  /* No need to check ‘/’ – if it has bad perms we are sunk. */
  if (stat("/tmp", &stat_buf) < 0)
    return -1;
  if (stat_buf.st_uid != 0 || (stat_buf.st_mode & 01000) == 0)
    return -1;
  do {
    CHECK_FUEL(return -1);
    if (sliprock_randombytes_sysrandom_buf(tmp, sizeof tmp) < 0)
      return -1;
    CHECK_FUEL(return -1);
    StringBuf_init(&buf, MAX_SOCK_LEN, 0, CON_PATH(connection));
    CHECK_FUEL(return -1);
    StringBuf_add_literal(&buf, "/tmp/sliprock.");
    StringBuf_add_decimal(&buf, (uintptr_t)getpid());
    StringBuf_add_char(&buf, '.');
    StringBuf_add_hex(&buf, *tmp);
    errno = 0;
  } while (mkdir(buf.buf, 0700) < 0 && EEXIST == errno);
  if (errno)
    return -1;
  connection->has_socket = 1;
  StringBuf_add_char(&buf, '/');
  StringBuf_add_hex(&buf, tmp[1]);
  return 0;
}

#define MyStrlen strlen

/* See documentation in sliprock.h */
int sliprock_connect(const struct SliprockReceiver *receiver,
                     SliprockHandle *handle) {
  SLIPROCK_STATIC_ASSERT(sizeof(struct sockaddr_storage) >=
                         sizeof(struct sockaddr_un));
  int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  struct sliprock_pending_connection con;
  *handle = INVALID_HANDLE_VALUE;
  if (sock < 0)
    return SLIPROCK_EOSERR;
#ifdef SLIPROCK_NO_SOCK_CLOEXEC
  sliprock_set_cloexec(sock);
#endif
  if (connect(sock, &receiver->prefix.sockaddr.addr,
              sizeof(receiver->prefix.sockaddr.addr)) < 0) {
    hclose(sock);
    return SLIPROCK_EOSERR;
  }
  sliprock__init_pending_connection(&con, receiver->prefix.key);
  int res = sliprock__poll(&con, sock, 500);
  if (res >= 0) {
    *handle = sock;
    return 0;
  }
  return res;
}
#define UNIX_CONST const
#endif
