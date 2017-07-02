#ifndef SLIPROCK_UNIX_H_INCLUDED
#define SLIPROCK_UNIX_H_INCLUDED
#ifdef __linux__
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif
#define _GNU_SOURCE
#ifdef __clang__
#pragma clang diagnostic pop
#endif
#endif
#include <errno.h>
#include <fcntl.h>

#include <assert.h>
#include <fcntl.h>
#include <libgen.h>
#include <pthread.h>
#include <pwd.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/un.h>
#include <unistd.h>

#include <include/sliprock.h>
#include <src/sliprock_internals.h>
#include <src/stringbuf.h>
#define hclose close

#define sliprock_unlink unlink
#define INVALID_HANDLE_VALUE -1

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

static const char *sliprock_get_home_directory(void **freeptr);

static int make_sockdir(struct SliprockConnection *connection);

SLIPROCK_API SliprockHandle
sliprock_connect(const struct SliprockReceiver *receiver);
SLIPROCK_API SliprockHandle
sliprock_accept(struct SliprockConnection *connection);
#define CON_PATH(con) ((con)->address.sun_path)

int sliprock_bind_os(struct SliprockConnection *connection);

SLIPROCK_API SliprockHandle
sliprock_accept(struct SliprockConnection *connection) {
  struct sockaddr_un _dummy;
  socklen_t _dummy2 = sizeof(struct sockaddr_un);
  assert(INVALID_HANDLE_VALUE != connection->fd);
#ifdef __linux__
  OsHandle fd = accept4(connection->fd, &_dummy, &_dummy2, SOCK_CLOEXEC);
  if (fd < 0)
    return (SliprockHandle)fd;
#else
  OsHandle fd = accept(connection->fd, &_dummy, &_dummy2);
  if (fd < 0)
    return fd;
  set_cloexec(fd);
#endif
  const unsigned char *pw_pos = connection->passwd,
                      *const limit = connection->passwd + 32;
  while (1) {
    const ssize_t delta = limit - pw_pos;
    assert(delta >= 0);
    const ssize_t num_written = write(fd, pw_pos, (size_t)delta);
    if (num_written <= 0) {
      hclose(fd);
      return (SliprockHandle)INVALID_HANDLE_VALUE;
    }
    assert(num_written <= delta);
    if (num_written >= delta)
      return (SliprockHandle)fd;
    pw_pos += num_written;
  }
}

int sliprock_bind_os(struct SliprockConnection *connection) {
  if (make_sockdir(connection) < 0)
    return -1;

  /* Establish the socket */
  connection->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (connection->fd >= 0) {

/* Set close-on-exec if it could not have been done atomically. */
#ifdef SLIPROCK_NO_SOCK_CLOEXEC
    set_cloexec(connection->fd);
#endif

    /* Bind the socket */
    if (bind(connection->fd, &connection->address,
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

/* Get the user's home directory.  A void* will be placed in freeptr
 * that must be passed to free(3) when needed.  Doing so invalidates
 * the returned pointer.
 *
 * On error, returns NULL and set errno. */
static const char *sliprock_get_home_directory(void **freeptr) {
  int e;
  char *buf = NULL;
  size_t size = 28;
  struct passwd pw, *pw_ptr;
  memset(&pw, 0, sizeof(pw));
  *freeptr = NULL;
  do {
    char *old_buf = buf;
    assert(size < (SIZE_MAX >> 1));
    if ((buf = realloc(buf, (size <<= 1))) == NULL) {
      // Yes, we need to handle running out of memory.
      free(old_buf);
      return NULL;
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
    return NULL;
  }
  *freeptr = buf;
  return pw_ptr->pw_dir;
}

/* Create a directory with suitable permissions */
static int makedir(MyChar *ptr) { return mkdir(ptr, 0700); }

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
#ifdef HAVE_RENAMEAT
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
#ifdef HAVE_OPENAT
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
#ifdef HAVE_RENAMEAT
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
      /* darn... */
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
  struct iovec vec[] = {
      {SLIPROCK_MAGIC, sizeof SLIPROCK_MAGIC - 1},
      {con->passwd, sizeof con->passwd},
      {&con->address.sun_path, MAX_SOCK_LEN},
  };
  int q =
      writev(fd, vec, 3) ==
              MAX_SOCK_LEN + sizeof con->passwd + sizeof SLIPROCK_MAGIC - 1
          ? 0
          : -1;
  return q;
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
static ssize_t
read_receiver(OsHandle fd, struct SliprockReceiver *receiver,
              char magic[static sizeof SLIPROCK_MAGIC - 1]) {
  memset(&receiver->sock, 0, sizeof receiver->sock);
  receiver->sock.sun_family = AF_UNIX;
  struct iovec vecs[] = {
      {magic, sizeof SLIPROCK_MAGIC - 1},
      {receiver->passcode, sizeof receiver->passcode},
      {&receiver->sock.sun_path, MAX_SOCK_LEN},
  };
  return readv(fd, vecs, 3);
}

#ifndef __linux__
static void set_cloexec(OsHandle fd) { fcntl(fd, F_SETFD, FD_CLOEXEC); }
#endif

static int sliprock_fsync(int fd) { return fsync(fd); }

/* Make a directory to hold a socket, and fill connection with the path */
static int make_sockdir(struct SliprockConnection *connection) {
  /* Temporary buffer used for random numbers */
  uint64_t tmp[2];
  (void)SLIPROCK_STATIC_ASSERT(sizeof CON_PATH(connection) > MAX_SOCK_LEN);
  (void)SLIPROCK_STATIC_ASSERT(MAX_SOCK_LEN == 69);

retry:
  CHECK_FUEL(return -1);
  if (sliprock_randombytes_sysrandom_buf(tmp, sizeof tmp) < 0)
    return -1;
  CHECK_FUEL(return -1);
  struct StringBuf buf;
  StringBuf_init(&buf, MAX_SOCK_LEN, 0, CON_PATH(connection));
  StringBuf_add_literal(&buf, "/tmp/sliprock.");
  StringBuf_add_decimal(&buf, (uintptr_t)getpid());
  StringBuf_add_char(&buf, '.');
  StringBuf_add_hex(&buf, *tmp);
  CHECK_FUEL(return -1);
  if (makedir(CON_PATH(connection)) < 0) {
    if (errno == EEXIST)
      goto retry;
    return -1;
  }
  connection->has_socket = 1;
  StringBuf_add_char(&buf, '/');
  StringBuf_add_hex(&buf, tmp[1]);
  return 0;
}

#define MyStrlen strlen

/* See documentation in sliprock.h */
SliprockHandle sliprock_connect(const struct SliprockReceiver *receiver) {
  int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  unsigned char pw_received[32];
  if (sock < 0)
    return (SliprockHandle)SLIPROCK_EOSERR;
#ifdef SLIPROCK_NO_SOCK_CLOEXEC
  set_cloexec(sock);
#endif
  if (connect(sock, &receiver->sock, sizeof(struct sockaddr_un)) < 0) {
    hclose(sock);
    return (SliprockHandle)SLIPROCK_EOSERR;
  }
  size_t remaining = sizeof pw_received;
  unsigned char *read_ptr = pw_received;
  while (remaining > 0) {
    ssize_t num_read = read(sock, read_ptr, remaining);
    if (num_read <= 0)
      break;
    if (remaining >= (size_t)num_read) {
      if (0 == sliprock_secure_compare_memory(pw_received,
                                              receiver->passcode, 32))
        return (SliprockHandle)sock;
      else
        break;
    } else {
      remaining -= (size_t)num_read;
      read_ptr += num_read;
    }
  }
  hclose(sock);
  return (SliprockHandle)SLIPROCK_EBADPASS;
}
#define UNIX_CONST const
#endif
