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

#define CON_PATH(con) ((con)->address.sun_path)

int sliprock_bind_os(struct SliprockConnection *connection);

SLIPROCK_API int sliprock_accept(struct SliprockConnection *connection,
                                 SliprockHandle *handle) {
  struct sockaddr_un _dummy;
  socklen_t _dummy2 = sizeof(struct sockaddr_un);
  OsHandle fd;
  assert(-1 != connection->fd);
#ifdef __linux__
  fd = accept4(connection->fd, &_dummy, &_dummy2, SOCK_CLOEXEC);
  *handle = (SliprockHandle)fd;
  if (fd < 0)
    return SLIPROCK_EOSERR;
#else
  fd = *handle = accept(connection->fd, &_dummy, &_dummy2);
  if (fd < 0)
    return SLIPROCK_EOSERR;
  sliprock_set_cloexec(fd);
#endif
  const unsigned char *pw_pos = connection->passwd,
                      *const limit = connection->passwd + 32;
  while (1) {
    const ssize_t delta = limit - pw_pos;
    ssize_t num_written;
    assert(delta >= 0);
    num_written = write(fd, pw_pos, (size_t)delta);
    if (num_written <= 0) {
      hclose(fd);
      *handle = INVALID_HANDLE_VALUE;
      return SLIPROCK_EPROTO;
    }
    assert(num_written <= delta);
    if (num_written >= delta)
      return 0;
    pw_pos += num_written;
  }
}

int sliprock_bind_os(struct SliprockConnection *connection) {
  if (sliprock_make_sockdir(connection) < 0)
    return -1;

  /* Establish the socket */
  connection->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (connection->fd >= 0) {

/* Set close-on-exec if it could not have been done atomically. */
#ifdef SLIPROCK_NO_SOCK_CLOEXEC
    sliprock_set_cloexec(connection->fd);
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
      // Yes, we need to handle running out of memory.
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
  if (makedir(buf->buf) && errno != EEXIST)
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
  int q = writev(fd, vec, 3) == MAX_SOCK_LEN + sizeof con->passwd +
                                    sizeof SLIPROCK_MAGIC - 1
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
static ssize_t sliprock_read_receiver(OsHandle fd,
                                      struct SliprockReceiver *receiver,
                                      char magic[STATIC_ARR MAGIC_SIZE]) {
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
static void sliprock_set_cloexec(OsHandle fd) {
  fcntl(fd, F_SETFD, FD_CLOEXEC);
}
#endif

static int sliprock_fsync(int fd) { return fsync(fd); }

/* Make a directory to hold a socket, and fill connection with the path */
static int sliprock_make_sockdir(struct SliprockConnection *connection) {
  /* Temporary buffer used for random numbers */
  uint64_t tmp[2];
  SLIPROCK_STATIC_ASSERT(sizeof CON_PATH(connection) > MAX_SOCK_LEN);
  SLIPROCK_STATIC_ASSERT(MAX_SOCK_LEN == 69);
  struct stat stat_buf;
  /* No need to check ‘/’ – if it has bad perms we are sunk. */
  if (stat("/tmp", &stat_buf) < 0)
    return -1;
  if (stat_buf.st_uid != 0 || (stat_buf.st_mode & 01000) == 0)
    return -1;
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
  if (makedir(buf.buf) < 0) {
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
int sliprock_connect(const struct SliprockReceiver *receiver,
                     SliprockHandle *handle) {
  int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  unsigned char pw_received[32];
  *handle = INVALID_HANDLE_VALUE;
  if (sock < 0)
    return SLIPROCK_EOSERR;
#ifdef SLIPROCK_NO_SOCK_CLOEXEC
  sliprock_set_cloexec(sock);
#endif
  if (connect(sock, &receiver->sock, sizeof(struct sockaddr_un)) < 0) {
    hclose(sock);
    return SLIPROCK_EOSERR;
  }
  size_t remaining = sizeof pw_received;
  unsigned char *read_ptr = pw_received;
  while (remaining > 0) {
    ssize_t num_read = read(sock, read_ptr, remaining);
    if (num_read <= 0)
      break;
    if (remaining >= (size_t)num_read) {
      if (0 == sliprock_secure_compare_memory(pw_received,
                                              receiver->passcode, 32)) {
        *handle = (SliprockHandle)sock;
        return 0;
      } else {
        hclose(sock);
        return SLIPROCK_ENOAUTH;
      }
    } else {
      remaining -= (size_t)num_read;
      read_ptr += num_read;
    }
  }
  hclose(sock);
  return SLIPROCK_EPROTO;
}
#define UNIX_CONST const
#endif
