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
#include <sys/uio.h>
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
  const unsigned char *pw_pos = connection->passwd;
  const unsigned char *const limit = connection->passwd + 32;
  socklen_t _dummy2 = sizeof(struct sockaddr_un);
  int fd;

  memset(&_dummy, 0, sizeof(_dummy));
  assert(-1 != connection->fd);
#if defined __linux__ || (defined __FreeBSD__ && __FreeBSD__ >= 10) ||    \
    (defined __NetBSD__ && __NetBSD__ >= 8)
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

#ifdef SLIPROCK_NO_SOCK_CLOEXEC
    /* Set close-on-exec if it could not have been done atomically. */
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
      MAX_SOCK_LEN + sizeof con->passwd + sizeof SLIPROCK_MAGIC - 1;
  struct iovec vec[] = {
      {SLIPROCK_MAGIC, sizeof SLIPROCK_MAGIC - 1},
      {con->passwd, sizeof con->passwd},
      {&con->address.sun_path, MAX_SOCK_LEN},
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
      {receiver->passcode, sizeof receiver->passcode},
      {&receiver->sock.sun_path, MAX_SOCK_LEN},
  };
  memset(&receiver->sock, 0, sizeof receiver->sock);
  receiver->sock.sun_family = AF_UNIX;
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
  int sock = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  unsigned char pw_received[32];
  size_t remaining = sizeof pw_received;
  unsigned char *read_ptr = pw_received;
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
  while (remaining > 0) {
    ssize_t num_read = read(sock, read_ptr, remaining);
    if (num_read <= 0)
      break;
    if (remaining >= (size_t)num_read) {
      /* Check the passcode */
      if (0 == sliprock_secure_compare_memory(pw_received,
                                              receiver->passcode, 32)) {
        *handle = (SliprockHandle)sock;
        return 0;
      } else {
        close(sock);
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
#if 0
typedef int (*SlipRockAsyncReadCont)(void *opaque, OsHandle hnd, void *buf,
                                     ssize_t size);
typedef int (*SlipRockAsyncReadCB)(void *user, void *opaque, OsHandle hnd,
                                   void *buf, ssize_t size,
                                   SlipRockAsyncReadCont cont);

typedef int (*SlipRockCopyCB)(void *user, size_t size);
struct SlipRockAsyncBuf {
  OsHandle in, out;
  void *user;
  SlipRockCopyCb cb;
  size_t start, end;
  bool is_reading;
  char buf[2048];
};

static int async_copy(void *user, OsHandle in, OsHandle out,
                      SlipRockCopyCB cb) {
  struct SlipRockAsyncBuf *ptr = calloc(1, sizeof(struct SlipRockAsyncBuf));
  if (NULL == ptr)
    return -ENOMEM;
  ptr->in = in, ptr->out = out, ptr->start = ptr->end = 0, ptr->user = user,
  ptr->cb = cb;
  ptr->is_reading = true;
  return async_read(user, ptr, in, &ptr->buf, sizeof ptr->buf, async_copy_cont);
}
static int async_copy_cont(void *opaque, OsHandle hnd, void *buf,
                           ssize_t size) {
  struct SlipRockAsyncBuf *data = (struct SlipRockAsyncBuf *)opaque;
  assert(&data->buf == buf);
  if (size <= 0) {
    SlipRockCopyCb cb = data->cb;
    void *user = data->user;
    ssize_t left_in_buf = data->end - data->start;
    assert(left_in_buf >= 0);
    free(data);
    return cb(user, size, left_in_buf);
  }
  assert(size < sizeof data->buf);
  if (buf->is_reading) {
    /* Assert we didn't have a buffer overflow */
    assert(sizeof(data->buf) - (size_t)size >= data->end);
    buf->end += (size_t)size;
    assert(buf->end <= sizeof(data->buf));
    if (sizeof(data->buf) <= buf->end) {
      /* Done reading - time to write */
    write:
      buf->is_reading = false;
      return async_write(buf->user, (void *)buf, buf->out, &buf->buf,
                         sizeof(data->buf), async_copy_cont);
    } else {
      /* Time to read! */
    read:
      buf->is_reading = true;
      return async_read(buf->user, (void *)buf, buf->in, &buf->buf,
                        sizeof(data->buf), async_copy_cont);
    }
  } else {
    /* Assert no buffer overflow */
    assert(buf->end - size >= buf->start);
    assert(sizeof(data->buf) == buf->end);

    /* Update start cursor */
    buf->start += (size_t)size;
    if (buf->start >= buf->end) {
      /* Time to switch to reads */
      buf->start = buf->end = 0;
      goto read;
    } else {
      goto write;
    }
  }
}
#endif
#define UNIX_CONST const
#endif
