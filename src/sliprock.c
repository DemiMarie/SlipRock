#ifdef _WIN32
#define SLIPROCK_INTERNALS
#define _UNICODE
#define UNICODE
#endif
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wreserved-id-macro"
#endif
#define _GNU_SOURCE
#ifdef __clang__
#pragma clang diagnostic pop
#endif
#include <stdint.h>

#include "sliprock.h"
#include "sliprock_internals.h"
#include "stringbuf.h"
#include <ctype.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#ifndef _WIN32
#include <errno.h>
#endif
#include <limits.h>
#include <stddef.h>
#include <stdint.h>

SLIPROCK_API void sliprock_close(struct SliprockConnection *connection) {
  if (NULL == connection) {
    return;
  }
  // not true in the presence of sliprock_UNSAFEgetRawHandle
  // assert(connection->fd.fd >= 0);
  if (NULL != connection->path) {
    sliprock_unlink(connection->path->buf);
    free((void *)connection->path);
  }
  if (connection->fd != INVALID_HANDLE_VALUE)
    hclose(connection->fd);
#ifndef _WIN32
  if (connection->has_socket) {
    sliprock_unlink(CON_PATH(connection));
    rmdir(dirname(CON_PATH(connection)));
  } else {
    rmdir(CON_PATH(connection));
  }
#endif
  free(connection);
}

static struct SliprockConnection *sliprock_new(const char *const name,
                                               const size_t namelen) {
  if (namelen > 200) {
    errno = ERANGE;
    return NULL;
  }

  struct SliprockConnection *connection =
      calloc(1, namelen + sizeof(struct SliprockConnection));

  if (NULL == connection)
    return NULL;
#ifndef _WIN32
  connection->address.sun_family = AF_UNIX;
#endif
  // We have (by construction) enough space for the name
  memcpy(&connection->name, name, namelen);
  connection->namelen = namelen;

  return connection;
}

static int sliprock_check_charset(const char *name, size_t namelen) {
  // TODO allow unicode
  for (size_t i = 0; i < namelen; ++i) {
    if (!isalnum(name[i]) && name[i] != '-' && name[i] != '.' &&
        name[i] != '_') {
      errno = EILSEQ;
      return -1;
    }
  }
  return 0;
}

#define RETURN_ERRNO(e)                                                   \
  do                                                                      \
    return -(errno = e);                                                  \
  while (1)

/**
 * Obtains the filename corresponding to the local file to be created.
 *
 * \param srcname points to the identifier of the newly created connection.
 * It need not be NUL-terminated, but must point to at least \p len worth
 * of
 * valid data.
 *
 * \param pid is the process ID of the process that created the connection.
 */
static struct StringBuf *get_fname(const char *const srcname,
                                   const size_t size, int pid,
                                   int *innerlen, int *outerlen) {
  void *freeptr = NULL;
  struct StringBuf *fname_buf = NULL;

  assert(sliprock_check_charset(srcname, size) == 0 &&
         "Bogus characters in connection name should have been detected "
         "earlier!");
  assert(size <= INT_MAX &&
         "Attempt to create connection with identifier length > INT_MAX!");

  UNIX_CONST MyChar *const decoded_srcname = CopyIdent(srcname, size);
  if (NULL == decoded_srcname)
    goto fail;

  const MyChar *const homedir = sliprock_get_home_directory(&freeptr);
  if (NULL == homedir)
    goto fail;

  const size_t homelen = MyStrlen(homedir);
  if (homelen > INT_MAX / 2) {
    errno = ERANGE;
    goto fail;
  }

  const size_t newsize = size + sizeof "/.sliprock/..sock" + 20 + homelen;
  if (newsize > INT_MAX) {
    errno = ERANGE;
    goto fail;
  }

  fname_buf = StringBuf_alloc(newsize);
  if (NULL == fname_buf)
    goto fail;

  size_t innerlen_ = homelen + sizeof "/.sliprock" - 1;
  assert(innerlen_ < INT_MAX / 2 &&
         "inner length is greater than outer length!");
  StringBuf_add_string(fname_buf, homedir, homelen);
  StringBuf_add_literal(fname_buf, "/.sliprock/");
  StringBuf_add_decimal(fname_buf, pid);
  StringBuf_add_char(fname_buf, ',');
  StringBuf_add_string(fname_buf, decoded_srcname, size);
  StringBuf_add_literal(fname_buf, ".sock");
  errno = 0;
  if (outerlen)
    *outerlen = fname_buf->buf_length;
  if (innerlen)
    *innerlen = (int)innerlen_;
  goto success;
fail:
  if (innerlen)
    *innerlen = 0;
  if (outerlen)
    *outerlen = 0;
  free(fname_buf);
  fname_buf = NULL;
success:
  free(freeptr);
  FreeIdent(decoded_srcname);
  return fname_buf;
}

static int sliprock_bind(struct SliprockConnection *con) {
  int e;
  OsHandle fd = (OsHandle)-1;
  struct StringBuf *fname_buf;
  int newlength, res;
  assert(sliprock_check_charset(con->name, con->namelen) == 0 &&
         "Bogus characters in connection name should have been detected "
         "earlier!");
  fname_buf =
      get_fname(con->name, con->namelen, getpid(), &res, &newlength);
  if (NULL == fname_buf)
    goto fail;
  con->path = fname_buf;
  if (fill_randombuf(con->passwd, sizeof con->passwd) < 0)
#ifndef _WIN32
    abort();
#else
    goto fail;
#endif
  fd = create_directory_and_file(fname_buf);
  if (INVALID_HANDLE_VALUE == fd)
    goto fail;
  (void)SLIPROCK_STATIC_ASSERT(sizeof SLIPROCK_MAGIC - 1 == 16);
  if (write_connection(fd, con) < 0)
    goto fail; // Write failed
  if (sliprock_fsync(fd) < 0)
    goto fail;
  if (hclose(fd) < 0) {
    // Don't double-close – the state of the FD is unspecified.  Better to
    // leak an FD than close an FD that other code could be using.
    fd = INVALID_HANDLE_VALUE;
    goto fail;
  }
  con->path = fname_buf;
  return errno = 0;
fail:
  e = errno;
  if (fd != INVALID_HANDLE_VALUE) {
    assert(NULL != fname_buf);
    hclose(fd);
    remove_file(fname_buf->buf);
  }
  free(fname_buf);
  con->path = NULL;
  return errno = e;
}

struct SliprockConnection *sliprock_socket(const char *const name,
                                           size_t const namelen) {
  if (init_func() < 0)
    return NULL;
  assert(name != NULL);
  if (name == NULL) {
    errno = EFAULT;
    return NULL;
  }
  if (namelen > 1 << 15) {
    errno = ERANGE;
    return NULL;
  }
  if (sliprock_check_charset(name, namelen) < 0)
    return NULL;
  // Allocate the connection
  struct SliprockConnection *connection = sliprock_new(name, namelen);
  if (NULL == connection)
    return NULL;

  if (make_sockdir(connection) < 0)
    goto no_directory;
  if ((errno = sliprock_bind(connection))) {
    goto no_binding;
  }
  // Establish the socket
  connection->fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
  if (INVALID_HANDLE_VALUE == connection->fd)
    goto bind_failed;

// Set close-on-exec if it could not have been done atomically.
#ifdef SLIPROCK_NO_SOCK_CLOEXEC
  set_cloexec(fd);
#endif
  /* Bind the socket */
  if (bind(connection->fd, &connection->address,
           sizeof(struct sockaddr_un)) < 0)
    goto bind_failed;
  if (listen(connection->fd, INT_MAX) == 0)
    return connection;
bind_failed:
  hclose(connection->fd);
  if (NULL != connection->path) {
    sliprock_unlink(connection->path->buf);
    free(connection->path);
  }
no_binding:
  delete_socket(CON_PATH(connection));
no_directory:
  free(connection);
  return NULL;
}

SLIPROCK_API void
sliprock_close_receiver(struct SliprockReceiver *receiver) {
  free(receiver);
}

SLIPROCK_API struct SliprockReceiver *
sliprock_open(const char *const identifier, size_t size, uint32_t pid) {
  int err;
  OsHandle fd;
  struct SliprockReceiver *receiver = NULL;
  struct StringBuf *fname;
  char magic[sizeof(SLIPROCK_MAGIC) - 1];
  if (sliprock_check_charset(identifier, size) != 0)
    return NULL;
  errno = 0;
#ifndef _WIN32
  assert(pid <= INT_MAX &&
         "PID must be within range of valid process IDs!");
#endif
  fname = get_fname(identifier, size, (int)pid, NULL, NULL);
  if (!fname)
    return NULL;
  errno = 0;
  fd = openfile(fname->buf, O_RDONLY);
  if (INVALID_HANDLE_VALUE == fd)
    goto fail;
  receiver = calloc(1, sizeof(struct SliprockReceiver));
  if (NULL == receiver)
    goto fail;
  {
    ssize_t res = read_receiver(fd, receiver, magic);
    if (res < (ssize_t)(sizeof magic + sizeof receiver->passcode +
                        sizeof receiver->sock))
      goto fail;
  }
  if (memcmp(magic, SLIPROCK_MAGIC, sizeof SLIPROCK_MAGIC - 1))
    goto fail;
  if (receiver->sock.sun_family != AF_UNIX)
    goto fail;
  hclose(fd);
  free(fname);
  return receiver;
fail:
  err = errno;
  if (INVALID_HANDLE_VALUE != fd)
    hclose(fd);
  free(fname);
  sliprock_close_receiver(receiver);
  errno = err;
  return NULL;
}

SLIPROCK_API SliprockHandle
sliprock_accept(struct SliprockConnection *connection) {
  assert(INVALID_HANDLE_VALUE != connection->fd);
#ifndef _WIN32
  struct sockaddr_un _dummy;
#endif
  socklen_t _dummy2 = sizeof(struct sockaddr_un);
#ifdef __linux__
  OsHandle fd = accept4(connection->fd, &_dummy, &_dummy2, SOCK_CLOEXEC);
  if (INVALID_HANDLE_VALUE == fd)
    return fd;
#else
  OsHandle fd = accept(connection->fd, &_dummy, &_dummy2);
  if (INVALID_HANDLE_VALUE == fd)
    return fd;
  set_cloexec(fd);
#endif
  if (write(fd, connection->passwd, sizeof connection->passwd) < 32) {
    hclose(fd);
    return INVALID_HANDLE_VALUE;
  }
  return (SliprockHandle)fd;
}

SLIPROCK_API uint64_t sliprock_UNSAFEgetRawHandle(
    struct SliprockConnection *con, int should_release) {
  uint64_t handle = (uint64_t)con->fd;
  if (should_release)
    con->fd = INVALID_HANDLE_VALUE;
  return handle;
}

SLIPROCK_API const char *
sliprock_UNSAFEgetPasscode(const struct SliprockConnection *connection) {
  return connection->passwd;
}
