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
    sliprock_unlink(connection->path);
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
#ifdef _WIN32
#define myprintf _wsnprintf
#else
#define myprintf snprintf
#endif
#define RETURN_ERRNO(e) do return -(errno = e); while (1)
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
static MyChar *get_fname(const MyChar *srcname, size_t len, int pid,
                         int *innerlen, int *outerlen) {
  void *freeptr;
  const MyChar *const homedir = sliprock_get_home_directory(&freeptr);
#ifndef _WIN32
  assert(sliprock_check_charset(srcname, len) == 0 &&
         "Bogus characters in connection name should have been detected "
         "earlier!");
#endif
  assert(len <= INT_MAX &&
         "Attempt to create connection with identifier length > INT_MAX!");
  if (NULL != homedir) {
    const size_t homelen =
#ifdef _WIN32
        wcslen(homedir);
#else
        strlen(homedir);
#endif
    const size_t newsize = len + sizeof "/.sliprock/..sock" + 20 + homelen;
    if (newsize > INT_MAX) {
      free(freeptr);
      errno = ERANGE;
      return NULL;
    }
    MyChar *fname_buf = malloc(newsize);
    if (NULL != fname_buf) {
      if (homelen > INT_MAX / 2) {
        errno = ERANGE;
      } else {
        size_t innerlen_ = homelen + sizeof "/.sliprock" - 1;
        int newlength;
        assert(innerlen_ < INT_MAX / 2 &&
               "inner length is greater than outer length!");
        newlength =
            myprintf(fname_buf, newsize, T("%s/.sliprock/%d.%.*s.sock"),
                     homedir, pid, (int)len, srcname);
        if (newlength >= 0) {
          errno = 0;
          if (outerlen)
            *outerlen = newlength;
          if (innerlen)
            *innerlen = (int)innerlen_;
          free(freeptr);
          return fname_buf;
        }
      }
      free(fname_buf);
    }
    free(freeptr);
  }
  if (innerlen)
    *innerlen = 0;
  if (outerlen)
    *outerlen = 0;
  return NULL;
}

static OsHandle sliprock_bind(struct SliprockConnection *con) {
  int e;
  OsHandle fd = (OsHandle)-1;
  MyChar *fname_buf;
  int newlength, res;
#ifndef _WIN32
   assert(
      sliprock_check_charset(con->name, con->namelen) == 0 &&
      "Bogus characters in connection name should have been detected earlier!");
#endif
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
    remove_file(fname_buf);
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
    sliprock_unlink(connection->path);
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
  MyChar *fname;
#ifndef _WIN32
  const
#endif
      MyChar *identifier_;
  char magic[sizeof(SLIPROCK_MAGIC) - 1];
  if (sliprock_check_charset(identifier, size) != 0)
    return NULL;
  errno = 0;
#ifndef _WIN32
  assert(pid <= INT_MAX &&
         "PID must be within range of valid process IDs!");
#endif
  identifier_ = CopyIdent(identifier);
  fname = get_fname(identifier_, size, (int)pid, NULL, NULL);
  if (!fname)
    return NULL;
  errno = 0;
  fd = openfile(fname, O_RDONLY);
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
  FreeIdent(identifier_);
  return receiver;
fail:;
  err = errno;
  if (fd >= 0)
    hclose(fd);
  free(fname);
  sliprock_close_receiver(receiver);
  errno = err;
  FreeIdent(identifier_);
  return NULL;
}

SLIPROCK_API SliprockHandle
sliprock_accept(struct SliprockConnection *connection) {
  assert(connection->fd >= 0);
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
