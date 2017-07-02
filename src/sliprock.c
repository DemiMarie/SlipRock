#ifdef _WIN32
#define SLIPROCK_INTERNALS
#define _UNICODE
#define UNICODE
#endif
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
#include <stdint.h>

#include "config.h"
#include "include/sliprock.h"
#include "src/stringbuf.h"
#ifdef _WIN32
#include "src/sliprock_windows.h"
#else
#include "src/sliprock_unix.h"
#endif
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
  if (NULL != connection->path.buf) {
    sliprock_unlink(connection->path.buf);
    free((void *)connection->path.buf);
  }
  if (connection->fd != INVALID_HANDLE_VALUE)
    hclose(connection->fd);
  delete_socket(connection);
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
  size_t i;
  for (i = 0; i < namelen; ++i) {
    if (!isalnum(name[i]) && name[i] != '-' && name[i] != '.' &&
        name[i] != '_') {
      errno = EILSEQ;
      return -1;
    }
  }
  return 0;
}

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
static int get_fname(const char *const srcname, const size_t size,
                     uint32_t pid, int *innerlen, uint16_t extraspace,
                     struct StringBuf *fname_buf) {
  void *freeptr = NULL;
  size_t innerlen_, newsize, homelen;
  int status = -1;
  const MyChar *homedir;
  UNIX_CONST MyChar *decoded_srcname;
  assert(sliprock_check_charset(srcname, size) == 0 &&
         "Bogus characters in connection name should have been detected "
         "earlier!");
  assert(size <= INT_MAX &&
         "Attempt to create connection with identifier length > INT_MAX!");

  decoded_srcname = CopyIdent(srcname, size);
  if (NULL == decoded_srcname)
    goto fail;

  homedir = sliprock_get_home_directory(&freeptr);
  if (NULL == homedir)
    goto fail;

  homelen = MyStrlen(homedir);
  if (homelen > UINT16_MAX) {
    errno = ERANGE;
    goto fail;
  }

  newsize = size + sizeof "/.sliprock/..sock" + 20 /* pid */ + homelen +
            extraspace;
  if (extraspace > UINT16_MAX || newsize > UINT16_MAX - extraspace) {
    errno = ERANGE;
    goto fail;
  }

  if (StringBuf_alloc(newsize + extraspace, fname_buf) < 0)
    goto fail;

  innerlen_ = homelen + sizeof "/.sliprock" - 1;
  assert(innerlen_ < INT_MAX / 2 &&
         "inner length is greater than outer length!");
  StringBuf_add_string(fname_buf, homedir, homelen);
  StringBuf_add_literal(fname_buf, "/.sliprock/");
  StringBuf_add_decimal(fname_buf, pid);
  StringBuf_add_char(fname_buf, ',');
  StringBuf_add_string(fname_buf, decoded_srcname, size);
  StringBuf_add_literal(fname_buf, ".sock");
  errno = 0;
  if (innerlen)
    *innerlen = (int)innerlen_;
  status = 0;
  goto success;
fail:
  if (innerlen)
    *innerlen = 0;
  free(fname_buf->buf);
  memset(fname_buf, 0, sizeof *fname_buf);
success:
  free(freeptr);
  FreeIdent(decoded_srcname);
  return status;
}

static int sliprock_bind(struct SliprockConnection *con) {
  int e = 0, created_file = 0, res = 0;
  OsHandle fd = (OsHandle)-1;
  /* Checked in sliprock_socket() */
  assert(sliprock_check_charset(con->name, con->namelen) == 0 &&
         "Bogus characters in connection name should have been detected "
         "earlier!");
  if (get_fname(con->name, con->namelen, (uint32_t)getpid(), &res, 17,
                &con->path) < 0) {
    return -1;
  }
  if (sliprock_randombytes_sysrandom_buf(con->passwd, sizeof con->passwd) <
      0) {
    return -1;
  }
  fd = create_directory_and_file(&con->path);
  if (INVALID_HANDLE_VALUE == fd)
    goto fail;
  created_file = 1;
  (void)SLIPROCK_STATIC_ASSERT(sizeof SLIPROCK_MAGIC - 1 == 16);
  if (write_connection(fd, con) < 0)
    goto fail;
  /* Write failed */
  if (sliprock_fsync(fd) < 0)
    goto fail;
  if (hclose(fd) < 0) {
    /* Don't double-close – the state of the FD is unspecified.  Better
     * to
     * leak an FD than close an FD that other code could be using. */
    fd = INVALID_HANDLE_VALUE;
    goto fail;
  }
  return errno = 0;
fail:
  e = errno;
  if (fd != INVALID_HANDLE_VALUE) {
    hclose(fd);
  }
  if (created_file) {
    assert(NULL != con->path.buf);
    sliprock_unlink(con->path.buf);
  }
  free(con->path.buf);
  con->path.buf = NULL;
  return -(errno = e);
}

struct SliprockConnection *sliprock_socket(const char *const name,
                                           size_t const namelen) {
  struct SliprockConnection *connection;
  assert(name != NULL);
  if (name == NULL) {
    errno = EFAULT;
    return NULL;
  }
  if (namelen > 1 << 15) {
    errno = ERANGE;
    return NULL;
  }
  /* This check ensures that connection names are human-readable */
  /* TODO: allow unicode */
  if (sliprock_check_charset(name, namelen) < 0)
    return NULL;
  /* Allocate the connection */
  connection = sliprock_new(name, namelen);
  if (NULL == connection)
    return NULL;
  /* Must do this first - otherwise connection->sock is filled with zeros
   * when write_connection() is called, and we get a confusing error
   * ("connection refused") from sliprock_open() */
  if (sliprock_bind_os(connection) == 0) {
    if ((errno = sliprock_bind(connection)) == 0) {
      /* Don't leave a directory and socket lying around in /tmp */
      return connection;
    }
    delete_socket(connection);
  }
  free(connection);
  return NULL;
}

// See documentation in sliprock.h
SLIPROCK_API void
sliprock_close_receiver(struct SliprockReceiver *receiver) {
  free(receiver);
}

// See documentation in sliprock.h
SLIPROCK_API struct SliprockReceiver *
sliprock_open(const char *const identifier, size_t size, uint32_t pid) {
  int err;
  OsHandle fd;
  struct SliprockReceiver *receiver = NULL;
  struct StringBuf fname;
  memset(&fname, 0, sizeof fname);
  char magic[sizeof(SLIPROCK_MAGIC) - 1];
  if (sliprock_check_charset(identifier, size) != 0)
    return NULL;
  errno = 0;
#ifndef _WIN32
  assert(pid <= INT_MAX &&
         "PID must be within range of valid process IDs!");
#endif
  if (get_fname(identifier, size, pid, NULL, 0, &fname))
    return NULL;
  errno = 0;
  fd = openfile(fname.buf, O_RDONLY);
  if (INVALID_HANDLE_VALUE == fd)
    goto fail;
  receiver = calloc(1, sizeof(struct SliprockReceiver));
  if (NULL == receiver)
    goto fail;
  {
    ssize_t res = read_receiver(fd, receiver, magic);
    if (res < (ssize_t)MAX_SOCK_LEN) {
      errno = EINVAL;
      goto fail;
    }
  }
  if (memcmp(magic, SLIPROCK_MAGIC, sizeof SLIPROCK_MAGIC - 1))
    goto fail;
  hclose(fd);
  free(fname.buf);
  return receiver;
fail:
  err = errno;
  if (INVALID_HANDLE_VALUE != fd)
    hclose(fd);
  free(fname.buf);
  sliprock_close_receiver(receiver);
  errno = err;
  return NULL;
}

SLIPROCK_API uint64_t sliprock_UNSAFEgetRawHandle(
    struct SliprockConnection *con, int should_release) {
  uint64_t handle = (uint64_t)con->fd;
  if (should_release)
    con->fd = INVALID_HANDLE_VALUE;
  return handle;
}

SLIPROCK_API const unsigned char *
sliprock_UNSAFEgetPasscode(const struct SliprockConnection *connection) {
  return connection->passwd;
}
