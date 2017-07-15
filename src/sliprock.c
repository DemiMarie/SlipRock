#ifdef _WIN32
#define SLIPROCK_INTERNALS
#define _UNICODE
#define UNICODE
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
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
#include "sliprock_internals.h"
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
#ifndef _WIN32
  if (-1 != connection->fd)
    close(connection->fd);
#else
  if (INVALID_HANDLE_VALUE != connection->hPipe)
    CloseHandle(connection->hPipe);
#endif
  delete_socket(connection);
  free(connection);
}

static int sliprock_new(const char *const name, const size_t namelen,
                        struct SliprockConnection **connection_) {
  struct SliprockConnection *connection;
  *connection_ = NULL;
  if (namelen > 200) {
    return SLIPROCK_ERANGE;
  }

  connection = *connection_ =
      calloc(1, namelen + sizeof(struct SliprockConnection));

  if (NULL == connection)
    return SLIPROCK_ENOMEM;
#ifndef _WIN32
  connection->address.sun_family = AF_UNIX;
#endif
  // We have (by construction) enough space for the name
  memcpy(&connection->name, name, namelen);
  connection->namelen = namelen;

  return 0;
}

static int sliprock_check_charset(const char *name, size_t namelen) {
  // TODO allow unicode
  size_t i;
  for (i = 0; i < namelen; ++i) {
    if (!isalnum(name[i]) && name[i] != '-' && name[i] != '.' &&
        name[i] != '_') {
      return SLIPROCK_EILSEQ;
    }
  }
  return 0;
}

/**
 * Obtains the filename corresponding to the local file to be created.
 *
 * \param srcname points to the identifier of the newly created connection.
 * It need not be NUL-terminated, but must point to at least \p size worth
 * of valid data.
 * \param size The number of bytes pointed to by srcname.
 * \param pid is the process ID of the process that created the connection.
 * \param innerlen ????
 * \param [in] extraspace The amount of extra space to include.
 * \param [out] fname_buf A StringBuf to store the result in.extraspace
 * \return 0 on success, a (negative) SlipRock error code on failure.
 */
static int sliprock_get_fname(const char *const srcname, const size_t size,
                              uint32_t pid, int *innerlen,
                              uint16_t extraspace,
                              struct StringBuf *fname_buf) {
  void *freeptr = NULL;
  int errcode = SLIPROCK_EINTERNALERROR;
  size_t innerlen_, newsize, homelen;
  const MyChar *homedir;
  UNIX_CONST MyChar *decoded_srcname;
  assert(sliprock_check_charset(srcname, size) == 0 &&
         "Bogus characters in connection name should have been detected "
         "earlier!");
  assert(size <= INT_MAX &&
         "Attempt to create connection with identifier length > INT_MAX!");

  decoded_srcname = CopyIdent(srcname, size);
  if (NULL == decoded_srcname) {
    errcode = SLIPROCK_ENOMEM;
    goto fail;
  }

  errcode = sliprock_get_home_directory(&freeptr, &homedir);
  assert((NULL != homedir) ^ (errcode != 0));
  if (NULL == homedir || errcode) {
    goto fail;
  }
  homelen = MyStrlen(homedir);
  if (homelen > UINT16_MAX) {
    errcode = SLIPROCK_ERANGE;
    goto fail;
  }

  newsize = size + sizeof "/.sliprock/..sock" + 20 /* pid */ + homelen +
            extraspace;
  if ((uint16_t)newsize > (uint16_t)UINT16_MAX - extraspace) {
    errcode = SLIPROCK_ERANGE;
    goto fail;
  }

  if (StringBuf_alloc(newsize + extraspace, fname_buf) < 0) {
    errcode = SLIPROCK_ENOMEM;
    goto fail;
  }

  innerlen_ = homelen + sizeof "/.sliprock" - 1;
  assert(innerlen_ < INT_MAX / 2 &&
         "inner length is greater than outer length!");

  /* Yes, we could use snprintf here */
  StringBuf_add_string(fname_buf, homedir, homelen);
  StringBuf_add_literal(fname_buf, "/.sliprock/");
  StringBuf_add_decimal(fname_buf, pid);
  StringBuf_add_char(fname_buf, ',');
  StringBuf_add_string(fname_buf, decoded_srcname, size);
  StringBuf_add_literal(fname_buf, ".sock");
  errno = 0;
  if (innerlen)
    *innerlen = (int)innerlen_;
  errcode = 0;
  goto success;
fail:
  if (innerlen)
    *innerlen = 0;
  free(fname_buf->buf);
  memset(fname_buf, 0, sizeof *fname_buf);
success:
  free(freeptr);
  FreeIdent(decoded_srcname);
  return errcode;
}

static int sliprock_bind(struct SliprockConnection *con) {
  int e = 0, created_file = 0, res = 0;
  OsHandle fd = (OsHandle)-1;
  /* Checked in sliprock_socket() */
  assert(sliprock_check_charset(con->name, con->namelen) == 0 &&
         "Bogus characters in connection name should have been detected "
         "earlier!");
  if ((e = sliprock_get_fname(con->name, con->namelen, (uint32_t)getpid(),
                              &res, 17, &con->path)) < 0) {
    return e;
  }
  if (sliprock_randombytes_sysrandom_buf(con->passwd, sizeof con->passwd) <
      0) {
    return SLIPROCK_ENORND;
  }
  fd = create_directory_and_file(&con->path);
  if ((OsHandle)INVALID_HANDLE_VALUE == fd)
    goto fail;
  created_file = 1;
  SLIPROCK_STATIC_ASSERT(sizeof SLIPROCK_MAGIC - 1 == 16);
  if (write_connection(fd, con) < 0)
    goto fail;
  /* Write failed */
  if (sliprock_fsync(fd) < 0)
    goto fail;
  if (hclose(fd) < 0) {
    /* Don't double-close – the state of the FD is unspecified.  Better
     * to
     * leak an FD than close an FD that other code could be using. */
    fd = (OsHandle)INVALID_HANDLE_VALUE;
    goto fail;
  }
  return errno = 0;
fail:
  e = errno;
  if (fd != (OsHandle)INVALID_HANDLE_VALUE) {
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

int sliprock_socket(const char *const name, size_t const namelen,
                    struct SliprockConnection **connection_) {
  struct SliprockConnection *connection;
  int err;
  *connection_ = NULL;
  assert(name != NULL);
  if (namelen > 1 << 15)
    return SLIPROCK_ERANGE;
  /* This check ensures that connection names are human-readable */
  /* TODO: allow unicode */
  if ((err = sliprock_check_charset(name, namelen))) {
    assert(err == SLIPROCK_EILSEQ);
    return err;
  }
  /* Allocate the connection */
  if ((err = sliprock_new(name, namelen, connection_))) {
    assert(err == SLIPROCK_ENOMEM);
    return err;
  }
  connection = *connection_;
  assert(connection != NULL);
  /* Must do this first - otherwise connection->sock is filled with zeros
   * when write_connection() is called, and we get a confusing error
   * ("connection refused") from sliprock_open() */
  if ((err = sliprock_bind_os(connection)) == 0) {
    if ((err = sliprock_bind(connection)) == 0) {
      /* Don't leave a directory and socket lying around in /tmp */
      return 0;
    }
    delete_socket(connection);
  }
  free(connection);
  return err;
}

// See documentation in sliprock.h
SLIPROCK_API void
sliprock_close_receiver(struct SliprockReceiver *receiver) {
  free(receiver);
}

// See documentation in sliprock.h
SLIPROCK_API int sliprock_open(const char *const identifier, size_t size,
                               uint32_t pid,
                               struct SliprockReceiver **receiver) {
  int err = SLIPROCK_EINTERNALERROR;
  OsHandle fd;
  struct StringBuf fname;
  assert(receiver);
  *receiver = NULL;
  memset(&fname, 0, sizeof fname);
  char magic[sizeof(SLIPROCK_MAGIC) - 1];
  if ((err = sliprock_check_charset(identifier, size)))
    return err;
#ifndef _WIN32
  assert(pid <= INT_MAX &&
         "PID must be within range of valid process IDs!");
#endif
  if ((err = sliprock_get_fname(identifier, size, pid, NULL, 0, &fname)))
    return err;
  fd = openfile(fname.buf, O_RDONLY);
  if ((OsHandle)INVALID_HANDLE_VALUE == fd) {
#ifdef _WIN32
    int is_enoent = GetLastError() == ERROR_FILE_NOT_FOUND;
#else
    int is_enoent = errno == ENOENT;
#endif
    err = is_enoent ? SLIPROCK_ENOCONN : SLIPROCK_EOSERR;
    goto fail;
  }
  *receiver = calloc(1, sizeof(struct SliprockReceiver));
  if (NULL == *receiver) {
    err = SLIPROCK_ENOMEM;
    goto fail;
  }
  MADE_IT;
  int res = (int)sliprock_read_receiver(fd, *receiver, magic);
  if (res !=
      (sizeof SLIPROCK_MAGIC - 1) + 32 + sizeof(TCHAR) * MAX_SOCK_LEN) {
    if (res >= 0) {
      MADE_IT;
      err = SLIPROCK_EPROTO;
    } else {
      MADE_IT;
      err = SLIPROCK_EOSERR;
    }
  } else if (!err &&
             memcmp(magic, SLIPROCK_MAGIC, sizeof SLIPROCK_MAGIC - 1))
    err = SLIPROCK_EPROTO;
fail:
  if ((OsHandle)INVALID_HANDLE_VALUE != fd)
    hclose(fd);
  free(fname.buf);
  if (err) {
    sliprock_close_receiver(*receiver);
    *receiver = NULL;
  }
  return err;
}

SLIPROCK_API uint64_t sliprock_UNSAFEgetRawHandle(
    struct SliprockConnection *con, int should_release) {
#ifndef _WIN32
  uint64_t handle = (uint64_t)con->fd;
  if (should_release)
    con->fd = (OsHandle)INVALID_HANDLE_VALUE;
  return handle;
#else
  HANDLE h;
  (void)should_release;
  if (DuplicateHandle(GetCurrentProcess(), con->hPipe, GetCurrentProcess(),
                      &h, 0, FALSE, DUPLICATE_SAME_ACCESS))
    return (uint64_t)h;
  else
    return (uint64_t)INVALID_HANDLE_VALUE;
#endif
}

SLIPROCK_API const unsigned char *
sliprock_UNSAFEgetPasscode(const struct SliprockConnection *connection) {
  return connection->passwd;
}
