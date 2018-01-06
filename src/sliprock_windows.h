/* Tiny Windows implementation of a reasonable platform abstraction
 * layer. */

#ifndef SLIPROCK_WINDOWS_H_INCLUDED
#define SLIPROCK_WINDOWS_H_INCLUDED SLIPROCK_WINDOWS_H_INCLUDED
#ifdef _WIN32
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include <assert.h>
#include <processthreadsapi.h>
#include <sliprock/config.h>
#include <src/stringbuf.h>
#include <stdint.h>
#include <stdio.h>
#include <userenv.h>
#define sliprock_unlink DeleteFileW
#define rmdir RemoveDirectoryW

typedef wchar_t MyChar;
typedef HANDLE OsHandle;
#define getpid GetCurrentProcessId
#define O_RDWR 3
#define O_RDONLY 2
#define O_WRONLY 1

/* Tracing function, for debugging. */

#ifdef SLIPROCK_TRACE
static void sliprock_strerror(void) {
  wchar_t *buf;
  DWORD dummy;
  DWORD buflen = FormatMessageW(
      FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_IGNORE_INSERTS |
          FORMAT_MESSAGE_FROM_SYSTEM,
      NULL, GetLastError(), 0, (LPTSTR)&buf, 0, NULL);
  if (buflen) {
    if (!WriteConsoleW(GetStdHandle(-12), buf, buflen, &dummy, NULL)) {
      size_t size = (3 * buflen + 1) >> 1;
      char *bytebuf = malloc(size);
      if (!buf)
        goto done;
      WideCharToMultiByte(CP_UTF8, 0, buf, buflen, bytebuf, size, NULL,
                          NULL);
      fwrite(bytebuf, 1, size, stderr);
      fputs("\n", stderr);
      fflush(stderr);
      free(bytebuf);
    }
  }
done:
  LocalFree(buf);
}
#else
static void sliprock_strerror(void) {}
#endif

static OsHandle openfile(MyChar *path, int mode) {
  int osmode = 0;
  int creation_mode = OPEN_EXISTING;
  SECURITY_ATTRIBUTES sec = {0};
  sec.nLength = sizeof sec;
  assert(mode && mode < 4);
  if (mode & 2)
    osmode |= GENERIC_READ;
  if (mode & 1) {
    osmode |= GENERIC_WRITE;
    creation_mode = CREATE_ALWAYS;
  }
  HANDLE h = CreateFileW(path, osmode, 0, &sec, creation_mode,
                         FILE_ATTRIBUTE_NORMAL, NULL);
#ifdef SLIPROCK_TRACE
  if (h == INVALID_HANDLE_VALUE) {
    sliprock_strerror();
  }
#endif
  return h;
}

/* Taken from Wine */
#define GetCurrentProcessToken() ((HANDLE) ~(ULONG_PTR)3)
#define snprintf _wsnprintf
#define CON_PATH(con) ((con)->pipename)
#define SLIPROCK_MAGIC "\0SlipRock\n\rPIPE\x1a"
#define hclose(x) CloseHandle(x)
INIT_ONCE initialized = INIT_ONCE_STATIC_INIT;

int init_func(void) { return 0; }

static int sliprock_get_home_directory(void **const freeptr,
                                       const wchar_t **homedir) {
  HANDLE const hCurProc = GetCurrentProcessToken();
  wchar_t *buf = NULL;
  DWORD len = 0;
  *homedir = *freeptr = NULL;
  GetUserProfileDirectoryW(hCurProc, NULL, &len);
  if ((buf = (wchar_t *)malloc(sizeof(wchar_t) * len)) == NULL)
    return SLIPROCK_ENOMEM;
  if (!GetUserProfileDirectoryW(hCurProc, buf, &len)) {
#ifdef SLIPROCK_WIN_DBG
    sliprock_strerror();
#endif
    free(buf);
    return SLIPROCK_EOSERR;
  }
  *homedir = *freeptr = buf;
  return 0;
}

static OsHandle create_directory_and_file(struct StringBuf *path) {
  size_t i;
  for (i = path->buf_length; i > 0;) {
    --i;
    if (L'\\' == path->buf[i] || L'/' == path->buf[i]) {
      path->buf[i] = 0;
      SECURITY_ATTRIBUTES sec = {0};
      sec.nLength = sizeof sec;
      fwprintf_s(stderr, L"%s\n", path->buf);
      if (!CreateDirectoryW(path->buf, &sec) &&
          GetLastError() != ERROR_ALREADY_EXISTS) {
        path->buf[i] = L'\\';
        return INVALID_HANDLE_VALUE;
      }
      path->buf[i] = L'\\';
      return openfile(path->buf, O_WRONLY);
    }
  }
  abort(); /* impossible */
}

static int sliprock_fsync(OsHandle fd) {
  return FlushFileBuffers(fd) ? 0 : -1;
}

#define SOCK_CLOEXEC 0 /* not needed */

#define MyStrlen wcslen

#define T(x) (L##x)

static wchar_t *CopyIdent(const char *identifier, const size_t size) {
  int res = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, identifier,
                                size, NULL, 0);
  wchar_t *identifier_;
  if (0 == res)
    return NULL;
  identifier_ = calloc(res, sizeof(wchar_t));
  if (identifier_ == NULL)
    return NULL;
  if (0 == MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, identifier,
                               size, identifier_, (size_t)res)) {
    free(identifier_);
    return NULL;
  }
  return identifier_;
}
#define FreeIdent(x) (free(x))
#define UNIX_CONST /* nothing */

static void delete_socket(struct SliprockConnection *con) {
  CloseHandle(con->fd);
}
static int write_connection(OsHandle fd, struct SliprockConnection *con) {
  char buf[MAGIC_SIZE + sizeof con->passwd + sizeof con->pipename];
  char *buf2 = buf;
  memcpy(buf2, SLIPROCK_MAGIC, MAGIC_SIZE);
  buf2 += MAGIC_SIZE;
  memcpy(buf2, con->passwd, sizeof con->passwd);
  buf2 += sizeof con->passwd;
  memcpy(buf2, con->pipename, sizeof con->pipename);
  DWORD written;
  if (WriteFile(fd, buf, sizeof buf, &written, NULL) == 0)
    return -1;
  if (written != sizeof buf)
    return -1;
  if (!FlushFileBuffers(fd))
    return -1;
  return 0;
}
static HANDLE
sliprock_get_handle_for_connection(struct SliprockConnection *connection) {
  SECURITY_ATTRIBUTES sec_attributes = {0};
  HANDLE hPipe = connection->hPipe;
  DWORD err = connection->lastError;

  sec_attributes.nLength = sizeof sec_attributes;
  SetLastError(0);
  connection->hPipe = CreateNamedPipeW(
      connection->pipename,
      PIPE_ACCESS_DUPLEX |
          (NULL == hPipe ? FILE_FLAG_FIRST_PIPE_INSTANCE : 0),
      PIPE_TYPE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
      PIPE_UNLIMITED_INSTANCES,
      1U << 12, /* Small to preserve nonpaged pool */
      1U << 12, 0, &sec_attributes);
  connection->lastError = GetLastError();
  SetLastError(err);
  return hPipe;
}

/*
 * Bind a connection to a named pipe
 */
static int sliprock_bind_os(struct SliprockConnection *connection) {
  uint64_t random[1];
  int res;
retry:
  if (sliprock_randombytes_sysrandom_buf(random, sizeof random) < 0)
    return -1;
  assert(connection->pipename);
  res = swprintf_s(connection->pipename,
                   sizeof connection->pipename / sizeof(wchar_t),
                   L"\\\\?\\pipe\\SlipRock\\%d-%I64x",
                   GetCurrentProcessId(), random[0]);
  if (res == -1) {
    assert(0);
    abort();
  }

  sliprock_get_handle_for_connection(connection);
  if (INVALID_HANDLE_VALUE == connection->hPipe) {
    if (ERROR_ACCESS_DENIED == connection->lastError)
      goto retry;
    else
      return SLIPROCK_EOSERR;
  }
  return 0;
}

SLIPROCK_API int sliprock_accept(struct SliprockConnection *connection,
                                 SliprockHandle *handle) {
  /*
   * It is absolutely imperative that there be ONLY ONE instance of the
   * named pipe open but not connected when CreateNamedPipe() is called.
   * Otherwise, Windows will pick an arbitrary one.  This causes
   * ConnectNamedPipe() to hang intermittently, causing problems that are
   * terribly difficult to debug!
   *
   * The solution is to wait until ConnectNamedPipe() returns to make the
   * next CreateNamedPipe() call.  This bug took a very long time to fix.
   */
  DWORD written_this_time, written = 0;
  HANDLE hPipe = connection->hPipe;
  int err;
  sliprock_trace(
      "sliprock_accept() called.  Getting connection handle.\n");
  if (hPipe == INVALID_HANDLE_VALUE) {
    sliprock_trace("Invalid handle!\n");
    SetLastError(connection->lastError);
    sliprock_strerror();
    return SLIPROCK_EOSERR;
  }
  sliprock_trace("Valid connection handle\n");
  SetLastError(0);
  if (ConnectNamedPipe(hPipe, NULL) == 0 &&
      GetLastError() != ERROR_PIPE_CONNECTED) {
    err = SLIPROCK_EOSERR;
    sliprock_trace("ConnectNamedPipe() failed\n");
    sliprock_strerror();
    goto fail;
  }
  sliprock_trace("ConnectNamedPipe() succeeded\n");
  sliprock_get_handle_for_connection(connection);
  while (1) {
    sliprock_trace("About to write to pipe\n");
    if (WriteFile(hPipe, connection->passwd + written,
                  sizeof connection->passwd - written, &written_this_time,
                  NULL) == 0) {
      sliprock_strerror();
      sliprock_trace("Failed to write to pipe\n");
      err = SLIPROCK_EPROTO;
      goto fail;
    }
    sliprock_trace("Write to pipe succeeded\n");
    if (FlushFileBuffers(hPipe) == 0) {
      sliprock_strerror();
      sliprock_trace("FlushFileBuffers() failed\n");
      err = SLIPROCK_EOSERR;
      goto fail;
    }
    assert(written_this_time <= sizeof connection->passwd - written);
    written += written_this_time;
    if (written == sizeof connection->passwd) {
      *handle = (SliprockHandle)hPipe;
      FlushFileBuffers(hPipe);
      return 0;
    }
    if (written == 0) {
      err = SLIPROCK_EPROTO;
      goto fail;
    }
  }
fail:
  CloseHandle(hPipe);
  return err;
}

static DWORD sliprock_read_all(HANDLE hnd, void *buf, DWORD size) {
  char *buf_ = buf;
  DWORD read;
  do {
    if (!ReadFile(hnd, buf_, size, &read, NULL))
      break;
    if (0 == read)
      break;
    if (read > size)
      abort();
    size -= read, buf_ += read;
  } while (read != size);
  return buf_ - (char *)buf;
}

static ssize_t sliprock_read_receiver(OsHandle fd,
                                      struct SliprockReceiver *receiver,
                                      char magic[STATIC_ARR MAGIC_SIZE]) {
  char buf[sizeof SLIPROCK_MAGIC - 1 + sizeof receiver->passcode +
           sizeof receiver->sock];
  char *buf2 = buf;
  DWORD read;
  SLIPROCK_STATIC_ASSERT(MAGIC_SIZE == sizeof SLIPROCK_MAGIC - 1);
  read = sliprock_read_all(fd, buf, sizeof buf);
  sliprock_trace("Read from connection file\n");
  if (read != sizeof buf) {
#ifdef SLIPROCK_TRACE
    fprintf(stderr, "Read %lu bytes - expected %Iu\n", read, sizeof buf);
#endif
    return -1;
  }
  memcpy(magic, buf, MAGIC_SIZE);
  buf2 += MAGIC_SIZE;
  memcpy(receiver->passcode, buf2, sizeof receiver->passcode);
  buf2 += sizeof receiver->passcode;
  memcpy(receiver->sock, buf2, sizeof receiver->sock);
  return read;
}

SLIPROCK_API int sliprock_connect(const struct SliprockReceiver *receiver,
                                  SliprockHandle *handle) {
  int err;
  DWORD read;
  unsigned char pass[sizeof receiver->passcode];
  HANDLE hPipe = CreateFileW(
      receiver->sock, GENERIC_READ | GENERIC_WRITE,
      FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, NULL,
      OPEN_EXISTING, SECURITY_SQOS_PRESENT | SECURITY_ANONYMOUS, NULL);
  sliprock_trace("Created file handle\n");
  *handle = (SliprockHandle)INVALID_HANDLE_VALUE;
  if (INVALID_HANDLE_VALUE == hPipe)
    return SLIPROCK_EOSERR;
  sliprock_strerror();
  sliprock_trace("About to read from pipe\n");
  if ((read = sliprock_read_all(hPipe, pass, sizeof pass)) !=
      sizeof pass) {
#ifdef SLIPROCK_TRACE
    sliprock_strerror();
    fprintf(stderr, "Protocol malfunction! Read %lu bytes, expected %Iu\n",
            read, sizeof pass);
    fflush(stderr);
#endif
    err = SLIPROCK_EPROTO;
    goto fail;
  }
  sliprock_trace("Read from pipe succeeded\n");
  if (sliprock_secure_compare_memory(pass, receiver->passcode,
                                     sizeof pass)) {
    err = SLIPROCK_ENOAUTH;
    goto fail;
  }
  *handle = (SliprockHandle)hPipe;
  return 0;
fail:
  CloseHandle(hPipe);
  return err;
}
#endif
#endif
