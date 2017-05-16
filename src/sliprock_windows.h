// Tiny Windows implementation of a reasonable platform abstraction
// layer.

#ifndef SLIPROCK_WINDOWS_H_INCLUDED
#define SLIPROCK_WINDOWS_H_INCLUDED SLIPROCK_WINDOWS_H_INCLUDED
#ifdef _WIN32
#ifndef UNICODE
#define UNICODE
#endif
#ifndef _UNICODE
#define _UNICODE
#endif

#include "stringbuf.h"
#include <assert.h>
#include <processthreadsapi.h>
#include <userenv.h>
#include <windows.h>
#define sliprock_unlink DeleteFileW
#define rmdir RemoveDirectoryW

typedef wchar_t MyChar;
typedef HANDLE OsHandle;
#define getpid GetCurrentProcessId
#define O_RDWR 3
#define O_RDONLY 2
#define O_WRONLY 1

static OsHandle openfile(MyChar *path, int mode) {
  int osmode = 0;
  int creation_mode = OPEN_EXISTING;
  SECURITY_ATTRIBUTES sec;
  ZeroMemory(&sec, sizeof sec);
  sec.nLength = sizeof sec;
  assert(mode && mode < 4);
  if (mode & 2)
    osmode |= GENERIC_READ;
  if (mode & 1) {
    osmode |= GENERIC_WRITE;
    creation_mode = CREATE_ALWAYS;
  }
  return CreateFileW(path, osmode, 0, &sec, creation_mode,
                     FILE_ATTRIBUTE_NORMAL, NULL);
}
#ifdef _MSC_VER
#include <processthreadsapi.h>
#else
// Taken from Wine
#define GetCurrentProcessToken() ((HANDLE) ~(ULONG_PTR)3)
#endif
#define snprintf _wsnprintf
#define RtlGenRandom SystemFunction036
#define CON_PATH(con) ((con)->pipename)
#define SLIPROCK_MAGIC "\0SlipRock\n\rPIPE\x1a"
extern BOOLEAN RtlGenRandom(_Out_ PVOID random_buf, _In_ ULONG buflen);

static int fill_randombuf(void *buf, size_t size) {
  return RtlGenRandom(buf, size);
}
#define hclose(x) CloseHandle(x)
INIT_ONCE initialized = INIT_ONCE_STATIC_INIT;

int init_func(void) { return 0; }

static wchar_t *sliprock_get_home_directory(void **const freeptr) {
  HANDLE const hCurProc = GetCurrentProcessToken();
  wchar_t *buf = NULL;
  DWORD len;
  *freeptr = NULL;
  if (!GetUserProfileDirectoryW(hCurProc, NULL, &len))
    return NULL;
  if ((buf = (wchar_t *)malloc(sizeof(wchar_t) * len)) == NULL)
    return NULL;
  if (!GetUserProfileDirectoryW(hCurProc, buf, &len)) {
    free(buf);
    return NULL;
  }
  return *freeptr = buf;
}

static OsHandle create_directory_and_file(struct StringBuf *path) {
  for (size_t i = path->buf_length; i > 0;) {
    --i;
    if (L'\\' == path->buf[i]) {
      path->buf[i] = 0;
      SECURITY_ATTRIBUTES sec;
      ZeroMemory(&sec, sizeof sec);
      sec.nLength = sizeof sec;
      if (!CreateDirectoryW(path->buf, &sec) &&
          GetLastError() != ERROR_ALREADY_EXISTS) {
        path->buf[i] = L'\\';
        return INVALID_HANDLE_VALUE;
      }
      path->buf[i] = L'\\';
      return openfile(path->buf, O_WRONLY);
    }
  }
  abort(); // impossible
}

static int sliprock_fsync(OsHandle fd) {
  return FlushFileBuffers(fd) ? 0 : -1;
}

#if 0
static int get_errno(void) {
   return GetLastError();
}
static int set_errno(DWORD err) {
   SetLastError(err);
   return err;
}
#endif

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
  char buf[sizeof SLIPROCK_MAGIC - 1 + sizeof con->passwd + sizeof con->pipename];
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
  return 0;
}

static int sliprock_bind_os_raw(struct SliprockConnection *connection, HANDLE *pipe) {
    SECURITY_ATTRIBUTES sec_attributes;
    /* Can't hurt.  Might help (IIRC several Windows API structs must be
     * zeroed).
     */
    ZeroMemory(&sec_attributes, sizeof sec_attributes);

    sec_attributes.nLength = sizeof sec_attributes;
    sec_attributes.bInheritHandle = 0; /* not necessary – already zeroed */
    HANDLE hPipe = CreateNamedPipeW(
        connection->pipename, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
        PIPE_TYPE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
        PIPE_UNLIMITED_INSTANCES,
        1U << 12, /* Small to preserve nonpaged pool */
        1U << 12, 0, &sec_attributes);
    *pipe = hPipe;
    if (INVALID_HANDLE_VALUE == hPipe) {
       return -1;
    }
    return 0;
}

SLIPROCK_API SliprockHandle
sliprock_accept(struct SliprockConnection *connection) {
  HANDLE hPipe;
  if (sliprock_bind_os_raw(connection, &hPipe) < 0)
    return (SliprockHandle)hPipe;
  if (ConnectNamedPipe(&hPipe, NULL) == 0) {
    goto fail;
  }
  DWORD written_this_time, written = 0;
  while (1) {
    if (WriteFile(hPipe, connection->passwd + written, sizeof connection->passwd - written, &written_this_time, NULL) == 0)
       goto fail;
    assert(written_this_time <= sizeof connection->passwd - written);
    written += written_this_time;
    if (written == sizeof connection->passwd)
       return (SliprockHandle)hPipe;
    if (written == 0)
       goto fail;
  }
fail:
  CloseHandle(hPipe);
  return (SliprockHandle)INVALID_HANDLE_VALUE;
}

static ssize_t read_receiver(OsHandle fd, struct SliprockReceiver *receiver,
                             char magic[static sizeof SLIPROCK_MAGIC - 1]) {
  char buf[sizeof SLIPROCK_MAGIC - 1 + sizeof receiver->passcode + sizeof receiver->sock];
  char *buf2 = buf;
  DWORD read;
  if (ReadFile(fd, buf, sizeof buf, &read, NULL) == 0)
    return -1;
  if (read != sizeof buf)
    return -1;
  if (memcmp(buf2, magic, MAGIC_SIZE))
    return -1;
  buf2 += MAGIC_SIZE;
  memcpy(receiver->passcode, buf2, sizeof receiver->passcode);
  buf2 += sizeof receiver->passcode;
  memcpy(receiver->sock, buf2, sizeof receiver->sock);
  return 0;
}

static int sliprock_bind_os(struct SliprockConnection *connection) {
   return sliprock_bind_os_raw(connection, &connection->fd);
}

#ifdef _MSC_VER
#define NOINLINE __declspec(noinline)
#elif defined __GNUC__
#define NOINLINE __attribute__((noinline))
#else
#error dont know how to tell the compiler not to inline this
#endif
static NOINLINE int
secure_compare_memory(const char *buf1, const char *buf2, size_t len) {
   int res = 0;
   for (size_t i = 0; i < len; ++i)
      res |= buf1[i] ^ buf2[i];
   return res;
}

SliprockHandle sliprock_connect(const struct SliprockReceiver *receiver) {
  HANDLE hPipe = CreateFile(
        receiver->sock,
        GENERIC_READ | GENERIC_READ,
        FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
        NULL,
        OPEN_EXISTING,
        SECURITY_SQOS_PRESENT|SECURITY_ANONYMOUS,
        NULL);
  if (INVALID_HANDLE_VALUE == hPipe)
     return (SliprockHandle)hPipe;
  char pass[sizeof receiver->passcode];
  DWORD read;
  if (ReadFile(hPipe, pass, sizeof pass, &read, NULL) == 0)
    goto fail;
  if (read != sizeof pass) {
    SetLastError(ERROR_ACCESS_DENIED);
    goto fail;
  }
  if (secure_compare_memory(pass, receiver->passcode, sizeof pass)) {
    SetLastError(ERROR_ACCESS_DENIED);
    goto fail;
  }
  return (SliprockHandle)hPipe;
fail:
  CloseHandle(hPipe);
  return (SliprockHandle)INVALID_HANDLE_VALUE;
}
#endif
#endif
