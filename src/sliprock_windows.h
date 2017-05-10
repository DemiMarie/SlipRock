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

static void set_cloexec(OsHandle fd) { (void)fd; }

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
#endif
#endif
