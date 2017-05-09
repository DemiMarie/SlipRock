// Tiny Windows implementation of a reasonable platform abstraction
// layer.

#ifndef SLIPROCK_WINDOWS_H_INCLUDED
#define SLIPROCK_WINDOWS_H_INCLUDED SLIPROCK_WINDOWS_H_INCLUDED
#ifdef _WIN32
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <userenv.h>
#include <processthreadsapi.h>
#include <assert.h>
#define sliprock_unlink DeleteFileW
#define rmdir RemoveDirectoryW

typedef wchar_t MyChar;
typedef HANDLE OsHandle;
static int makedir(MyChar *path) {
  SECURITY_ATTRIBUTES sec;
  ZeroMemory(&sec, sizeof sec);
  sec.nLength = sizeof sec;
  return CreateDirectoryW(path, &sec) != 0 ? 0 : -1;
}
#define getpid GetCurrentProcessId
#define O_RDWR 3
#define O_RDONLY 2
#define O_WRONLY 1

static OsHandle openfile(MyChar *path, int mode) {
  HANDLE h;
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
  h = CreateFileW(path, osmode, 0, &sec, creation_mode, FILE_ATTRIBUTE_NORMAL,
                  NULL);
  if (INVALID_HANDLE_VALUE == h)
    return (OsHandle)-1;
  else
    return h;
}
#ifdef _MSC_VER
#include <processthreadsapi.h>
#else
// Taken from Wine
#define GetCurrentProcessToken() ((HANDLE)~(ULONG_PTR)3)
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
   if (!GetUserProfileDirectoryW(hCurProc, NULL, &len)) return NULL;
   if ((buf = (wchar_t *) malloc(sizeof(wchar_t) * len)) == NULL) return NULL;
   if (!GetUserProfileDirectoryW(hCurProc, buf, &len)) {
      free(buf);
      return NULL;
   }
   return *freeptr = buf;
}

static OsHandle create_directory_and_file(MyChar *path) {
   for (size_t i = wcslen(path); i > 0;) {
      --i;
      if (L'\\' == path[i]) {
         path[i] = 0;
         if (makedir(path) < 0 && GetLastError() != ERROR_ALREADY_EXISTS) {
            path[i] = L'\\';
            return INVALID_HANDLE_VALUE;
         }
         path[i] = L'\\';
         return openfile(path, O_WRONLY);
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
#define T(x) (L##x)
#endif
#endif
