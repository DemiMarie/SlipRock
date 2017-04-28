// Tiny Windows implementation of a reasonable platform abstraction
// layer.
#ifdef _WIN32
#define UNICODE
#define _UNICODE
#include <windows.h>

typedef wchar_t MyChar;

static int makedir(MyChar *path) {
  SECURITY_ATTRIBUTES sec;
  ZeroMemory(&sec, sizeof sec);
  sec.nLength = sizeof sec;
  return CreateDirectoryW(path, &sec) != 0 ? 0 : -1;
}

#define O_RDWR 3
#define O_RDONLY 2
#define O_WRONLY 1

static uintptr_t openfile(MyChar *path, int mode) {
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
    return -1;
  else
    return h;
}

static int get_errno(void) {
   return GetLastError();
}
static int set_errno(DWORD err) {
   SetLastError(err);
   return err;
}
#pragma gcc poison errno
#endif
