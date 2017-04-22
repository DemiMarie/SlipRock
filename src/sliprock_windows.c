#define RtlGenRandom SystemFunction036
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#define SLIPROCK_INTERNALS
#include "sliprock.h"
#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#ifndef _MSC_VER
__declspec(dllimport) HANDLE GetCurrentProcessToken(void);
__declspec(dllimport) HANDLE
    GetUserProfileDirectoryW(HANDLE tok, wchar_t *buf, DWORD *len);
#endif
#include <processthreadsapi.h>
#ifndef _Out_
#define _Out_
#endif
BOOLEAN RtlGenRandom(void *buffer, unsigned long length);
#define SIZE 61

struct pipe {
  HANDLE handle;
  wchar_t name[61];
};
struct fd {
  int fd;
};

struct SliprockConnection {
  const size_t namelen;
  const size_t pathlen;
  struct pipe pipe;
  char passwd[32];
  wchar_t
      *file_path; //< The path – must be passed to free() when no longer needed
  char name[];
};

void sliprock_close(struct SliprockConnection *conn) {
  if (conn->pipe.handle != INVALID_HANDLE_VALUE)
    CloseHandle(conn->pipe.handle);
  free(conn->file_path);
  free(conn);
}

#if 0
static char *nameptr(struct SliprockConnection *con) {
  return (char *)(uintptr_t)(con->file_path + con->pathlen);
}
#endif

static const wchar_t *get_fname(const char *srcname, size_t len, int pid,
                                int *innerlen, int *outerlen) {
  void *current_token = GetCurrentProcessToken();
  DWORD homelen = 0;
  GetUserProfileDirectoryW(current_token, NULL, &homelen);
  if (homelen == 0)
    return NULL;
  wchar_t *path = calloc(20 /* length of UINT64_MAX as decimal */ +
                             homelen /* length of home directory */ +
                             len + sizeof "\\.sliprock\\..sock" +
                         4 /* size of \\?\ */,
                         2);
  if (path == NULL)
    return NULL;
  CopyMemory(path, "\\\\?\\", sizeof "\\\\?\\");
  DWORD newhomelen;
  GetUserProfileDirectoryW(current_token + 4, path, &newhomelen);
  if (newhomelen != homelen)
    abort();
  size_t available = 20 + sizeof "\\.sliprock\\.";
  int res = _snwprintf_s(path + newhomelen, available, available + 1,
                         L"\\.sliprock\\%d.", pid);
  if (res < 0)
    abort();
  *innerlen = newhomelen + res;
  if (len > INT_MAX)
    abort();
  size_t newlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, srcname,
                                      len, path + newhomelen + res, len);
  wcscpy(path + newhomelen + res + newlen, L".sock");
  *outerlen = path + newhomelen + res + newlen + 5;
  return path;
}

void initNamedPipe(_Out_ struct pipe *pipe) {
  uint64_t random[2];
  /* Zero the pipe.  Avoids any worries down the line. */
  ZeroMemory(pipe, sizeof *pipe);
  if (!RtlGenRandom(random, sizeof random)) {
    /* RNG failure is not recoverable and indicates an OS bug */
    abort();
  }
  /* Not worried about timing attacks.  The pipe name is public anyway. */
  if ((size_t)_snwprintf_s(pipe->name, (sizeof pipe->name) / 2,
                           (sizeof pipe->name) / 2 + 1,
                           L"\\\\?\\pipe\\sliprock\\%ld\\%016I64\\sock",
                           GetCurrentProcessId(), random[0]) < 0) {
    /* Impossible */
    abort();
  }

  SecureZeroMemory(random, sizeof random);
  SECURITY_ATTRIBUTES sec_attributes;
  /* Can't hurt.  Might help (IIRC several Windows API structs must be zeroed).
   */
  ZeroMemory(&sec_attributes, sizeof sec_attributes);

  sec_attributes.nLength = sizeof sec_attributes;
  sec_attributes.bInheritHandle = 0; /* not necessary – already zeroed */
  pipe->handle = CreateNamedPipeW(
      pipe->name, PIPE_ACCESS_DUPLEX | FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS, PIPE_UNLIMITED_INSTANCES,
      1U << 12, /* Small to preserve nonpaged pool */
      1U << 12, 0, &sec_attributes);
}

struct SliprockConnection *sliprock_socket(const char *const name,
                                           size_t const namelen) {
  int innerlen;
  unsigned char tmp[16];
  struct SliprockConnection *connection = NULL;
  HANDLE fhandle = INVALID_HANDLE_VALUE;
  SECURITY_ATTRIBUTES sec_attributes;

  assert(name != NULL);
  // TODO allow unicode
  for (size_t i = 0; i < namelen; ++i) {
    if (!isalnum(name[i]) && name[i] != '-' && name[i] != '.' &&
        name[i] != '_') {
      errno = EILSEQ;
      return NULL;
    }
  }
  // Allocate the connection
  connection = calloc(sizeof(struct SliprockConnection), 1);
  if (NULL != connection)
    goto fail;
  connection->path = get_fname(name, namelen, GetCurrentProcessId(), &innerlen,
                               &connection->pathlen);
  if (NULL != connection->path)
    return NULL;
  initNamedPipe(&connection->pipe);
  if (NULL != connection->pipe.handle)
    goto fail;

  assert(connection->path[innerlen] == '\\');
  connection->path[innerlen] = '\0';
  /* Can't hurt.  Might help (IIRC several Windows API structs must be zeroed).
   */
  ZeroMemory(&sec_attributes, sizeof sec_attributes);

  sec_attributes.nLength = sizeof sec_attributes;
  sec_attributes.bInheritHandle = 0; /* not necessary – already zeroed */
  if (!CreateDirectoryW(connection->path, &sec_attributes) &&
      GetLastError() != ERROR_ALREADY_EXISTS)
    goto fail;
  else
     SetLastError(ERROR_SUCCESS);
  connection->path[innerlen] = '\\';
  fhandle = CreateFileW(connection->path,
                   GENERIC_READ,
                   0,
                   &sec_attributes,
                   CREATE_ALWAYS,
                   FILE_ATTRIBUTE_NORMAL,
                               NULL);
  if (INVALID_HANDLE_VALUE == fhandle)
     goto fail;
  assert(0 && "Not yet implemented: writing temp file!");
  CloseHandle(fhandle);
  fhandle = INVALID_HANDLE_VALUE;
  return connection;
fail:
  DWORD err = GetLastError();
  if (INVALID_HANDLE_VALUE != connection->pipe.handle)
     CloseHandle(connection->pipe.handle);
  if (INVALID_HANDLE_VALUE != fhandle)
     CloseHandle(fhandle);
  DeleteFile(connection->path);
  free(connection->path);
  free(connection);
  SetLastError(err);
  return NULL;
}
