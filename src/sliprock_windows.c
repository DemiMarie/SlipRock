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
  wchar_t file_path[];
  /* char name[];*/
};

static char *nameptr(struct SliprockConnection *con) {
   return (char*)(uintptr_t)(con->file_path + con->pathlen);
}

static const wchar_t *get_fname(const char *srcname, size_t len, int pid,
                                int *innerlen) {
  void *current_token = GetCurrentProcessToken();
  DWORD homelen = 0;
  GetUserProfileDirectoryW(current_token, NULL, &homelen);
  if (homelen == 0)
    return NULL;
  void *myheap = GetProcessHeap();
  if (myheap == INVALID_HANDLE_VALUE)
    return NULL;
  wchar_t *path =
      HeapAlloc(myheap, 20 /* length of UINT64_MAX as decimal */ +
                            2 * homelen /* length of home directory */ +
                            2 * len + sizeof L"\\.sliprock\\..sock",
                8);
  if (path == NULL)
    return NULL;
  DWORD newhomelen;
  GetUserProfileDirectoryW(current_token, path, &newhomelen);
  if (newhomelen != homelen)
    abort();
  size_t available = 20 + sizeof "\\.sliprock\\.";
  int res = _snwprintf_s(path + newhomelen, available, available + 1,
                         L"\\.sliprock\\%d.", pid);
  if (res < 0)
    abort();
  *innerlen = newhomelen + res;
  if (len > INT_MAX) abort();
  size_t newlen = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS,
        srcname, len, path + newhomelen + res, len);
  wcscpy(path + newhomelen + res + newlen, L".sock");
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
  if ((size_t)_snwprintf_s(pipe->name, (sizeof pipe->name)/2, (sizeof pipe->name)/2 + 1,
                        L"\\\\.\\pipe\\sliprock.%ld.%016I64x%016I64x.sock",
                        GetCurrentProcessId(), random[0],
                        random[1]) < 0) {
    /* Impossible */
    abort();
  }

  SecureZeroMemory(random, sizeof random);
  SECURITY_ATTRIBUTES sec_attributes;
  /* Can't hurt.  Might help (IIRC several Windows API structs must be zeroed).
   */
  ZeroMemory(&sec_attributes, sizeof sec_attributes);

  sec_attributes.nLength = sizeof sec_attributes;
  sec_attributes.bInheritHandle = 0; /* not necessary */
  pipe->handle = CreateNamedPipeW(
      pipe->name, PIPE_ACCESS_DUPLEX|FILE_FLAG_FIRST_PIPE_INSTANCE,
      PIPE_TYPE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS,
      PIPE_UNLIMITED_INSTANCES, 1U << 12, /* Small to preserve nonpaged pool */
      1U << 12,
      0, &sec_attributes);
}
struct pipe *allocConnection(void) {
  struct pipe *res = (struct pipe *)malloc(sizeof(struct pipe));
  if (res == NULL)
    return NULL;
  initNamedPipe(res);
  if (res->handle == INVALID_HANDLE_VALUE) {
    free(res);
    return NULL;
  }
  return res;
}

void deleteConnection(struct pipe *mypipe) {
  if (mypipe == NULL)
    return;
  CloseHandle(mypipe->handle);
  free(mypipe);
}
struct SliprockConnection *sliprock_socket(const char *const name,
                                           size_t const namelen) {
  assert(name != NULL);
  // TODO allow unicode
  for (size_t i = 0; i < namelen; ++i) {
    if (!isalnum(name[i]) && name[i] != '-' && name[i] != '.' &&
        name[i] != '_') {
      errno = EILSEQ;
      return NULL;
    }
  }
  unsigned char tmp[16];
  // Allocate the connection
  struct SliprockConnection *connection = sliprock_new(name, namelen);
  char created_directory = 0;
  if (NULL == connection)
    return NULL;
  (void)SLIPROCK_STATIC_ASSERT(sizeof connection->address.sun_path >
                               sizeof "/tmp/sliprock." - 1 + 20 + 1 + 16 + 1 +
                                   16 + 1);

// Temporary buffer used for random numbers
retry:
  randombytes_buf(tmp, sizeof tmp);

  if ((errno = sliprock_bind(connection))) {
    sliprock_close(connection);
    return NULL;
  }

  return connection;
fail:
  if (connection != NULL) {
    if (connection->fd.fd != -1) {
      close(connection->fd.fd);
    }
    if (created_directory) {
      rmdir(dirname(connection->address.sun_path));
    }
    free(connection);
  }
  return NULL;
}
