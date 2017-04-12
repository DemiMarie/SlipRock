#define RtlGenRandom SystemFunction036
#define UNICODE
#define _UNICODE
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
BOOLEAN RtlGenRandom(void *buffer, unsigned long length);
#define SIZE (26 + 33)

struct pipe {
  HANDLE handle;
  char name[SIZE];
}

struct pipe *allocConnection(void) {
   struct pipe *res = (struct pipe *)malloc(sizeof(struct pipe));
   if (res == NULL) return NULL;
   initNamedPipe(res);
   if (res->handle == INVALID_HANDLE_VALUE) {
      free(res);
      return NULL;
   }
   return res;
}

void deleteConnection(struct pipe *mypipe) {
   if (mypipe == NULL) return;
   CloseHandle(mypipe->handle);
   free(mypipe);
}

void initNamedPipe(_Out_ struct pipe *pipe) {
  uint64_t random[2];
  /* Zero the pipe.  Avoids any worries down the line. */
  ZeroMemory(pipe, sizeof *pipe);
  if (!RtlGenRandom(random, sizeof random)) {
    /* RNG failure is not recoverable and indicates an OS bug */
    __fastfail();
  }
  /* Not worried about timing attacks.  The pipe name is public anyway. */
  if ((size_t)_snprintf(&pipe->name, sizeof pipe->name,
                       "\\\\.\\pipe\\sliprock.%d.%016llx%016llx",
                       GetCurrentProcessId(), random[0],
                       random[1]) >= sizeof pipe->name) {
    /* Impossible */
    __fastfail();
  }

  SecureZeroMemory(random, sizeof random);
  SECURITY_ATTRIBUTES sec_attributes;
  /* Can't hurt.  Might help (IIRC several Windows API structs must be zeroed).
   */
  ZeroMemory(&sec_attributes, sizeof sec_attributes);

  sec_attributes.nLength = sizeof sec_attributes;
  sec_attributes.bInheritHandle = 0; /* not necessary */
  pipe->handle = CreateNamedPipeW(
      name, PIPE_ACCESS_DUPLEX, PIPE_TYPE_MESSAGE,
      PIPE_READMODE_MESSAGE | PIPE_REJECT_REMOTE_CLIENTS, 0,
      PIPE_UNLIMITED_INSTANCES, 1U << 12, /* Small to preserve nonpaged pool */
      0, &sec_attributes);
}
