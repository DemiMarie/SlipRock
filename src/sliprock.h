#ifndef SLIPROCK_H_INCLUDED
#define SLIPROCK_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#elif 0
}
#endif

#ifdef _WIN32
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#ifdef SLIPROCK_INTERNALS
#define SLIPROCK_API __declspec((dllexport))
#else
#define SLIPROCK_API __declspec((dllimport))
#endif
typedef HANDLE sliprock_Handle;
#else
#include <sys/socket.h>
#include <sys/types.h>
#ifdef __GNUC__
#define SLIPROCK_API __attribute__((visibility("default")))
#else
#define SLIPROCK_API
#endif
typedef int sliprock_Handle;
#endif

#define SLIPROCK_EOSERR	-1
#define SLIPROCK_EBADPASS	-2

#define SLIPROCK_STATIC_ASSERT(expr)                                              \
  (0 * sizeof(struct { int static_assertion_failed : 2 * !!(expr)-1; }))

typedef struct SliprockConnection SliprockConnection;

/**
 * \param name The name of the connection.  Does not need to be NUL-terminated,
 * but must not have any NUL characters in it.  Sliprock will copy this string
 * if necessary; it does not need to be kept alive by the caller.
 *
 * \param length The length of the name.
 *
 * \return an opaque pointer (of type SliprockConnection) that encapsulates the
 * state of the connection, or sliprock_Invalid_Handle on error.  Must be
 * explicitly released by the caller with sliprock_release when no longer needed.
 */
SLIPROCK_API SliprockConnection *sliprock_socket(const char *name, size_t length);

SLIPROCK_API int sliprock_bind(SliprockConnection *conn);

SLIPROCK_API int sliprock_accept(SliprockConnection *conn, struct sockaddr *addr, socklen_t *size);

SLIPROCK_API void sliprock_close(SliprockConnection *conn);


typedef struct SliprockReceiver SliprockReceiver;

SLIPROCK_API SliprockReceiver *sliprock_open(const char *const filename);

SLIPROCK_API void sliprock_close_receiver(struct SliprockReceiver *receiver);

SLIPROCK_API int sliprock_connect(struct SliprockReceiver *receiver);

#if 0
{
#elif defined __cplusplus
}
#endif
#endif
