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
#define SLIPROCK_API __declspec(dllexport)
#else
#define SLIPROCK_API __declspec(dllimport)
#endif
#else
#include <sys/socket.h>
#include <sys/types.h>
#ifdef __GNUC__
#define SLIPROCK_API __attribute__((visibility("default")))
#else
#define SLIPROCK_API
#endif
#endif

#include <stdint.h>

#define SLIPROCK_EOSERR -1
#define SLIPROCK_EBADPASS -2

#define SLIPROCK_STATIC_ASSERT(expr)                                           \
  (0 * sizeof(struct { int static_assertion_failed : 2 * !!(expr)-1; }))

typedef struct SliprockConnection SliprockConnection;

typedef uint64_t SliprockHandle;

/**
 * \brief Creates a SlipRock connection (server-side).
 *
 * This function creates a the server side of a SlipRock connection.  On success
 * a pointer to the connection is returned, which must be freed with
 * sliprock_close() when the connection is no longer needed.  This is not just
 * to avoid memory leaks – sliprock_socket() creates temporary filesystem
 * objects that must be deleted when no longer in use.
 *
 * \param name The name of the connection.  Does not need to be NUL-terminated,
 * but must not have any NUL characters in it.  Sliprock will copy this string
 * if necessary; it does not need to be kept alive by the caller.
 *
 * If name contains bytes below 0x20, is not valid UTF-8, or contains any
 * characters invalid in Windows filenames, sliprock_socket() will return \p
 * NULL and set \p errno to \p EILSEQ (in the case of invalid UTF-8) or \p
 * EINVAL (in the case of invalid characters in Windows filenames).  If \p name
 * is \p NULL, * sliprock_socket() will crash the process with a fatal assertion
 * failure.
 *
 * \param length The length of the name.
 *
 * \return an opaque pointer (of type SliprockConnection) that encapsulates the
 * state of the connection, or sliprock_Invalid_Handle on error.  Must be
 * explicitly released by the caller with sliprock_release when no longer
 * needed.
 */
SLIPROCK_API SliprockConnection *sliprock_socket(const char *name,
                                                 size_t length);

/**
 * Accepts an OS connection from the server side of a SlipRock
 * connection.
 *
 * The return value is a \p HANDLE (Windows) or a file descriptor (*nix).  It -1
 * (*nix) or \p INVALID_HANDLE_VALUE (Windows) on error.  On error, errno (*nix)
 * or the return value of GetLastError() (Windows) is set to indicate the error.
 *
 * This is a blocking call.  Use sliprock_accept_async() if you want
 * anon-blocking version.
 *
 * \param conn The SlipRock connection to accept the connection from.
 */
SLIPROCK_API SliprockHandle sliprock_accept(SliprockConnection *conn);

/**
 * Closes a Sliprock connection, freeing underlying resources.
 *
 * This frees any resources used by the connection.  It must always be closed to
 * avoid leaking both memory and temporary files, directories, and sockets or
 * named pipes.
 *
 * \param conn The connection to close.
 *
 * Any subsequent use of \p conn results in undefined behavior.
 */
SLIPROCK_API void sliprock_close(SliprockConnection *conn);

/**
 * \brief A receiver for SlipRock messages.
 *
 * This represents all of the information a client needs to connect to an
 * existing SlipRock connection.  It must be closed with
 * sliprock_close_receiver() when no longer needed, to avoid memory leaks.
 */
typedef struct SliprockReceiver SliprockReceiver;

/**
 * \brief Open the client side of a SlipRock connection.
 *
 * This opens the client side of a SlipRock connection.  The resulting
 * SliprockReceiver pointer can be used to make as many connections to the
 * server as desired.
 *
 * This is a blocking call.  Call it on a worker thread if you need to avoid
 * blocking.
 *
 * \param identifier The name of the identifier that the server has used for the
 * connection.  Does not need to be NUL-terminated.
 *
 * \param size The length of \p identifier.
 *
 * \param pid The process ID of the process to be connected to.
 */
SLIPROCK_API SliprockReceiver *sliprock_open(const char *const filename,
                                             size_t size, uint32_t pid);

/**
 * Frees the given SliprockReceiver, releasing underlying resources.
 *
 * After this function is called, the argument is no longer a valid pointer.
 *
 * This function does not block, except by calling free().
 */
SLIPROCK_API void sliprock_close_receiver(struct SliprockReceiver *receiver);

/**
 * Connects the given SliprockReceiver to its peer.
 *
 * This connects the given SliprockReceiver to its peer.  The return value is an
 * OS handle to the connection.
 *
 * It is safe to call this function may be from multiple threads concurrently,
 * even with the same \p receiver.
 *
 * This is a blocking call and blocks until the peer has created a connection.
 */
SLIPROCK_API SliprockHandle
sliprock_connect(const struct SliprockReceiver *receiver);

/**
 * Unsafely gets the raw OS handle to a server-side connection.
 *
 * This function unsafely obtains the raw OS handle to the server-side
 * connection.  This is an open AF_UNIX socket on *nix and a HANDLE to a named
 * pipe on Windows.  The return value should be downcast to the appropriate
 * type.
 *
 * SlipRock promises that the return value will be a valid HANDLE (Windows) or
 * file descriptor (*nix), but only until sliprock_close() is called.  If
 * `should_release` is zero, the handle is owned by SlipRock; it must not be
 * deallocated by the caller.  Otherwise, the handle is no longer owned by
 * SlipRock – the caller is responsible for deallocation.  Subsequent calls to
 * sliprock_accept() or sliprock_UNSAFEgetRawHandle() will cause a fatal
 * assertion failure.
 *
 * It is not safe to call this function concurrently with other calls that pass
 * the same \p connection argument if \p should_release is true.  If it is
 * false, this function can be called concurrently with other SlipRock calls,
 * even on the same \p connection.
 */
SLIPROCK_API SliprockHandle sliprock_UNSAFEgetRawHandle(
    struct SliprockConnection *connection, int should_release);

/**
 * Gets a pointer to the passphrase in a SliprockConnection.
 *
 * The passphrase is guaranteed to be 32 bytes.  It must not be leaked to
 * untrusted code.  Failing to meet this requirement loses all security
 * guarantees provided by this library.
 *
 * If an OS handle is retrieved using sliprock_UNSAFEgetRawHandle(), the bytes
 * pointed to by this **MUST** be the first thing written to any handles created
 * from the OS handle.
 */
SLIPROCK_API const char *
sliprock_UNSAFEgetPasscode(const struct SliprockConnection *connection);
#if 0
{
#elif defined __cplusplus
}
#endif
#endif
