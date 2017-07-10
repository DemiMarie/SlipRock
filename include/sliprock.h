#ifndef SLIPROCK_H_INCLUDED
#define SLIPROCK_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#elif 0
} /* make emacs indent happy */
#endif
#ifdef SLIPROCK_INTERNALS
#include "../src/sliprock_internals.h"
#endif
#include <assert.h>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
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

#define SLIPROCK_EOSERR -1    /* Operating system failure */
#define SLIPROCK_ENOMEM -2    /* Out of memory */
#define SLIPROCK_EINVAL -3    /* Invalid argument */
#define SLIPROCK_ETMPPERMS -4 /* Insecure permissions in /tmp */
#define SLIPROCK_ENOAUTH -5   /* Authentication failed */
#define SLIPROCK_ENOCONN -6   /* No such connection */
#define SLIPROCK_ENORND -7    /* Failure to obtain random numbers from the OS */
#define SLIPROCK_ERANGE -8    /* Argument out of range (ex. too long) */
#define SLIPROCK_EILSEQ -9    /* Illegal byte sequence */
#define SLIPROCK_EINTERNALERROR -10 /* Internal error (this is a bug) */
#define SLIPROCK_EPROTO -11         /* Protocol error */

#if !defined static_assert && (!defined __cplusplus || __cplusplus < 201103L)
#define SLIPROCK_STATIC_ASSERT(expr)                                           \
  ((void)sizeof(struct {                                                       \
    int static_assertion_failed : (8 * sizeof(int) * ((2 * !!(expr)) - 1));    \
  }))
#else
#define SLIPROCK_STATIC_ASSERT(expr)                                           \
  static_assert(expr, "Static assertion failed")
#endif
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
 * \param connection Set to an opaque pointer (of type SliprockConnection) that
 * encapsulates the state of the connection, or sliprock_Invalid_Handle on
 * error.  Must be explicitly released by the caller with sliprock_release when
 * no longer needed.  On failure, it is set to NULL.
 * \return 0 on success.  On error, a (negative) SlipRock error is returned.
 */
SLIPROCK_API int sliprock_socket(const char *name, size_t length,
                                 SliprockConnection **connection);

/**
 * Accepts an OS connection from the server side of a SlipRock
 * connection.
 *
 * On success, *handle is set to a \p HANDLE (Windows) or a file descriptor
 * (*nix).  It -1 (*nix) or \p INVALID_HANDLE_VALUE (Windows) on error.
 *
 * Returns 0 on success.  On error, a negative error code is returned.
 *
 * This is a blocking call.  Use sliprock_accept_async() if you want
 * anon-blocking version.
 *
 * \param conn The SlipRock connection to accept the connection from.

 */
SLIPROCK_API int sliprock_accept(SliprockConnection *conn,
                                 SliprockHandle *handle);

/**
 * Closes a SlipRock connection, freeing underlying resources.
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
 *
 * \param receiver A pointer through which a SliprockReceiver* will be written.
 *
 * \returns 0 on success.  On error, a (negative) SlipRock error code is
 * returned, and *receiver is set to NULL.
 */
SLIPROCK_API int sliprock_open(const char *const identifier, size_t size,
                               uint32_t pid, SliprockReceiver **receiver);

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
 * This connects the given SliprockReceiver to its peer.  On return, *handle is
 * an OS handle to the connection, or -1 (suitably cast) on error.
 *
 * \return 0 on success, a (negative) SlipRock error code on failure.
 *
 * It is safe to call this function may be from multiple threads concurrently,
 * even with the same \p receiver.
 *
 * This is a blocking call and blocks until the peer has created a connection.
 */
SLIPROCK_API int sliprock_connect(const struct SliprockReceiver *receiver,
                                  SliprockHandle *handle);

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
SLIPROCK_API const unsigned char *
sliprock_UNSAFEgetPasscode(const struct SliprockConnection *connection);

#ifdef _MSC_VER
#define SLIPROCK_NOINLINE __declspec(noinline)
#elif defined __GNUC__
#define SLIPROCK_NOINLINE __attribute__((noinline))
#else
#warning dont know how to tell the compiler not to inline this
#define SLIPROCK_NOINLINE
#endif
/**
 * Compare two byte sequences in constant time.  Return -1 if they are equal, or
 * -1 otherwise.
 */
SLIPROCK_NOINLINE int
sliprock_secure_compare_memory(const volatile unsigned char *const buf1,
                               const volatile unsigned char *const buf2,
                               size_t len);

#if defined __GNUC__ || defined __INTEL_COMPILER
#define SLIPROCK_WARN_UNUSED_RESULT __attribute__((warn_unused_result))
#else
#define SLIPROCK_WARN_UNUSED_RESULT /* nothing */
#endif

/* Cryptographic random number generation */
SLIPROCK_WARN_UNUSED_RESULT int
sliprock_randombytes_sysrandom_buf(void *const buf, const size_t size);

#if 0
{ /* make emacs happy */
#elif defined __cplusplus
}
#endif
#endif
