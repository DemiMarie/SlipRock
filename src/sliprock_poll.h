#include "sliprock/config.h"
#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef _WIN32

#include <winsock.h>
#include <ws2tcpip.h>
typedef SOCKET sliprock_socket_t;
#define SLIPROCK_POLL WSAPoll
#define SLIPROCK_POLL_FLAGS (POLLRDNORM | POLLWRNORM)
#define SLIPROCK_EAGAIN WSAEWOULDBLOCK
#define SLIPROCK_EWOULDBLOCK WSAEWOULDBLOCK
#define SLIPROCK_EPROTO WSAEPROTO
#define SLIPROCK_EINTR WSAEINTR

#else /* !defined _WIN32 */
#include <errno.h>
#include <poll.h>
#include <unistd.h>
typedef int sliprock_socket_t;
#define SLIPROCK_POLL poll
#define SLIPROCK_POLL_FLAGS (POLLIN | POLLOUT)
#define SLIPROCK_EAGAIN EAGAIN
#define SLIPROCK_EWOULDBLOCK EWOULDBLOCK
#define SLIPROCK_EPROTO EPROTO
#define SLIPROCK_EINTR EINTR

#endif /* defined _WIN32 */
#ifdef __cplusplus
extern "C" {
#elif 0
}
#endif
#define CHALLENGE_BYTES 32
#define KEY_BYTES 32
#define RESPONSE_BYTES 32
#define HANDSHAKE_BYTES (CHALLENGE_BYTES + RESPONSE_BYTES)
struct sliprock_pending_connection {
  unsigned char key[KEY_BYTES];
  unsigned char send_buffer[HANDSHAKE_BYTES],
      receive_buffer[HANDSHAKE_BYTES];
  int status;
  bool received_challenge;
  uint8_t received, sent, to_send;
  bool good;
};

int sliprock__poll(struct sliprock_pending_connection *con,
                   sliprock_socket_t fd, int timeout);
SLIPROCK_API int sliprock__init_pending_connection(
    struct sliprock_pending_connection *pending,
    const unsigned char buf[32]);
void sliprock__on_send(struct sliprock_pending_connection *con,
                       size_t size);
int sliprock__on_receive(struct sliprock_pending_connection *con,
                         size_t size);
bool sliprock__connection_is_good(struct sliprock_pending_connection *con);

enum sliprock_status {
  SLIPROCK_MORE_DATA = 1,
  SLIPROCK_COMPLETE = 2,
};
#if 0
{
#elif defined __cplusplus
}
#endif
