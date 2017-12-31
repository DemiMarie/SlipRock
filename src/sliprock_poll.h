#include <assert.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

#ifdef _WIN32

#include <winsock.h>
#include <ws2tcpip.h>
typedef SOCKET sliprock_socket_t;
typedef WSAPOLLFD sliprock_poll_fd;
#define SLIPROCK_API __declspec(dllexport)
#define SLIPROCK_POLL WSAPoll
#define SLIPROCK_POLL_FLAGS (POLLRDNORM | POLLWRNORM)
#define errno (WSAGetLastError())
#define EAGAIN WSAEWOULDBLOCK
#define EWOULDBLOCK WSAEWOULDBLOCK
#define EPROTO WSAEPROTO
#define EINTR WSAEINTR

#else /* !defined _WIN32 */

#define SLIPROCK_API __attribute__((visibility("default")))
#include <errno.h>
#include <poll.h>
#include <stdbool.h>
#include <unistd.h>
typedef int sliprock_socket_t;
typedef struct pollfd sliprock_poll_fd;
#define SLIPROCK_POLL poll
#define SLIPROCK_POLL_FLAGS (POLLIN | POLLOUT)

#endif /* defined _WIN32 */

#define CHALLENGE_BYTES 32
#define RESPONSE_BYTES 32
#define HANDSHAKE_BYTES (CHALLENGE_BYTES + RESPONSE_BYTES)
typedef unsigned char key[32];
struct sliprock_pending_connection {
  key key;
  unsigned char send_buffer[HANDSHAKE_BYTES],
      receive_buffer[HANDSHAKE_BYTES];
  int status;
  bool received_challenge;
  uint8_t received, sent, to_send;
  bool good;
};

int sliprock__poll(struct sliprock_pending_connection *con,
                   sliprock_socket_t fd, int timeout);
int sliprock__init_pending_connection(
    struct sliprock_pending_connection *pending,
    const unsigned char buf[static 32]);
void sliprock__on_send(struct sliprock_pending_connection *con,
                       size_t size);
int sliprock__on_receive(struct sliprock_pending_connection *con,
                         size_t size);
bool sliprock__connection_is_good(struct sliprock_pending_connection *con);
SLIPROCK_API void sliprock_on_send(struct sliprock_pending_connection *con,
                                   size_t bytes);

enum sliprock_status {
  SLIPROCK_MORE_DATA = 1,
  SLIPROCK_COMPLETE = 2,
};
