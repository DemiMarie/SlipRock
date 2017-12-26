#ifdef _WIN32

#include <winsock.h>
#include <ws2tcpip.h>
typedef struct SOCKADDR_STORAGE sliprock_sockaddr_storage_t;
typedef SOCKET sliprock_socket_t;
typedef WSAPOLLFD sliprock_poll_fd;
#define SLIPROCK_POLL WSAPoll
#define SLIPROCK_POLL_FLAGS (POLLRDNORM | POLLWRNORM)

#else /* !defined _WIN32 */

#include <poll.h>
typedef struct sockaddr_storage sliprock_sockaddr_storage_t;
typedef int sliprock_socket_t;
typedef struct pollfd sliprock_poll_fd;
#define SLIPROCK_POLL poll
#define SLIPROCK_POLL_FLAGS (POLLIN | POLLOUT)

#endif /* defined _WIN32 */

#define CHALLENGE_BYTES 32
#define RESPONSE_BYTES 32
#define HANDSHAKE_BYTES (CHALLENGE_BYTES + RESPONSE_BYTES)

int sliprock__on_send(struct sliprock_pending_connection *con,
                      size_t size);
int sliprock__on_receive(struct sliprock_pending_connection *con,
                         size_t size);
bool sliprock__connection_is_good(struct sliprock_pending_connection *con);

typedef uint64_t key[4];
struct sliprock_pending_connection {
  const char magic[16];
  key key;
  char send_buf[HANDSHAKE_BYTES], receive_buf[HANDSHAKE_BYTES];
  int status;
  bool received_challenge;
  uint8_t received, sent, to_send;
};

enum sliprock_status {
  SLIPROCK_MORE_DATA = 1,
  SLIPROCK_COMPLETE = 2,
}
