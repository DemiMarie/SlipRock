#ifndef STATE_MACHINE_H_INCLUDED
#define STATE_MACHINE_H_INCLUDED STATE_MACHINE_H_INCLUDED
#include <stdint.h>
#include <windows.h>
#include <winsock2.h>
#include <ntsecapi.h>
#define SIZEOF_NONCE 16
#define SIZEOF_HASH 32
#define KEYLEN 32
typedef struct {
  DWORD object_length;
  BCRYPT_ALG_HANDLE sha256provider;
  BCRYPT_ALG_HANDLE rngProvider;
  HANDLE processHeap;
  ULONG sizeOfHasher;
} InitState;

static const InitState *state_machine_init(void);
typedef struct SConnection SConnection;
typedef int (*next_step_fn)(SConnection *con);

typedef struct SConnection {
  uint32_t count;
  enum { CLIENT_HELLO = 28, SERVER_HELLO = 60, CLIENT_REPLY = 32 } state;
  SOCKET fd;
  const InitState *init;
  next_step_fn next_step;
  char key[32];
  uint8_t num_transmitted;
  uint8_t num_received;
  char buf[SERVER_HELLO];
  char storage[SERVER_HELLO];
} SConnection;

struct CConnection {
  char key[KEYLEN];
  unsigned char nonce[SIZEOF_NONCE];
  unsigned char hash[SIZEOF_HASH]
  SOCKADDR_STORAGE sockaddr;
  const InitState *init;
  SOCKET sock;
  enum {
    SLIPROCK_INVALID_STATE,
    SLIPROCK_CONNECTING,
    SLIPROCK_RECEIVING,
    SLIPROCK_AUTHENTICATING,
    SLIPROCK_CONNECTED,
    SLIPROCK_ERROR
  } state;
  uint8_t transmit_length;
  uint8_t receive_length;
  uint8_t transmit_limit;
  uint8_t receive_limit;
  char transmit_buf[NONCELEN + sizeof(SOCKADDR_STORAGE) + HASH_SIZE];
  char receive_buf[NONCELEN + sizeof(SOCKADDR_STORAGE) + HASH_SIZE];
};
int mac_nonce_and_data(struct CConnection *const con,
                       const SOCKADDR_STORAGE *addr,
                       const size_t addr_len,
                       const unsigned char nonce[static SIZEOF_NONCE],
                       unsigned char hash[static SIZEOF_HASH]);
#endif /* !defined STATE_MACHINE_H_INCLUDED */

