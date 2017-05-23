#include "../state_machine.h"
#include <assert.h>
#include <sliprock_windows.h>
#include <string.h>
typedef struct { char address[6]; } con_info;
#ifndef STATUS_SUCCESS
#define STATUS_SUCCESS 0
#endif
#ifndef IGNORE
#define IGNORE(x) ((void)0)
#endif
#define MAX(x, y)                                                              \
  (IGNORE(asd##x##1234), IGNORE(asd##y##1234), (x) > (y) ? (x) : (y))
int get_client_hello(SConnection *con, char *const buf, size_t *const length) {
  PUCHAR hasher = NULL;
  assert(con->state == CLIENT_HELLO);
  const size_t blength = *length;
  /* NOTE avoid integer overflow vulnerability */
  if (CLIENT_HELLO - con->count < blength)
    return 0;
  memcpy(con->storage + con->count, buf, blength);
  con->count += blength;
  if (con->count == con->state) {
    /* Ready to proceed! */
    return (con->next_step)(con);
  }
  return 1;
}
static void append_to_buf(struct CConnection *con, void *buf, size_t size) {
  assert(sizeof con->transmit_buf - con->transmit_length > size);
  memcpy(con->transmit_buf, buf, size);
  con->transmit_limit += size;
}
static int ccon_init(struct CConnection *con) {
  ZeroMemory(con, sizeof *con); /* also zeros out the SOCKADDR_STORAGE struct */
  const InitState *init = con->init = state_machine_init();
  if (!init)
    return 0;
  if (BCryptGenRandom(init->rngProvider, con->nonce, SIZEOF_NONCE, 0) !=
      STATUS_SUCCESS)
    return 0;
  append_to_buf(con, con->nonce, SIZEOF_NONCE);
  con->transmit_limit = SIZEOF_NONCE;
  con->receive_limit = SIZEOF_NONCE + sizeof(SOCKADDR_STORAGE);
  WSASetLastError(0);
  SOCKET sock = con->sock = socket(AF_INET, SOCK_STREAM, 0);
  if (WSAGetLastError())
    return 0;
  con->state = SLIPROCK_CONNECTING;
  return 1;
}

static int ccon_connected(struct CConnection *con) {
  int size = sizeof con->sockaddr;
  ZeroMemory(&con->sockaddr, sizeof con->sockaddr);
  if (!getsockname(con->sock, (struct sockaddr *)&con->sockaddr, &size))
    return con->state = SLIPROCK_ERROR;
  append_to_buf(con, &con->sockaddr, sizeof con->sockaddr);
}

static int ccon_transmit(struct CConnection *con, size_t *count) {
  if (SLIPROCK_ERROR == con->state)
    return con->state;
  if (con->transmit_limit - con->transmit_length < *count)
    return con->state = SLIPROCK_ERROR;
  else
    con->transmit_length += *count;
  return 0;
}

static int sliprock_receive(struct CConnection *const con, const size_t count) {
  const size_t old_size = con->receive_length;
  if (con->receive_limit - old_size < count)
    return con->state = SLIPROCK_ERROR;
  const size_t new_size = con->receive_length = old_size + count;
  if (con->state == SLIPROCK_RECEIVING) {
    /* Check if we passed the threshold and can compute the HMAC */
    if (con->receive_length >= sizeof(SOCKADDR_STORAGE) + SIZEOF_NONCE) {
      /* We can */
      const unsigned char *const nonce = con->receive_buf;
      const unsigned char *const sockaddr = con->receive_buf + SIZEOF_NONCE;
      unsigned char *const peerhash =
          con->receive_buf + SIZEOF_NONCE + sizeof(SOCKADDR_STORAGE);
      assert(con->state == SLIPROCK_RECEIVING);
      SOCKADDR_STORAGE storage;
      ZeroMemory(&storage, sizeof storage);
      /* Get the peer name */
      int sizeof_storage = sizeof storage;
      if (!getpeername(con->sock, (struct sockaddr *)&storage, &sizeof_storage))
        return 0;
      /* Check that we are connected directly to the peer */
      if (secure_compare_memory(&storage, sockaddr, sizeof storage)) {
        /* Bogus remote - we are being MITMd */
        WSASetLastError(WSAEPERM);
        goto fail;
      }
      if (!mac_nonce_and_data(con, &con->sockaddr, sizeof storage, nonce,
                              peerhash))
        goto fail;
      if (!mac_nonce_and_data(con, &storage, sizeof storage, con->nonce,
                              con->hash))
        goto fail;
      con->receive_limit += SIZEOF_HASH;
      con->transmit_limit += SIZEOF_HASH;
    }
    con->state = SLIPROCK_AUTHENTICATING;
  }
  if (SLIPROCK_AUTHENTICATING == con->state &&
      con->receive_length == sizeof con->receive_buf) {
    if ((con->receive_buf + SIZEOF_NONCE + sizeof(SOCKADDR_STORAGE), con->hash,
         SIZEOF_HASH)) {
      goto fail;
    }
    con->state = SLIPROCK_CONNECTED;
  }
  return con->state;
fail:
  return con->state = SLIPROCK_ERROR;
}
/**
 * <h2>CLIENT CONNECTION SEQUENCE:</h2>
 * <p>
 * <ol>
 * <li>Send a 16-byte nonce N, followed by a SOCKADDR_STORAGE struct
 * filled with the contents of the local address.  Uninitialized members
 * must be zeroed</li>
 * <li>
 */
