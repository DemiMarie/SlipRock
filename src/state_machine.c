#include "SHA256.h"
#include "sliprock_internals.h"
#include "sliprock_poll.h"
#include <sliprock.h>
#include <sliprock/config.h>
#include <stdio.h>
static void compute_reply(const unsigned char key[static 32],
                          const unsigned char challenge[static 32],
                          unsigned char hash[static 32]) {
  hash_state st;
  sliprock__SHA256_init(&st);
  sliprock__SHA256_process(&st, key, 32);
  sliprock__SHA256_process(&st, challenge, 32);
  sliprock__SHA256_done(&st, hash);
}

static bool verify_challenge(const unsigned char key[static 32],
                             const unsigned char reply[static 32],
                             const unsigned char challenge[static 32]) {
  unsigned char buf[32];
  compute_reply(key, challenge, buf);
  return !sliprock_secure_compare_memory(buf, reply, sizeof buf);
}

int sliprock__init_pending_connection(
    struct sliprock_pending_connection *pending,
    const unsigned char buf[static 32]) {
  SLIPROCK_STATIC_ASSERT((sizeof pending->key == 32));
  memset(pending, 0, sizeof(*pending));
  if (sliprock_randombytes_sysrandom_buf(pending->send_buffer,
                                         CHALLENGE_BYTES))
    abort();
  pending->to_send = CHALLENGE_BYTES;
  memcpy(pending->key, buf, sizeof pending->key);
  return 0;
}

static int on_receive(struct sliprock_pending_connection *con,
                      size_t size) {
  int err = -EFAULT;
  /* Did we receive too many bytes? */
  if (con->received > HANDSHAKE_BYTES) {
    assert(!"Received too many bytes - memory corruption detected!");
    abort();
  }
  /* Too many bytes received?  Order matters because of overflow. */
  if (size > HANDSHAKE_BYTES || HANDSHAKE_BYTES - size < con->received)
    return -EFAULT;
  assert(size <= 255);
/* #define SLIPROCK_DO_TRACE */
#ifdef SLIPROCK_DO_TRACE
  fprintf(stderr, "Got %d bytes\n", (int)size);
#endif
  assert(255U - con->received >= size);
  con->received += size;
  assert(con->received >= size && "impossible integer overflow");
  if (con->sent < CHALLENGE_BYTES && con->received > CHALLENGE_BYTES) {
  /* Peer cannot possibly have known enough to send response this soon */
#ifdef SLIPROCK_DO_TRACE
    fprintf(stderr, "Peer sent response too soon!\n");
#endif
    return -EPROTO;
  }
  if (con->received >= CHALLENGE_BYTES && !con->received_challenge) {
    /* Challenge received */
    con->received_challenge = true;
    compute_reply(con->key, con->receive_buffer,
                  con->send_buffer + CHALLENGE_BYTES);
    con->to_send += RESPONSE_BYTES;
  }
  if (con->received >= HANDSHAKE_BYTES) {
    /* Handshake complete */
    assert(HANDSHAKE_BYTES == con->received && "Overflow not detected!");
    if ((err = !verify_challenge(con->key,
                                 con->receive_buffer + CHALLENGE_BYTES,
                                 con->send_buffer))) {
      return -EPROTO;
      /* Crypto error */
    } else {
      /* Good reply */
      con->good = true;
      return 0;
    }
  }
  return 0;
}

int sliprock__on_receive(struct sliprock_pending_connection *con,
                         size_t bytes) {
  int err;
  assert(NULL != con);
  err = on_receive(con, bytes);
  if (err) {
    con->status = err;
    /* This is wrong because it could trip an assert in on_send */
    /* con->to_send = 0; */
    return err;
  } else {
    return 0;
  }
}

SLIPROCK_API void
sliprock_on_send(struct sliprock_pending_connection *pending, size_t *size,
                 const void **buf) {
  size_t size_;
  assert(NULL != size);
  assert(NULL != buf);
  size_ = *size;
  if (size_) {
    sliprock__on_send(pending, size_);
  }
  *size = pending->to_send;
  *buf = pending->send_buffer + pending->sent;
}

SLIPROCK_API int
sliprock_on_receive(struct sliprock_pending_connection *con, size_t *size,
                    void **buf) {
  size_t size_;
  int retval;
  assert(NULL != size);
  assert(NULL != buf);
  size_ = *size;
  retval = size_ ? sliprock__on_receive(con, size_) : 0;
  *size = sizeof(con->receive_buffer) - con->received;
  *buf = con->receive_buffer + con->received;
  return retval;
}

bool sliprock__connection_is_good(
    struct sliprock_pending_connection *con) {
  return con->good && HANDSHAKE_BYTES == con->sent &&
         HANDSHAKE_BYTES == con->received;
}

void sliprock__on_send(struct sliprock_pending_connection *con,
                       size_t size) {
  assert(con);
  assert(con->sent <= HANDSHAKE_BYTES);
  assert(size <= con->to_send && "Sent data before it was ready!");
  con->sent += size;
  con->to_send -= size;

  assert((con->received_challenge || con->sent <= CHALLENGE_BYTES) &&
         "Sent challenge response before receiving challenge!");
}
