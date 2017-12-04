
typedef uint64_t key[4];
struct connection {
  const char magic[16];
  key key, challenge_sent, challenge_received, response_sent,
      response_received;
  int status;
  bool received_challenge;
  uint8_t received, sent, to_send;
};

#define CHALLENGE_BYTES 32
#define RESPONSE_BYTES 32
#define HANDSHAKE_BYTES (CHALLENGE_BYTES + RESPONSE_BYTES)
static int on_receive(struct connection *con, size_t size) {
  int err = -EFAULT;
  /* Did we receive too many bytes? */
  if (con->received > HANDSHAKE_BYTES) {
    assert(!"Received too many bytes - memory corruption detected!");
    abort();
  }
  /* Too many bytes received?  Order matters because of overflow. */
  if (size > HANDSHAKE_BYTES || HANDSHAKE_BYTES - size < con->received)
    return -EFAULT;
  con->received += size;
  assert(con->received > size && "impossible integer overflow");
  if (con->sent < CHALLENGE_BYTES && con->received > CHALLENGE_BYTES) {
    /* Peer cannot possibly have known enough to send response this soon */
    return -EPROTO;
  }
  if (con->received >= CHALLENGE_BYTES && !con->received_challenge) {
    /* Challenge received */
    con->received_challenge = true;
    if ((err = compute_reply(con->key, con->receive_buffer,
                             con->send_buffer + CHALLENGE_BYTES)))
      return err;
    con->to_send += RESPONSE_BYTES;
  }
  if (con->received >= HANDSHAKE_BYTES) {
    /* Handshake complete */
    assert(HANDSHAKE_BYTES == con->received && "Overflow not detected!");
    if ((err = verify_challenge(con->key,
                                con->receive_buffer + CHALLENGE_BYTES,
                                con->send_buffer))) {
      assert(err < 0);
      return err;
      /* Crypto error */
    } else {
      /* Good reply */
      con->good = true;
      return 0;
    }
  }
}

static int sliprock_on_receive(struct connection *con, size_t bytes) {
  int err;
  assert(NULL != con);
  err = on_receive(con, bytes);
  if (err) {
    con->status = err;
    con->to_send = 0;
    return err;
  } else {
    return 0;
  }
}

static int on_send(struct connection *con, size_t size) {
  ASSERT(con);
  ASSERT(con->sent <= HANDSHAKE_BYTES);
  if (size > con->to_send) {
    assert(!"Sent data before it was ready!");
    abort();
  }
  con->sent += size;
  con->to_send -= size;

  if (!con->received_challenge && con->sent > CHALLENGE_BYTES) {
    assert(!"Sent challenge response before receiving challenge!");
    return -EPROTO;
  }
}