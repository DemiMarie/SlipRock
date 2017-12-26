#include "sliprock_poll.h"

typedef ssize_t (*fill_buf_cb)(sliprock_socket_t fd, char *buf,
                               size_t size);
#ifndef MSG_NONBLOCK
#define MSG_NONBLOCK 0
#endif

static ssize_t errno_to_retval(ssize_t retval) {
  return retval < 0 ? -errno : 0 != retval ? retval : -EPROTO;
}

/**
 * Performs a single read from a socket, and updates the connection
 * accordingly.
 */
static sliprock__receive_once(struct sliprock_pending_connection *con,
                              sliprock_socket_t fd) {
  ssize_t res;
  res = errno_to_retval(recv(fd, con->receive_buf + con->received,
                             sizeof(con->receive_buf) - con->received,
                             MSG_DONTWAIT));
  if (res > 0)
    sliprock__on_receive(con, (size_t)res);
  return res;
}

/**
 * Reads from a socket until an error occurs or until the connection is
 * full.
 */
static ssize_t sliprock__receive(struct sliprock_pending_connection *con,
                                 sliprock_socket_t fd) {
  ssize_t res;
  do {
    res = sliprock__receive_once(con, fd);
  } while (res > 0 && con->received < sizeof(con->receive_buf));
}

/**
 * Performs a single send operation on a socket, and updates the connection
 * accordingly.
 */
static sliprock__send_once(struct sliprock_pending_connection *con,
                           sliprock_socket_t fd) {
  ssize_t res = errno_to_retval(
      send(fd, con->send_buf + con->sent, con->to_send, MSG_DONTWAIT));
  if (res > 0)
    sliprock__on_send(con, (size_t)res);
  return res;
}

/**
 * Retrys sending until an error occurs.
 */
static sliprock__send(struct sliprock_pending_connection *con,
                      sliprock_socket_t fd) {
  ssize_t res;
  do {
    res = sliprock__send_once(con, fd);
  } while (res > 0 && con->to_send);
}

/**
 * Should I retry?
 */
static bool do_retry(ssize_t val) {
  switch (val) {
  case -EINTR:
  case -EAGAIN:
  case -EWOULDBLOCK:
    return true;
  default:
    return val > 0;
  }
}

SLIPROCK_API int sliprock_on_poll(short events,
                                  struct sliprock_pending_connection *conn,
                                  sliprock_socket_t fd) {
  ssize_t res = 0;
  int errno_res = 0;
  errno = 0;
  if (events & POLLOUT) {
    res = sliprock__receive(conn, fd);
    assert(res);
    if (!do_retry(res))
      return res;
  }
  if (events & POLLIN)
    res = sliprock__send(conn, fd);
  assert(res);
  return res;
}

/**
 * Connect the socket to the remote peer
 */
int sliprock__poll(struct sliprock_pending_connection *conn,
                   sliprock_socket_t fd, int timeout) {
  sliprock_poll_fd p = {fd, SLIPROCK_POLL_FLAGS, 0};
  for (;;) {
    int res = SLIPROCK_POLL(&p, 1, timeout);
    if (res < 0)
      return -errno;
    else if (!res)
      return -ETIMEDOUT;
    else {
      assert(1 == res);
      if (p.events & POLLERR)
        return -ECONNRESET;
      else {
        res = sliprock_on_poll(p.events);
        assert(res);
        if (!do_retry(res))
          return res;
        if (sliprock__connection_is_good(conn))
          return 0;
        if (con->status)
          return -EPROTO;
      }
    }
  }
}
