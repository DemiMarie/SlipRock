#ifndef SLIPROCK_STRINGBUF_H_INCLUDED
#define SLIPROCK_STRINGBUF_H_INCLUDED SLIPROCK_STRINGBUF_H_INCLUDED
#ifdef __cplusplus
extern "C" {
#endif

#include <limits.h>
#include <stddef.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>

#ifdef _WIN32
#define UNICODE
#define _UNICODE
#include <windows.h>
#else
typedef char TCHAR;
#endif

struct StringBuf {
  TCHAR *buf;
  const uint16_t buf_capacity; /**< in *TCHARs* */
  uint16_t buf_length;         /**< in *TCHARs* */
};

static inline void StringBuf_init(struct StringBuf *buf,
                                  size_t const buf_capacity,
                                  size_t const buf_length,
                                  TCHAR *const buf_ptr) {
  assert(buf_capacity < 65535);
  assert(buf_length <= buf_capacity);
  struct StringBuf buf_ = {
      buf_ptr, (uint16_t)buf_capacity, (uint16_t)buf_length,
  };
  memcpy(buf, &buf_, sizeof buf_);
}

__attribute__((warn_unused_result)) static inline int
StringBuf_alloc(size_t const buf_capacity, struct StringBuf *const buf) {
  assert(buf_capacity < UINT16_MAX);
  TCHAR *val = (TCHAR *)calloc(buf_capacity, sizeof(TCHAR));
  if (NULL == val)
    return -1;
  struct StringBuf retval = { val, (uint16_t)buf_capacity, 0, };
  memcpy(buf, &retval, sizeof retval);
  return 0;
}

static inline void StringBuf_add_char(struct StringBuf *buf, TCHAR c) {
  assert(buf->buf_capacity > buf->buf_length + 1);
  buf->buf[buf->buf_length++] = c;
  buf->buf[buf->buf_length + 1] = '\0';
}

static inline void StringBuf_add_decimal(struct StringBuf *buf,
                                         uintptr_t value) {
  /* int oldlen = buf->buf_length; */
  int cap = 0, res;
  uintptr_t currentval = value;
  assert(buf->buf_capacity - buf->buf_length >= 21);
  do {
    cap++;
    currentval /= 10;
  } while (currentval > 0);
  buf->buf_length += cap;
  res = buf->buf_length;
  assert(res <= buf->buf_capacity);
  do {
    buf->buf[--res] = '0' + value % 10;
    value /= 10;
  } while (value > 0);
  buf->buf[buf->buf_length] = '\0';
}
static inline void StringBuf_add_hex(struct StringBuf *buf, uint64_t value) {
  int i;
  assert(buf->buf_capacity - buf->buf_length >= 9);
  for (i = 0; i < 64; i += 4) {
    int res = (value >> i & 0xF);
    StringBuf_add_char(buf, (char)(res > 9 ? 'a' + res : '0' + res));
  }
}
#define StringBuf_add_literal(x, y)                                            \
  (StringBuf_add_string((x), ("" y), sizeof(y) - 1))
static inline void StringBuf_add_string(struct StringBuf *buf, const TCHAR *ptr,
                                        size_t len) {
  uint16_t i, j;
  assert(len != SIZE_MAX);
  assert((size_t)(buf->buf_capacity - buf->buf_length) >= len);
  for ((void)(i = buf->buf_length), j = (uint16_t)(buf->buf_length + len);
       i < j; ++i) {
    buf->buf[i] = *ptr++;
  }
  buf->buf_length += len;
}
#ifdef __cplusplus
}
#endif
#endif /*! defined SLIPROCK_STRINGBUF_H_INCLUDED*/
