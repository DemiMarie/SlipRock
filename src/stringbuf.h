#ifndef SLIPROCK_STRINGBUF_H_INCLUDED
#define SLIPROCK_STRINGBUF_H_INCLUDED SLIPROCK_STRINGBUF_H_INCLUDED
#ifdef _WIN32
#define TCHAR wchar_t
#else
#define TCHAR char
#endif
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#ifdef NDEBUG
#undef NDEBUG
#endif
#include <assert.h>
struct StringBuf {
  uint16_t buf_length;   // in *TCHARs*
  uint16_t buf_capacity; // in *TCHARs*
  TCHAR buf[];
};

static inline struct StringBuf *
StringBuf_alloc(size_t const buf_capacity) {
  assert(buf_capacity < UINT16_MAX);
  struct StringBuf *val = (struct StringBuf *)calloc(
      sizeof(struct StringBuf) + buf_capacity * sizeof(TCHAR) + 1, 1);
  if (NULL == val)
    return NULL;
  val->buf_capacity = buf_capacity;
  return val;
};

static inline void StringBuf_add_char(struct StringBuf *buf, TCHAR c) {
  assert(buf->buf_capacity > buf->buf_length);
  buf->buf[buf->buf_length++] = c;
}

static inline void StringBuf_add_decimal(struct StringBuf *buf,
                                         uintptr_t value) {
  assert(buf->buf_capacity - buf->buf_length >= 20);
  // int oldlen = buf->buf_length;
  int cap = 0;
  uintptr_t currentval = value;
  do {
    cap++;
    currentval /= 10;
  } while (currentval > 0);
  buf->buf_length += cap;
  int res = buf->buf_length;
  assert(res <= buf->buf_capacity);
  do {
    buf->buf[--res] = '0' + value % 10;
    value /= 10;
  } while (value > 0);
}

static inline void StringBuf_add_hex(struct StringBuf *buf,
                                     uint64_t value) {
  assert(buf->buf_capacity - buf->buf_length >= 8);
  for (int i = 0; i < 64; i += 4) {
    int res = (value >> i & 0xF);
    StringBuf_add_char(buf, res > 9 ? 'a' + res : '0' + res);
  }
}

static inline void StringBuf_add_string(struct StringBuf *buf,
                                        const TCHAR *ptr, size_t len) {
  assert((size_t)(buf->buf_capacity - buf->buf_length) >= len);
  for (uint16_t i = buf->buf_length, j = buf->buf_length + len; i < j;
       ++i) {
    buf->buf[i] = *ptr++;
  }
  buf->buf_length += len;
}

static inline void StringBuf_add_literal(struct StringBuf *buf,
                                         const char *ptr) {
  const size_t len = strlen(ptr);
  assert((size_t)(buf->buf_capacity - buf->buf_length) >= len);
  for (uint16_t i = buf->buf_length, j = buf->buf_length + len; i < j;
       ++i) {
    buf->buf[i] = *ptr++;
  }
  buf->buf_length += len;
}
#endif //! defined SLIPROCK_STRINGBUF_H_INCLUDED
