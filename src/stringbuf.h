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

#include "sliprock_internals.h"
struct StringBuf {
  uint16_t buf_length;   /**< in *TCHARs* */
  uint16_t buf_capacity; /**< in *TCHARs* */
  TCHAR buf[];
};

static struct StringBuf *StringBuf_alloc(size_t const buf_capacity) {
  struct StringBuf *val;
  assert(buf_capacity < UINT16_MAX);
  CHECK_FUEL(return NULL);
  val = (struct StringBuf *)calloc(
      sizeof(struct StringBuf) + buf_capacity * sizeof(TCHAR) + 1, 1);
  if (NULL == val)
    return NULL;
  val->buf_capacity = (uint16_t)buf_capacity;
  return val;
}

static void StringBuf_add_char(struct StringBuf *buf, TCHAR c) {
  assert(buf->buf_capacity > buf->buf_length);
  buf->buf[buf->buf_length++] = c;
}

static void StringBuf_add_decimal(struct StringBuf *buf, uintptr_t value) {
  /* int oldlen = buf->buf_length; */
  int cap = 0, res;
  uintptr_t currentval = value;
  assert(buf->buf_capacity - buf->buf_length >= 20);
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
}
#if 0
static void StringBuf_add_hex(struct StringBuf *buf,
                                     uint64_t value) {
  int i;
  assert(buf->buf_capacity - buf->buf_length >= 8);
  for (i = 0; i < 64; i += 4) {
    int res = (value >> i & 0xF);
    StringBuf_add_char(buf, (char)(res > 9 ? 'a' + res : '0' + res));
  }
}
#endif
static void StringBuf_add_string(struct StringBuf *buf, const TCHAR *ptr,
                                 size_t len) {
  uint16_t i, j;
  assert((size_t)(buf->buf_capacity - buf->buf_length) >= len);
  for ((void)(i = buf->buf_length), j = (uint16_t)(buf->buf_length + len);
       i < j; ++i) {
    buf->buf[i] = *ptr++;
  }
  buf->buf_length += len;
}

static void StringBuf_add_literal(struct StringBuf *buf, const char *ptr) {
  uint16_t i, j;
  const size_t len = strlen(ptr);
  assert((size_t)(buf->buf_capacity - buf->buf_length) >= len);
  for (i = buf->buf_length, j = buf->buf_length + (uint16_t)len; i < j;
       ++i) {
    buf->buf[i] = *ptr++;
  }
  buf->buf_length += len;
}
#endif /*! defined SLIPROCK_STRINGBUF_H_INCLUDED*/
