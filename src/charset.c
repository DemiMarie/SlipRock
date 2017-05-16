#include <stddef.h>
static int sliprock_is_valid_filename(char *buf, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    if (buf[i] < 0x20 || buf > 0x7F)
      return 0;
    switch (buf[i]) {
    case '<':
    case '>':
    case '\\':
    case '/':
    case '"':
    case '?':
    case '*':
    case ':':
      return 0;
    }
  }
  return 1;
}
