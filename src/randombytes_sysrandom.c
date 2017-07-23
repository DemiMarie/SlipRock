/*
 * ISC License
 *
 * Copyright (c) 2013-2017
 * Frank Denis <j at pureftpd dot org>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */
/* Taken from libsodium */

#ifdef _MSC_VER
#define __attribute__(x) syntax error !
#endif
/* From utils.h */
#ifndef SODIUM_C99
#if defined(__cplusplus) || !defined(__STDC_VERSION__) ||                 \
    __STDC_VERSION__ < 199901L
#define SODIUM_C99(X)
#else
#define SODIUM_C99(X) X
#endif
#endif
#ifndef _WIN32

__attribute__((warn_unused_result)) static int
randombytes_sysrandom_init(void);

__attribute__((warn_unused_result)) static int
randombytes_sysrandom_stir(void);
__attribute__((warn_unused_result)) static int
randombytes_sysrandom_stir_if_needed(void);
#endif
#ifdef __GLIBC__
#define _GNU_SOURCE
#endif
#include "sliprock.h"
#include "sliprock_internals.h"
#include "stringbuf.h"
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <string.h>
#ifndef _WIN32
#include <unistd.h>
#endif

#include <stdlib.h>
#include <sys/types.h>
#ifndef _WIN32
#include <sys/stat.h>
#include <sys/time.h>
#endif
#ifdef __linux__
#ifdef __dietlibc__
#define _LINUX_SOURCE
#else
#include <sys/syscall.h>
#endif
#include <poll.h>
#endif

//#include "randombytes.h"
//#include "utils.h"

#ifdef _WIN32
/* `RtlGenRandom` is used over `CryptGenRandom` on Microsoft Windows based
 * systems:
 *  - `CryptGenRandom` requires pulling in `CryptoAPI` which causes
 * unnecessary
 *     memory overhead if this API is not being used for other purposes
 *  - `RtlGenRandom` is thus called directly instead. A detailed
 * explanation
 *     can be found here:
 * https://blogs.msdn.microsoft.com/michael_howard/2005/01/14/cryptographically-secure-random-number-on-windows-without-using-cryptoapi/
 */
#include <windows.h>
#define RtlGenRandom SystemFunction036
#if defined(__cplusplus)
extern "C"
#endif
    BOOLEAN NTAPI
    RtlGenRandom(PVOID RandomBuffer, ULONG RandomBufferLength);
#ifdef _MSC_VER
#pragma comment(lib, "advapi32.lib")
#endif
#endif

#if defined(__OpenBSD__) || defined(__CloudABI__)
#define HAVE_SAFE_ARC4RANDOM 1
#endif

#ifndef SSIZE_MAX
#define SSIZE_MAX (SIZE_MAX / 2 - 1)
#endif

#ifdef HAVE_SAFE_ARC4RANDOM

static int randombytes_sysrandom_stir(void) {}

static randombytes_sysrandom_buf(void *const buf, const size_t size) {
  return arc4random_buf(buf, size);
}

static int randombytes_sysrandom_close(void) { return 0; }

#else /* __OpenBSD__ */

typedef struct SysRandom_ {
  int random_data_source_fd;
  int initialized;
  int getrandom_available;
} SysRandom;
#ifndef _WIN32
static SysRandom stream = {SODIUM_C99(.random_data_source_fd =) - 1,
                           SODIUM_C99(.initialized =) 0,
                           SODIUM_C99(.getrandom_available =) 0};

static ssize_t safe_read(const int fd, void *const buf_, size_t size) {
  unsigned char *buf = (unsigned char *)buf_;
  ssize_t readnb;

  assert(size > (size_t)0U);
  assert(size <= SSIZE_MAX);
  do {
    while ((readnb = read(fd, buf, size)) < (ssize_t)0 &&
           (errno == EINTR || errno == EAGAIN))
      ; /* LCOV_EXCL_LINE */
    if (readnb < (ssize_t)0) {
      return readnb; /* LCOV_EXCL_LINE */
    }
    if (readnb == (ssize_t)0) {
      break; /* LCOV_EXCL_LINE */
    }
    size -= (size_t)readnb;
    buf += readnb;
  } while (size > (ssize_t)0);

  return (ssize_t)(buf - (unsigned char *)buf_);
}
#endif

#ifndef _WIN32
#if defined(__linux__) && !defined(USE_BLOCKING_RANDOM) &&                \
    !defined(NO_BLOCKING_RANDOM_POLL)
static int randombytes_block_on_dev_random(void) {
  struct pollfd pfd;
  int fd;
  int pret;

  fd = open("/dev/random", O_RDONLY);
  if (fd == -1) {
    return -1;
  }
  pfd.fd = fd;
  pfd.events = POLLIN;
  pfd.revents = 0;
  do {
    pret = poll(&pfd, 1, -1);
  } while (pret < 0 && (errno == EINTR || errno == EAGAIN));
  if (pret != 1) {
    (void)close(fd);
    errno = EIO;
    return -1;
  }
  return close(fd);
}
#endif
__attribute__((warn_unused_result)) static int
randombytes_sysrandom_random_dev_open(void) {
  /* LCOV_EXCL_START */
  struct stat st;
  static const char *devices[] = {
#ifndef USE_BLOCKING_RANDOM
      "/dev/urandom",
#endif
      "/dev/random", NULL};
  const char **device = devices;
  int fd;

#if defined(__linux__) && !defined(USE_BLOCKING_RANDOM) &&                \
    !defined(NO_BLOCKING_RANDOM_POLL)
  if (randombytes_block_on_dev_random() != 0) {
    return -1;
  }
#endif
  do {
    fd = open(*device, O_RDONLY);
    if (fd != -1) {
      if (fstat(fd, &st) == 0 &&
#ifdef __COMPCERT__
          1
#elif defined(S_ISNAM)
          (S_ISNAM(st.st_mode) || S_ISCHR(st.st_mode))
#else
          S_ISCHR(st.st_mode)
#endif
      ) {
#if defined(F_SETFD) && defined(FD_CLOEXEC)
        (void)fcntl(fd, F_SETFD, fcntl(fd, F_GETFD) | FD_CLOEXEC);
#endif
        return fd;
      }
      (void)close(fd);
    } else if (errno == EINTR) {
      continue;
    }
    device++;
  } while (*device != NULL);

  errno = EIO;
  return -1;
  /* LCOV_EXCL_STOP */
}

#if defined(__dietlibc__) ||                                              \
    (defined(SYS_getrandom) && defined(__NR_getrandom))
static int _randombytes_linux_getrandom(void *const buf,
                                        const size_t size) {
  int readnb;

  assert(size <= 256U);
  do {
#ifdef __dietlibc__
    readnb = getrandom(buf, size, 0);
#else
    readnb = (int)syscall(SYS_getrandom, buf, (int)size, 0);
#endif
  } while (readnb < 0 && (errno == EINTR || errno == EAGAIN));

  return (readnb == (int)size) - 1;
}

static int randombytes_linux_getrandom(void *const buf_, size_t size) {
  unsigned char *buf = (unsigned char *)buf_;
  size_t chunk_size = 256U;

  do {
    if (size < chunk_size) {
      chunk_size = size;
      assert(chunk_size > (size_t)0U);
    }
    if (_randombytes_linux_getrandom(buf, chunk_size) != 0) {
      return -1;
    }
    size -= chunk_size;
    buf += chunk_size;
  } while (size > (size_t)0U);

  return 0;
}
#endif

__attribute__((warn_unused_result)) static int
randombytes_sysrandom_init(void) {
  const int errno_save = errno;

#if defined(SYS_getrandom) && defined(__NR_getrandom)
  {
    unsigned char fodder[16];

    if (randombytes_linux_getrandom(fodder, sizeof fodder) == 0) {
      stream.getrandom_available = 1;
      errno = errno_save;
      return 0;
    }
    stream.getrandom_available = 0;
  }
#endif

  if ((stream.random_data_source_fd =
           randombytes_sysrandom_random_dev_open()) == -1) {
    return -1;
  }
  errno = errno_save;
  return 0;
}

static int randombytes_sysrandom_stir(void) {
  if (stream.initialized == 0) {
    if (randombytes_sysrandom_init() < 0) {
      return -1;
    }
    stream.initialized = 1;
  }
  return 0;
}

static int randombytes_sysrandom_stir_if_needed(void) {
  if (stream.initialized == 0) {
    return randombytes_sysrandom_stir();
  }
  return 0;
}
#ifndef SLIPROCK_NO_THREADS
#include <pthread.h>
static pthread_once_t once = PTHREAD_ONCE_INIT;
#endif
static int is_initialized;
static void init_libsodium(void) {
  is_initialized = randombytes_sysrandom_stir_if_needed();
}

// Initialize libsodium
static int init_func(void) {
#ifndef SLIPROCK_NO_THREADS
  int initialized = pthread_once(&once, &init_libsodium);
#else
  int initialized = init_libsodium();
#endif
  if (initialized) {
    errno = initialized;
    return -1;
  }
  if (is_initialized == -1) {
    return -1;
  }
  return 0;
}

#endif
#if 0
static int
psliprock_randombytes_sysrandom_close(void)
{
    int ret = -1;

#ifndef _WIN32
    if (stream.random_data_source_fd != -1 &&
        close(stream.random_data_source_fd) == 0) {
        stream.random_data_source_fd = -1;
        stream.initialized = 0;
        ret = 0;
    }
#if defined(SYS_getrandom) && defined(__NR_getrandom)
    if (stream.getrandom_available != 0) {
        ret = 0;
    }
#endif
#else /* _WIN32 */
    if (stream.initialized != 0) {
        stream.initialized = 0;
        ret = 0;
    }
#endif
    return ret;
}
#endif
SLIPROCK_WARN_UNUSED_RESULT int
sliprock_randombytes_sysrandom_buf(void *const buf, const size_t size) {
#ifndef _WIN32
  if (init_func() < 0)
    return -1;
#endif
#if defined(ULONG_LONG_MAX) && defined(SIZE_MAX)
#if SIZE_MAX > ULONG_LONG_MAX
  /* coverity[result_independent_of_operands] */
  assert(size <= ULONG_LONG_MAX);
#endif
#endif
#ifndef _WIN32
#if defined(SYS_getrandom) && defined(__NR_getrandom)
  if (stream.getrandom_available != 0) {
    if (randombytes_linux_getrandom(buf, size) != 0) {
      return -1;
    }
    return 0;
  }
#endif
  if (stream.random_data_source_fd == -1 ||
      safe_read(stream.random_data_source_fd, buf, size) !=
          (ssize_t)size) {
    return -1; /* LCOV_EXCL_LINE */
  }
#else
  if (size > (size_t)0xffffffff) {
    return -1; /* LCOV_EXCL_LINE */
  }
  if (!RtlGenRandom((PVOID)buf, (ULONG)size)) {
    return -1; /* LCOV_EXCL_LINE */
  }
#endif
  return 0;
}

#endif /* __OpenBSD__ */

NOINLINE int
sliprock_secure_compare_memory(const volatile unsigned char *const buf1,
                               const volatile unsigned char *const buf2,
                               size_t len) {
  int res = 0;
  const volatile unsigned char *ptr1 = buf1, *ptr2 = buf2;
  size_t i;
  for (i = 0; i < len; ++i)
    res |= ptr1[i] ^ ptr2[i];
  return (1 & ((res - 1) >> 8)) - 1;
}
