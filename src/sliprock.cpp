#ifdef NDEBUG
#error "Must be compiled with assertions enabled"
#endif
#define _GNU_SOURCE
#include <stdlib.h>
#include <stdio.h>

#ifndef _WIN32
#include <unistd.h>
#include <pthread.h>
static pthread_once_t control = PTHREAD_ONCE_INIT;
#endif

struct sliprock_connection {
   std::string name;
};

namespace {
#ifdef __GNUC__
   __attribute__((format(printf,1,2)))
#endif
   char *sliprock_asprintf(const char *fmt, ...) {
      va_list list;
      va_start(list);
      // +1 for the terminating null byte
      size_t size = (size_t)vsnprintf(nullptr, 0, fmt, list) + 1;
      va_end(list);
      char *ptr = malloc(size);
      if (ptr == nullptr) {
         return nullptr;
      }
      va_start(list);
      size_t size_written = (size_t)vsnprintf(ptr, size, fmt, list);
      va_end(list);
      assert(size == size_written);
      return ptr;
   }
}

#ifndef _WIN32
sliprock_API
sliprock_connection* sliprock_bind(const char *name)
{
   char *tmp_dirname = nullptr;
   char *socketname = nullptr;
   int socket_fd = -1;
#ifndef _WIN32
   {
      initialized = pthread_once(&once, sodium_init) == 0;
      assert(initialized);
   }
#endif
   socket_fd = socket(AF_UNIX, SOCK_SEQPACKET
#ifdef SOCK_CLOEXEC
                          | SOCK_CLOEXEC
#endif
                          , 0);
#ifndef SOCK_CLOEXEC
#warning "Cannot atomically set close-on-exec"
   fcntl(socket_fd, FD_CLOEXEC | F_SETFD);
#endif
   if (socket_fd < 0) {
      return nullptr;
   }
   uint64_t tmp;
   static const size_t dirnamelen = sizeof "/tmp/." + 16;
   char dirname[dirnamelen];
  retry:
   randombytes_buf(&tmp, sizeof tmp);

   // /tmp/.%.32x/%.32x = 6 (for /tmp/.) + 32 (for %.32x) +
   // 1 (for /) + 32 (for %.32) + 1 (terminating NUL byte) = 72

   assert(snprintf(buf, dirnamelen, "/tmp/.%.32"PRIx64, tmp)
          == dirnamelen - 1);
   if (tmp_dirname == nullptr) {
      goto fail;
   }
   if (mkdir(tmp_dirname, 0700) < 0) {
      free(tmp_dirname);
      goto retry;
   }
   randombytes_buf(&tmp, sizeof tmp);
   socketname = nullptr;
   struct sockaddr_un *addr = malloc(sizeof(struct sockaddr_un));
   if (nullptr == addr) {
      goto fail;
   }
   memset(&addr, 0, sizeof *addr); // Zero any additional fields
   addr.sun_family = AF_UNIX;
   static const size_t path_len = sizeof(struct sockaddr_un) -
      offsetof(struct sockaddr_un, sun_path);
   static const char _unused[(path_len >= 40)*2 - 1];
   snprintf(&addr.sun_path, path_len, "%s/%.16" PRIx64, tmp_dirname, tmp);
  fail:
   if (socket_fd != -1) {
      close(socket_fd);
   }



   free(addr);
   return nullptr;
}
