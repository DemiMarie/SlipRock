#ifdef __GLIBC__
#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored - Wreserved - id - macro
#endif
#define _GNU_SOURCE
#ifdef __clang__
#pragma clang diagnostic pop
#endif
#endif
#include <ctype.h>
#include <errno.h>
#include <getopt.h>
#include <pthread.h>
#include <sliprock.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static const char *const helptxt =
    "Usage: %s [options] [--] [peer pid] name\n"
    "\n"
    "Serves one connection (and then exits) on _name_, or\n"
    " (if _pid_ is provided) connects to the pipe _name_ with pid _pid_.\n"
    "\n"
    "Options:\n"
    "   -h, -?, --help          print this message\n"
    "   -v, --version           print version information\n"
    "   -V, --verbose           be verbose\n"
    "   --pid-file=FILE         write PID to FILE\n"
    "   --                      indicates end of options\n";

__attribute__((noreturn)) static void stdout_error(void) {
  fflush(stdout);
  if (ferror(stdout)) {
    perror("I/O error");
    exit(1);
  }
  exit(0);
}

__attribute__((noreturn)) static void usage(int argc, char **argv) {
  fprintf(stdout, helptxt, argc != 0 ? argv[0] : "sliprock");
  stdout_error();
}

typedef struct {
  int src;
  int dst;
} fd_pair;

#define fail(str)                                                              \
  do {                                                                         \
    perror(str);                                                               \
    pthread_mutex_lock(&mutex);                                                \
    exit(1);                                                                   \
  } while (0)

static void *do_copy(void *arg) {
  const fd_pair pair = *(fd_pair *)arg;
  const int src = pair.src, dst = pair.dst;
  char buf[8192];
  ssize_t res;
  while ((res = read(src, buf, sizeof buf))) {
    ssize_t offset = 0;
    ssize_t write_res;
    if (res < 0)
      fail("read");
    for (;;) {
      write_res = write(dst, buf + offset, (size_t)(res - offset));
      if (write_res < 0)
        fail("write");
      if (res - offset <= write_res)
        break;
      offset += write_res;
    }
  }
  shutdown(dst, SHUT_WR);
  return NULL;
}
static void copy_fds(int fd) {
  pthread_attr_t attr;
  pthread_t thread;
  void *res;
  fd_pair q = {.src = 0, .dst = fd}, q2 = {.src = fd, .dst = 1};
  int err;
  if (pthread_attr_init(&attr) != 0)
    fail("pthread_attr_init");
  if ((err = pthread_create(&thread, &attr, &do_copy, &q))) {
    errno = err;
    fail("pthread_create");
  }
  do_copy(&q2);
  pthread_join(thread, &res);
}

static void execute_client(const uint32_t pid, const char *const name) {
  SliprockReceiver *receiver = sliprock_open(name, strlen(name), pid);
  if (NULL == receiver)
    fail("sliprock_open");
  int fd = (int)sliprock_connect(receiver);
  if (fd < 0)
    fail("sliprock_connect");
  sliprock_close_receiver(receiver);
  copy_fds(fd);
}

static void execute_server(const char *const name) {
  struct SliprockConnection *con = sliprock_socket(name, strlen(name));
  if (NULL == con)
    fail("sliprock_socket");
  int fd = (int)sliprock_accept(con);
  if (fd < 0)
    perror("sliprock_accept");
  sliprock_close(con);
  copy_fds(fd);
}

int main(int argc, char **argv) {
  int verbose = 0;
  int res, option_index;
  static const struct option long_options[] = {
      {"version", no_argument, NULL, 'v'},
      {"verbose", no_argument, NULL, 'V'},
      {"help", no_argument, NULL, 'h'},
      {"pid-file", required_argument, NULL, 'p'},
      {0, 0, 0, 0},
  };
  while ((res = getopt_long(argc, argv, ":vh?p:", long_options,
                            &option_index)) != -1) {
    switch (res) {
    case ':':
      return 1;
    case 'V':
      verbose = 1;
      break;
    case 'h':
    case '?':
      usage(argc, argv);
    case 'v':
      puts("SlipRock interactive client/server, version 0.1");
      stdout_error();
    case 'p': {
      FILE *f = fopen(optarg, "w");
      if (!f)
        fail("fopen");
      if (fprintf(f, "%d", getpid()) < 0)
        fail("fprintf");
      if (fflush(f) < 0)
        fail("fflush");
      if (ferror(f))
        fail("ferror");
      fclose(f);
      break;
    }
    default:
      abort();
    }
  }
  const char *curopt = argv[optind];
  char *endptr;
  unsigned long val;
  switch (argc - optind) {
  case 2:
    errno = 0;
    if (*curopt > '9' || *curopt < '0')
      usage(argc, argv);
    val = strtoul(curopt, &endptr, 0);
    if (errno || val > UINT32_MAX || *endptr)
      usage(argc, argv);
    execute_client((uint32_t)val, argv[optind + 1]);
    return 0;
  case 1:
    execute_server(curopt);
    return 0;
  default:
    usage(argc, argv);
  }
}