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
#include <include/sliprock.h>
#include <pthread.h>
#include <signal.h>
#include <src/sliprock_internals.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

static pthread_mutex_t mutex = PTHREAD_MUTEX_INITIALIZER;
static int verbose = 0;
#define helptxt                                                                \
  "Usage: %s [options] [--] [PID] NAME\n"                                      \
  "\n"                                                                         \
  "Serves one connection (and then exits) on NAME, or\n"                       \
  "(if PID is provided) connects to the pipe NAME with pid PID.\n"             \
  "\n"                                                                         \
  "Options:\n"                                                                 \
  "   -h, -?, --help          print this message\n"                            \
  "   -v, --version           print version information\n"                     \
  "   -V, --verbose           be verbose\n"                                    \
  "   --pid-file=FILE         write PID to FILE\n"                             \
  "   --                      indicates end of options\n"

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

#define check_sliprock(sliprock_retval)                                        \
  do {                                                                         \
    int q = (sliprock_retval);                                                 \
    if (q) {                                                                   \
      fprintf(stderr, "Sliprock call failed: line %d, error %d", __LINE__, q); \
      exit(1);                                                                 \
    }                                                                          \
  } while (0)

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
      goto done;
    for (;;) {
      write_res = write(dst, buf + offset, (size_t)(res - offset));
      if (write_res < 0)
        goto done;
      if (res - offset <= write_res)
        break;
      offset += write_res;
    }
  }
done:
  shutdown(dst, SHUT_WR);
  shutdown(src, SHUT_RD);
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
  if (verbose)
    fprintf(stderr, "Connecting to pid %d with name '%s'\n", pid, name);
  SliprockReceiver *receiver;
  check_sliprock(sliprock_open(name, strlen(name), pid, &receiver));
  if (verbose)
    fputs("Open succeeded", stderr);
  SliprockHandle fd;
  check_sliprock(sliprock_connect(receiver, &fd));
  if ((int)fd < 0)
    fail("sliprock_connect");
  if (verbose)
    fprintf(stderr, "Connection succeeded: fd = %d,\nsocket path = %s\n",
            (int)fd, receiver->prefix.sockaddr.addr.sun_path);
  sliprock_close_receiver(receiver);
  copy_fds((int)fd);
}

static void execute_server(const char *const name) {
  SliprockHandle fd;
  if (verbose)
    fprintf(stderr, "Listening on name %s\n", name);
  struct SliprockConnection *con;
  check_sliprock(sliprock_socket(name, strlen(name), &con));
  if (NULL == con)
    fail("sliprock_socket");
  if (verbose)
    fprintf(stderr, "Listening on socket %s\n",
            con->prefix.sockaddr.addr.sun_path);
  check_sliprock(sliprock_accept(con, &fd));
  if (verbose)
    fprintf(stderr, "Accepted file descriptor %d\n", (int)fd);
  sliprock_close(con);
  copy_fds((int)fd);
}

int main(int argc, char **argv) {
  int res, option_index;
  static const struct option long_options[] = {
      {"version", no_argument, NULL, 'v'},
      {"verbose", no_argument, NULL, 'V'},
      {"help", no_argument, NULL, 'h'},
      {"pid-file", required_argument, NULL, 'p'},
      {0, 0, 0, 0},
  };
  signal(SIGPIPE, SIG_IGN);
  while ((res = getopt_long(argc, argv, ":Vvh?p:", long_options,
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
      puts("SlipRock CLI, version 0.1");
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
