
#ifdef _WIN32
#define _UNICODE 1
#define UNICODE 1
#endif
#define BOOST_TEST_MODULE SlipRock module
#ifdef _MSC_VER
#include <boost/test/included/unit_test.hpp>
#else
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
#endif

#include "../include/sliprock.h"
#include "sliprock_internals.h"
#include "stringbuf.h"
#include <csignal>
#include <exception>
#include <mutex>
#include <stdexcept>
#include <stdlib.h>
#include <thread>
#include <type_traits>

#ifdef _WIN32
#define address pipename
#include <windows.h>
#endif
#ifndef BOOST_TEST
#define BOOST_TEST BOOST_CHECK
#endif

#ifndef _WIN32
typedef int HANDLE;
#include <pthread.h>
#define INVALID_HANDLE_VALUE (-1)
#endif
static uint32_t sliprock_getpid(void) {
#ifdef _WIN32
  return GetCurrentProcessId();
#else
  return (uint32_t)getpid();
#endif
}
struct set_on_close {
  set_on_close(std::mutex &m, bool &b) : boolean(b), mut(m) {}
  ~set_on_close() {
    std::unique_lock<std::mutex> locker{mut};
    boolean = true;
  }

private:
  bool &boolean;
  std::mutex &mut;
};
template <size_t size>
bool client(char (&buf)[size], SliprockConnection *con, bool &finished,
            std::mutex &mutex) {
  set_on_close closer(mutex, finished);
  char buf2[size + 1] = {0};
  bool read_succeeded = false;
  SliprockHandle fd_ = (SliprockHandle)INVALID_HANDLE_VALUE;
#ifndef _WIN32
  BOOST_TEST(system("ls -a ~/.sliprock") == 0);
#endif
  SliprockReceiver *receiver;
  int x = sliprock_open("dummy_valr", sizeof("dummy_val") - 1,
                        sliprock_getpid(), &receiver);
  BOOST_TEST(x == 0);
  BOOST_REQUIRE(x == 0);
  MADE_IT;
  x = sliprock_connect(receiver, &fd_);
  BOOST_TEST(x == 0);
  BOOST_REQUIRE(x == 0);
  MADE_IT;
  HANDLE fd = (HANDLE)fd_;
#ifdef _WIN32
  DWORD read;
  BOOST_TEST(0 != ReadFile(fd, buf2, sizeof buf, &read, nullptr));
  BOOST_TEST(read == sizeof buf);
  BOOST_TEST(0 != WriteFile(fd, buf2, sizeof buf, &read, nullptr));
  BOOST_TEST(read == sizeof buf);
  FlushFileBuffers(fd);
#else
  if (fd >= 0) {
    BOOST_TEST(sizeof buf == read(fd, buf2, sizeof buf));
    BOOST_TEST(sizeof buf == write(fd, buf2, sizeof buf));
  }
#endif
  // static_assert(sizeof buf2 == sizeof buf, "Buffer size mismatch");
  static_assert(sizeof con->address == sizeof receiver->sock,
                "Connection size mismatch");
  BOOST_TEST(memcmp(&buf2[0], &buf[0], sizeof buf) == 0);
  fwrite(buf, 1, sizeof buf, stderr);
  fwrite(buf2, 1, sizeof buf2, stderr);
#ifndef _WIN32
  BOOST_TEST((int)fd > -1);
#endif
  read_succeeded = true;
  BOOST_TEST(0 == memcmp(reinterpret_cast<void *>(&receiver->sock),
                         reinterpret_cast<void *>(&con->address),
                         sizeof con->address));
  BOOST_TEST(read_succeeded == true);
  BOOST_TEST(receiver != static_cast<SliprockReceiver *>(nullptr));
#ifndef _WIN32
  BOOST_TEST(close(fd) == 0);
#else
  BOOST_TEST(CloseHandle(fd) != 0);
#endif
  sliprock_close_receiver(receiver);
  return read_succeeded;
}

template <size_t n>
bool server(char (&buf)[n], SliprockConnection *con, bool &finished,
            std::mutex &mutex) {
  set_on_close closer(mutex, finished);
  MADE_IT;
  SliprockHandle handle_;
  int err = sliprock_accept(con, &handle_);
  if (err != 0) {
    fprintf(stderr, "error code %d\n", err);
    return false;
  }
  auto handle = (HANDLE)handle_;
  MADE_IT;
  if (handle == INVALID_HANDLE_VALUE)
    return false;
  MADE_IT;
  char buf3[sizeof buf];
#ifndef _WIN32
  if (write(handle, buf, sizeof buf) != sizeof buf)
    return false;
  MADE_IT;
  if (read(handle, buf3, sizeof buf) != sizeof buf)
    return false;
  MADE_IT;
  if (close(handle))
    return false;
  MADE_IT;
#else
  DWORD written;
  MADE_IT;
  if (WriteFile(handle, buf, sizeof buf, &written, NULL) == 0)
    return false;
  if (!FlushFileBuffers(handle))
    return false;
  MADE_IT;
  if (written != sizeof buf3)
    return false;
  MADE_IT;
  if (ReadFile(handle, buf3, sizeof buf3, &written, NULL) == 0)
    return false;
  if (!CloseHandle(handle))
    return false;
  MADE_IT;
#endif
  bool x = !memcmp(buf3, buf, sizeof buf);
  finished = true;
  return x;
}
#ifndef _WIN32
static void donothing(int _) {
  (void)_;
  return;
}
static_assert(std::is_same<std::thread::native_handle_type, pthread_t>(),
              "Mismatched native handle type!");
#elif 0
static_assert(std::is_same<std::thread::native_handle_type, HANDLE>(),
              "Mismatched native handle type!");
#endif
// Interrupt a thread IF read_done is true, ensuring that lock is held
// when reading its value.
static void interrupt_thread(std::mutex &lock, const bool &read_done,
                             std::thread &thread) {
  std::unique_lock<std::mutex> locker(lock);
  if (!read_done) {
#ifndef _WIN32
    static_assert(
        std::is_same<std::thread::native_handle_type, pthread_t>::value,
        "Bad native handle type");
    pthread_kill(thread.native_handle(), SIGPIPE);
#elif _MSC_VER
    static_assert(
        std::is_same<std::thread::native_handle_type, HANDLE>::value,
        "Bad native handle type");
    CancelSynchronousIo(thread.native_handle());
#else
    (void)thread;
#endif
  }
}
BOOST_AUTO_TEST_CASE(can_create_connection) {
#ifndef _WIN32
  struct sigaction sigact;
  memset(&sigact, 0, sizeof sigact);
  sigact.sa_handler = donothing;
  sigemptyset(&sigact.sa_mask);
  sigaddset(&sigact.sa_mask, SIGPIPE);
  sigaction(SIGPIPE, &sigact, nullptr);
  BOOST_TEST(system("rm -rf -- \"$HOME/.sliprock\" /tmp/sliprock.*") == 0);
#endif
  SliprockConnection *con = nullptr;
  int x = sliprock_socket("dummy_val", sizeof("dummy_val") - 1, &con);
  BOOST_TEST(x == 0);
  BOOST_REQUIRE(x == 0);

  std::mutex lock, lock2;
  bool read_done = false, write_done = false;
  char buf[] = "Test message!\n";
  bool write_succeeded = false, read_succeeded = false;
  std::thread thread([&]() {
    if (!(read_succeeded = server(buf, con, read_done, lock2)))
      perror("sliprock_server");
  });
  std::thread thread2(
      [&]() { write_succeeded = client(buf, con, write_done, lock); });
  auto interrupter = std::thread{[&]() {
#ifndef _WIN32
    struct timespec q = {1, 0};
    nanosleep(&q, nullptr);
#else
    sliprock_trace("Calling Sleep()\n");
    Sleep(10000000);
#endif
    sliprock_trace("Interrupting thread\n");
    interrupt_thread(lock2, read_done, thread);
    interrupt_thread(lock, write_done, thread2);
  }};
  thread.join();
  thread2.join();
#ifdef _WIN32
  interrupter.detach();
#else
  interrupter.join();
#endif
  BOOST_TEST(write_succeeded);
  BOOST_TEST(read_succeeded);

  sliprock_close(con);
}
// BOOST_AUTO_TEST_SUITE_END()
