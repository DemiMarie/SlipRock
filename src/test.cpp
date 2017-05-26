#include <stdlib.h>

#ifdef _WIN32
#define _UNICODE 1
#define UNICODE 1
#endif

#include "../include/sliprock.h"
#include "sliprock_internals.h"
#include "stringbuf.h"
#include <csignal>
#include <exception>
//#include <gtest/gtest.h>
#define BOOST_TEST_MODULE SlipRock module
#define BOOST_TEST_DYN_LINK
#include <boost/test/unit_test.hpp>
//#include <boost/thread.hpp>
#include <stdexcept>
#include <thread>

#ifdef _WIN32
#define address pipename
#endif
#ifndef BOOST_TEST
#define BOOST_TEST BOOST_CHECK
#endif

bool serve(SliprockConnection *con) {}
// BOOST_AUTO_TEST_SUITE(sliprock_works)

#ifndef _WIN32
typedef int HANDLE;
#define INVALID_HANDLE_VALUE (-1)
#endif
template <size_t size> bool client(char (&buf)[size], SliprockConnection *con) {
  char buf2[size + 1] = {0};
  bool read_succeeded = false;
  HANDLE fd = INVALID_HANDLE_VALUE;
  system("ls -a ~/.sliprock");
  SliprockReceiver *receiver =
      sliprock_open("dummy_valr", sizeof("dummy_val") - 1, (uint32_t)getpid());
  if (receiver == nullptr) {
    perror("sliprock_open");
    goto fail;
  }
  MADE_IT;
  fd = (HANDLE)sliprock_connect(receiver);
  if (fd == INVALID_HANDLE_VALUE) {
    perror("sliprock_connect");
    goto fail;
  }
  MADE_IT;
#ifdef _WIN32
  DWORD read;
  BOOST_TEST(0 != ReadFile(fd, buf2, sizeof buf, &read, nullptr));
  BOOST_TEST(read == sizeof buf);
  BOOST_TEST(0 != WriteFile(fd, buf2, sizeof buf, &read, nullptr));
  BOOST_TEST(read == sizeof buf);
#else
  BOOST_TEST(sizeof buf == read(fd, buf2, sizeof buf));
  BOOST_TEST(sizeof buf == write(fd, buf2, sizeof buf));
#endif
  // static_assert(sizeof buf2 == sizeof buf, "Buffer size mismatch");
  static_assert(sizeof con->address == sizeof receiver->sock,
                "Connection size mismatch");
  BOOST_TEST(memcmp(&buf2[0], &buf[0], sizeof buf) == 0);
  puts(buf);
  puts(buf2);
#ifndef _WIN32
  BOOST_TEST(fd > -1);
#endif
  read_succeeded = true;
fail:
  BOOST_REQUIRE(nullptr != receiver);
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
template <size_t n> bool server(char (&buf)[n], SliprockConnection *con) {
  MADE_IT;
  auto handle = (HANDLE)sliprock_accept(con);
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
  return !memcmp(buf3, buf, sizeof buf);
}
void donothing(int _) { return; }
BOOST_AUTO_TEST_CASE(can_create_connection) {
  struct sigaction sigact;
  memset(&sigact, 0, sizeof sigact);
  sigact.sa_handler = donothing;
  sigemptyset(&sigact.sa_mask);
  sigaddset(&sigact.sa_mask, SIGALRM);
  sigaction(SIGALRM, &sigact, nullptr);
  system("rm -rf -- \"$HOME/.sliprock\" /tmp/sliprock.*");
  SliprockConnection *con =
      sliprock_socket("dummy_valq", sizeof("dummy_val") - 1);
  BOOST_REQUIRE(con != nullptr);

  char buf[] = "Test message!";
  char buf2[sizeof buf] = {0};
  bool write_succeeded = false, read_succeeded = false;
  std::thread thread([&]() {
    if (!(read_succeeded = server(buf, con)))
      perror("sliprock_server");
  });
  std::thread thread2([&]() { write_succeeded = client(buf, con); });
#ifndef _WIN32
  std::thread{[&]() {
    for (;;) {
      struct timespec q = {1, 0};
      nanosleep(&q, nullptr);
      raise(SIGALRM);
    }
  }}.detach();
#endif
  thread.join();
  if (!read_succeeded) {
    thread2.detach();
    throw std::runtime_error("failed to read");
  } else {
    thread2.join();
  }
  BOOST_TEST(write_succeeded);
  BOOST_TEST(read_succeeded);

  sliprock_close(con);
}
// BOOST_AUTO_TEST_SUITE_END()
#if 0
int main(int argc, TCHAR **argv) {
  testing::InitGoogleTest(&argc, argv);
  int code = RUN_ALL_TESTS();
#ifdef _WIN32
  Sleep(INFINITE);
#endif
  return code;
}
#endif
