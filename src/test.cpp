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
#ifndef BOOST_TEST
#define BOOST_TEST BOOST_CHECK
#endif
//#include <boost/thread.hpp>
#include <stdexcept>
#include <thread>

#ifdef _WIN32
#define address pipename
#endif
//BOOST_AUTO_TEST_SUITE(sliprock_works)
BOOST_AUTO_TEST_CASE(can_create_connection)
{
#ifndef _WIN32
  typedef int HANDLE;
#define INVALID_HANDLE_VALUE (-1)
#endif
  system("rm -rf -- \"$HOME/.sliprock\" /tmp/sliprock.*");
  SliprockConnection *con =
      sliprock_socket("dummy_valq", sizeof("dummy_val") - 1);
  BOOST_REQUIRE(con != nullptr);

  char buf[] = "Test message!";
  char buf2[sizeof buf];
  bool write_succeeded = false, read_succeeded = false;
  std::thread thread([&]() {
    MADE_IT;
    auto handle = (HANDLE)sliprock_accept(con);
    MADE_IT;
    if (handle == INVALID_HANDLE_VALUE)
      return;
    MADE_IT;
#ifndef _WIN32
    if (write(handle, buf, sizeof buf) != sizeof buf)
      return;
    MADE_IT;
    if (read(handle, buf, sizeof buf) != sizeof buf)
      return;
    MADE_IT;
    if (close(handle))
      return;
    MADE_IT;
#else
    DWORD written;
    MADE_IT;
    if (WriteFile(handle, buf, sizeof buf, &written, NULL) == 0)
      return;
    MADE_IT;
    if (written != sizeof buf)
      return;
    MADE_IT;
    if (ReadFile(handle, buf, sizeof buf, &written, NULL) == 0)
      return;
    if (!CloseHandle(handle))
      return;
    MADE_IT;
#endif
    write_succeeded = true;
  });
  HANDLE fd = INVALID_HANDLE_VALUE;
  system("ls -a ~/.sliprock");
  SliprockReceiver *receiver = sliprock_open(
      "dummy_valr", sizeof("dummy_val") - 1, (uint32_t)getpid());
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
  static_assert(sizeof con->address == sizeof receiver->sock,
                "Connection size mismatch");
  BOOST_TEST(memcmp(buf2, buf, sizeof buf) == 0);
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
  BOOST_TEST(receiver != static_cast<SliprockReceiver*>(nullptr));
  if (fd != INVALID_HANDLE_VALUE) {
    MADE_IT;
#ifndef _WIN32
    BOOST_TEST(close(fd) == 0);
#else
    BOOST_TEST(CloseHandle(fd) != 0);
#endif
    thread.join();
    MADE_IT;
  } else {
    thread.detach();
  }
  sliprock_close_receiver(receiver);
  BOOST_TEST(write_succeeded);

  sliprock_close(con);
}
//BOOST_AUTO_TEST_SUITE_END()
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
