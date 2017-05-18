#ifdef _WIN32
#define _UNICODE _UNICODE
#define UNICODE UNICODE
#define main _wmain
#else
#define TCHAR char
#endif
#include "sliprock.h"
#include "sliprock_internals.h"
#include <csignal>
#include <exception>
#include <stdexcept>
#include <gtest/gtest.h>
#include <thread>

#ifdef _WIN32
#define address pipename
#endif
TEST(CanCreateConnection, ItWorks) {
#ifndef _WIN32
  typedef int HANDLE;
#define INVALID_HANDLE_VALUE (-1)
#endif
  system("rm -rf -- \"$HOME/.sliprock\" /tmp/sliprock.*");
  SliprockConnection *con =
      sliprock_socket("dummy_valq", sizeof("dummy_val") - 1);
  ASSERT_NE(con, nullptr);

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
    if (!CloseHandle(handle))
      return;
    MADE_IT;
#endif
    write_succeeded = true;
  });
  HANDLE fd = INVALID_HANDLE_VALUE;
  system("ls -a ~/.sliprock");
  SliprockReceiver *receiver =
      sliprock_open("dummy_valr", sizeof("dummy_val") - 1, getpid());
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
  EXPECT_NE(0, ReadFile(fd, buf2, sizeof buf, &read, nullptr));
  EXPECT_EQ(read, sizeof buf);
#else
  EXPECT_EQ(sizeof buf, read(fd, buf2, sizeof buf));
#endif
  static_assert(sizeof con->address == sizeof receiver->sock,
                "Connection size mismatch");
  EXPECT_EQ(memcmp(buf2, buf, sizeof buf), 0);
#ifndef _WIN32
  EXPECT_GT(fd, -1);
#endif
  read_succeeded = true;
fail:
  ASSERT_NE(nullptr, receiver);
  EXPECT_EQ(0, memcmp(reinterpret_cast<void *>(&receiver->sock),
                      reinterpret_cast<void *>(&con->address),
                      sizeof con->address));
  EXPECT_EQ(true, read_succeeded);
  EXPECT_NE(receiver, nullptr);
  if (fd != INVALID_HANDLE_VALUE) {
    MADE_IT;
#ifndef _WIN32
    EXPECT_EQ(close(fd), 0);
#else
    EXPECT_NE(CloseHandle(fd), 0);
#endif
    thread.join();
    MADE_IT;
  } else {
    thread.detach();
  }
  sliprock_close_receiver(receiver);
  EXPECT_EQ(write_succeeded, true);

  sliprock_close(con);
}

int main(int argc, TCHAR **argv) {
  testing::InitGoogleTest(&argc, argv);
  int code = RUN_ALL_TESTS();
#ifdef _WIN32
  Sleep(INFINITE);
#endif
  return code;
}
