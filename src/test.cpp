#ifdef _WIN32
#define _UNICODE _UNICODE
#define UNICODE UNICODE
#define main _wmain
#else
#define TCHAR char
#endif
#include "sliprock.h"
#include "../src/sliprock_internals.h"
#include <gtest/gtest.h>
#include <thread>
#include <csignal>

#ifdef _WIN32
#define address pipename
#endif
TEST(CanCreateConnection, ItWorks) {
  system("rm -rf -- \"$HOME/.sliprock\" /tmp/sliprock.*");
  SliprockConnection *con =
      sliprock_socket("dummy_valq", sizeof("dummy_val") - 1);
  ASSERT_NE(con, nullptr);

  char buf[] = "Test message!";
  char buf2[sizeof buf];
  bool write_succeeded = false, read_succeeded = false;
  std::thread thread([&]() {
    auto handle = (int)sliprock_accept(con);
    if (handle < 0)
      return;
    if (write(handle, buf, sizeof buf) != sizeof buf)
      return;
    if (close(handle))
      return;
    write_succeeded = true;
  });
  int fd = -1;
  system("ls -a ~/.sliprock");
  SliprockReceiver *receiver =
      sliprock_open("dummy_valr", sizeof("dummy_val") - 1, getpid());
  if (receiver == nullptr) {
    perror("sliprock_open");
    goto fail;
  }
  fd = sliprock_connect(receiver);
  if (fd <= 0) {
    perror("sliprock_connect");
    goto fail;
  }
  EXPECT_EQ(sizeof buf, read(fd, buf2, sizeof buf));
  static_assert(sizeof con->address == sizeof receiver->sock, "Connection size mismatch");
  EXPECT_EQ(memcmp(buf2, buf, sizeof buf), 0);
  EXPECT_GT(fd, -1);
  read_succeeded = true;
fail:
  ASSERT_NE(nullptr, receiver);
  EXPECT_EQ(0, memcmp(reinterpret_cast<void*>(&receiver->sock), reinterpret_cast<void*>(&con->address), sizeof con->address));
  EXPECT_EQ(true, read_succeeded);
  EXPECT_NE(receiver, nullptr);
  if (fd >= 0) {
    EXPECT_EQ(close(fd), 0);
    thread.join();
  } else {
    thread.detach();
  }
  sliprock_close_receiver(receiver);
  EXPECT_EQ(write_succeeded, true);

  sliprock_close(con);
}

int main(int argc, TCHAR **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
