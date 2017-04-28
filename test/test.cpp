#ifdef _WIN32
#define _UNICODE _UNICODE
#define UNICODE UNICODE
#define TCHAR wchar_t
#else
#define TCHAR char
#endif
#include "../src/sliprock.h"
#include <gtest/gtest.h>
#include <thread>
#include <csignal>

TEST(CanCreateConnection, ItWorks) {
  int fds[2];
  ASSERT_EQ(pipe(fds), 0);
  SliprockConnection *con =
      sliprock_socket("dummy_valq", sizeof("dummy_val") - 1);
  ASSERT_NE(con, nullptr);

  char buf[] = "Test message!";
  char buf2[sizeof buf];
  bool accept_succeeded = false, open_succeeded = false,
       write_succeeded = false, read_succeeded = false;
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
  system("ls ~/.sliprock");
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
  if (read(fd, buf2, sizeof buf) != sizeof buf) {
    perror("read");
    goto fail;
  }
  EXPECT_EQ(memcmp(buf2, buf, sizeof buf), 0);
  EXPECT_GT(fd, -1);
  read_succeeded = true;
fail:
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
