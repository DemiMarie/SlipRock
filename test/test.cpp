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

TEST(CanCreateConnection, ItWorks) {
  int fds[2];
  ASSERT_EQ(pipe(fds), 0);
  SliprockConnection *con =
      sliprock_socket("dummy_val", sizeof("dummy_val") - 1);
  ASSERT_NE(con, nullptr);

  char buf[] = "Test message!";
  char buf2[sizeof buf];
  bool accept_succeeded = false, open_succeeded = false,
       write_succeeded = false, read_succeeded = false;
   std::thread thread([&] () {
    auto handle = sliprock_accept(con);
    if (handle < 0)
      return;
    if (write(handle, buf, sizeof buf) != sizeof buf)
      return;
    if (close(handle))
      return;
    write_succeeded = true;
   });
   int fd = -1;
   SliprockReceiver *receiver = sliprock_open("dummy_val", strlen("dummy_val"), getpid());
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
   EXPECT_EQ(close(fd), 0);
   fd = -1;
   read_succeeded = true;
fail:
   EXPECT_EQ(read_succeeded, true);
   EXPECT_NE(receiver, nullptr);
   close(fd);
   sliprock_close_receiver(receiver);
   thread.join();
   EXPECT_EQ(write_succeeded, true);


   sliprock_close(con);
}

int main(int argc, TCHAR **argv) {
  testing::InitGoogleTest(&argc, argv);
  return RUN_ALL_TESTS();
}
