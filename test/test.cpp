#ifdef _WIN32
# define _UNICODE _UNICODE
# define UNICODE UNICODE
# define TCHAR wchar_t
#else
# define TCHAR char
#endif
#include "../src/sliprock.h"
#include <gtest/gtest.h>

TEST(CanCreateConnection, ItWorks) {
   SliprockConnection *con = sliprock_socket("dummy_val", sizeof("dummy_val") - 1);
   EXPECT_NE(con, nullptr);
   EXPECT_EQ(sliprock_bind(con), 0);
   sliprock_close(con);
}

int main(int argc, TCHAR **argv) {
   testing::InitGoogleTest(&argc, argv);
   return RUN_ALL_TESTS();
}
