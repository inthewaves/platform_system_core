// Unit tests for safe_read(), safe_read_cstring(), and safe_read_at().
//
// These cases are intentionally copied and adapted from the relevant libunwindstack tests so our
// local process_vm_readv and bounded-string helpers keep the same behavior:
//   - system/unwinding/libunwindstack/tests/MemoryRemoteTest.cpp
//   - system/unwinding/libunwindstack/tests/MemoryTest.cpp
//
// The goal is not just generic coverage. These tests specifically lock in the page-split
// process_vm_readv behavior copied from libunwindstack's ProcessVmRead() and the chunked
// bounded-string read behavior copied from Memory::ReadString().

#include "safe_read.h"

#include <stdint.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace mte_suppression;

TEST(SafeRead, ReadStackVariable) {
  uint64_t val = 0xDEADBEEFCAFEBABEULL;
  uint64_t out = 0;
  EXPECT_TRUE(safe_read(&out, reinterpret_cast<uintptr_t>(&val), sizeof(val)));
  EXPECT_EQ(out, 0xDEADBEEFCAFEBABEULL);
}

// Copied from MemoryRemoteTest.read_large. Verifies that safe_read() preserves correct contents
// across a large multi-page read.
TEST(SafeRead, ReadLarge) {
  static constexpr size_t kTotalPages = 245;
  const size_t page_size = static_cast<size_t>(getpagesize());

  std::vector<uint8_t> src(kTotalPages * page_size);
  for (size_t i = 0; i < kTotalPages; i++) {
    memset(&src[i * page_size], static_cast<int>(i), page_size);
  }

  std::vector<uint8_t> dst(src.size(), 0);
  ASSERT_TRUE(safe_read(dst.data(), reinterpret_cast<uintptr_t>(src.data()), src.size()));
  for (size_t i = 0; i < src.size(); i++) {
    ASSERT_EQ(src[i], dst[i]) << "Failed at byte " << i;
  }
}

TEST(SafeRead, ReadUnmappedFails) {
  uint64_t out = 0;
  EXPECT_FALSE(safe_read(&out, 0x1000, sizeof(out)));
}

TEST(SafeRead, ReadNullFails) {
  uint64_t out = 0;
  EXPECT_FALSE(safe_read(&out, 0, sizeof(out)));
}

// Copied from MemoryRemoteTest.read_fail. Verifies that page-split reads still return false when
// the range crosses into an unmapped hole.
TEST(SafeRead, ReadCrossesMunmapHoleFails) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  void* src = mmap(nullptr, page_size * 2, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  ASSERT_NE(src, MAP_FAILED);
  memset(src, 0x4c, page_size * 2);
  ASSERT_EQ(0, munmap(reinterpret_cast<char*>(src) + page_size, page_size));

  std::vector<uint8_t> dst(page_size, 0);
  ASSERT_TRUE(safe_read(dst.data(), reinterpret_cast<uintptr_t>(src), page_size));
  for (size_t i = 0; i < dst.size(); i++) {
    ASSERT_EQ(0x4cU, dst[i]) << "Failed at byte " << i;
  }

  EXPECT_FALSE(safe_read(dst.data(), reinterpret_cast<uintptr_t>(src) + page_size, 1));
  EXPECT_TRUE(safe_read(dst.data(), reinterpret_cast<uintptr_t>(src) + page_size - 1, 1));
  EXPECT_FALSE(safe_read(dst.data(), reinterpret_cast<uintptr_t>(src) + page_size - 4, 8));
  EXPECT_FALSE(safe_read(dst.data(), UINTPTR_MAX - 100, 200));

  ASSERT_EQ(0, munmap(src, page_size));
}

// Copied and adapted from system/unwinding/libunwindstack/tests/MemoryRemoteTest.cpp,
// MemoryRemoteTest.read_mprotect_hole. Verifies that process_vm_readv-based reads still return
// false when the range crosses into a PROT_NONE page.
TEST(SafeRead, ReadCrossesProtNoneHoleFails) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  void* src = mmap(nullptr, page_size * 3, PROT_READ | PROT_WRITE, MAP_ANON | MAP_PRIVATE, -1, 0);
  ASSERT_NE(src, MAP_FAILED);
  memset(src, 0xff, page_size * 3);
  ASSERT_EQ(0, mprotect(static_cast<char*>(src) + page_size, page_size, PROT_NONE));

  std::vector<uint8_t> dst(page_size * 2, 0);
  EXPECT_FALSE(safe_read(dst.data(), reinterpret_cast<uintptr_t>(src) + page_size - 16, page_size));

  ASSERT_EQ(0, munmap(src, page_size * 3));
}

TEST(SafeReadAt, ReadArrayElement) {
  uint32_t arr[] = {10, 20, 30, 40};
  uint32_t out = 0;
  EXPECT_TRUE(safe_read_at(&out, reinterpret_cast<uintptr_t>(arr), 2));
  EXPECT_EQ(out, 30u);
}

TEST(SafeReadAt, OverflowIndexFails) {
  uint64_t out = 0;
  EXPECT_FALSE(safe_read_at(&out, 0x7FFFFFFFFFFFF000ULL, 0x7FFFFFFFFFFFF000ULL));
}

// Copied from MemoryTest.read_string. Verifies normal bounded-string reads, offset reads, and
// max_len failure behavior.
TEST(SafeReadCString, ReadString) {
  std::string name("string_in_memory");
  char dst[64];

  ASSERT_TRUE(safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(name.c_str()), 100));
  ASSERT_STREQ("string_in_memory", dst);

  ASSERT_TRUE(
      safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(name.c_str()) + 7, 100));
  ASSERT_STREQ("in_memory", dst);

  ASSERT_TRUE(
      safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(name.c_str()) + 7, 10));
  ASSERT_STREQ("in_memory", dst);

  ASSERT_FALSE(
      safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(name.c_str()) + 7, 9));
  ASSERT_STREQ("", dst);
}

// Copied from MemoryTest.read_string_error. Verifies that unterminated strings return false and
// leave dst empty.
TEST(SafeReadCString, ReadStringError) {
  char name[] = "short";
  char dst[64];

  // Exclude the terminating NUL.
  ASSERT_FALSE(safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(name), 5));
  ASSERT_STREQ("", dst);

  ASSERT_TRUE(safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(name), 6));
  ASSERT_STREQ("short", dst);
}

// Copied and adapted from system/unwinding/libunwindstack/tests/MemoryTest.cpp,
// MemoryTest.read_string_error. Verifies that safe_read_cstring() also returns false on an
// unmapped source address, not just on unterminated data.
TEST(SafeReadCString, ReadFromUnmappedAddressFails) {
  char dst[64] = "garbage";
  ASSERT_FALSE(safe_read_cstring(dst, sizeof(dst), 0x1000, 32));
  ASSERT_STREQ("", dst);
}

// Copied from MemoryTest.read_string_long. Verifies multi-chunk reads that are longer than the
// helper's internal stack buffer.
TEST(SafeReadCString, ReadStringLong) {
  static constexpr char kLongString[] =
      "one two three four five six seven eight nine ten eleven twelve thirteen fourteen fifteen "
      "sixteen seventeen eightteen nineteen twenty twenty-one twenty-two twenty-three twenty-four "
      "twenty-five twenty-six twenty-seven twenty-eight twenty-nine thirty thirty-one thirty-two "
      "thirty-three thirty-four thirty-five thirty-six thirty-seven thirty-eight thirty-nine forty "
      "forty-one forty-two forty-three forty-four forty-five forty-size forty-seven forty-eight "
      "forty-nine fifty fifty-one fifty-two fifty-three fifty-four fifty-five fifty-six "
      "fifty-seven fifty-eight fifty-nine sixty sixty-one sixty-two sixty-three sixty-four "
      "sixty-five sixty-six sixty-seven sixty-eight sixty-nine seventy seventy-one seventy-two "
      "seventy-three seventy-four seventy-five seventy-six seventy-seven seventy-eight "
      "seventy-nine eighty";

  char dst[sizeof(kLongString)];
  ASSERT_TRUE(safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(kLongString),
                                sizeof(kLongString)));
  ASSERT_STREQ(kLongString, dst);

  std::string expected(kLongString, 255);
  ASSERT_TRUE(safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(expected.c_str()),
                                expected.size() + 1));
  ASSERT_STREQ(expected.c_str(), dst);
  ASSERT_FALSE(
      safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(expected.c_str()), 255));
  ASSERT_STREQ("", dst);

  // Copied and adapted from
  // system/unwinding/libunwindstack/tests/MemoryTest.cpp,
  // MemoryTest.read_string_long. These exact boundaries exercise the internal 256-byte buffer used
  // by safe_read_cstring().
  expected = std::string(kLongString, 256);
  ASSERT_TRUE(safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(expected.c_str()),
                                expected.size() + 1));
  ASSERT_STREQ(expected.c_str(), dst);
  ASSERT_FALSE(
      safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(expected.c_str()), 256));
  ASSERT_STREQ("", dst);

  expected = std::string(kLongString, 257);
  ASSERT_TRUE(safe_read_cstring(dst, sizeof(dst), reinterpret_cast<uintptr_t>(expected.c_str()),
                                expected.size() + 1));
  ASSERT_STREQ(expected.c_str(), dst);
}
