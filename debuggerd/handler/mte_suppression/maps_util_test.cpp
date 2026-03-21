// Unit tests for parse_maps_line() and for_each_line_from_fd(). These helpers live in maps_util.h
// and have no aarch64 or bionic dependencies, so they can run as host tests.

#include "maps_util.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace mte_suppression;

// ---------------------------------------------------------------------------
// Helper: write string to a pipe and return the read fd.
// ---------------------------------------------------------------------------
static int pipe_with_content(const char* content) {
  int fds[2];
  EXPECT_EQ(pipe(fds), 0);
  size_t len = strlen(content);
  EXPECT_EQ(static_cast<size_t>(write(fds[1], content, len)), len);
  EXPECT_EQ(close(fds[1]), 0) << "close write end: " << strerror(errno);
  return fds[0];
}

// ===== parse_maps_line tests =====

TEST(ParseMapsLine, BasicLibrary) {
  MapsEntry e = {};
  const char* line = "7f8a000000-7f8a010000 r-xp 00000000 fe:01 12345  /system/lib64/libc.so";
  ASSERT_TRUE(parse_maps_line(line, &e));
  EXPECT_EQ(e.start, 0x7f8a000000UL);
  EXPECT_EQ(e.end, 0x7f8a010000UL);
  EXPECT_EQ(e.offset, 0UL);
  EXPECT_STREQ(e.name, "/system/lib64/libc.so");
}

TEST(ParseMapsLine, NonZeroOffset) {
  MapsEntry e = {};
  const char* line = "7f8a010000-7f8a020000 r--p 00010000 fe:01 12345  /system/lib64/libc.so";
  ASSERT_TRUE(parse_maps_line(line, &e));
  EXPECT_EQ(e.start, 0x7f8a010000UL);
  EXPECT_EQ(e.end, 0x7f8a020000UL);
  EXPECT_EQ(e.offset, 0x10000UL);
  EXPECT_STREQ(e.name, "/system/lib64/libc.so");
}

TEST(ParseMapsLine, AnonymousMapping) {
  MapsEntry e = {};
  const char* line = "7f8b000000-7f8b001000 rw-p 00000000 00:00 0";
  ASSERT_TRUE(parse_maps_line(line, &e));
  EXPECT_EQ(e.start, 0x7f8b000000UL);
  EXPECT_EQ(e.end, 0x7f8b001000UL);
  EXPECT_EQ(e.offset, 0UL);
  EXPECT_STREQ(e.name, "");
}

TEST(ParseMapsLine, NamedAnonymous) {
  MapsEntry e = {};
  const char* line = "7f8b000000-7f8b001000 rw-p 00000000 00:00 0  [stack]";
  ASSERT_TRUE(parse_maps_line(line, &e));
  EXPECT_STREQ(e.name, "[stack]");
}

TEST(ParseMapsLine, VendorDsoLongPath) {
  MapsEntry e = {};
  const char* line =
      "0000c33faa064000-0000c33faa0d3000 r-xp 00000000 fe:30 3236  "
      "/vendor/lib64/hw/android.hardware.composer.hwc3-service.pixel.so";
  ASSERT_TRUE(parse_maps_line(line, &e));
  EXPECT_EQ(e.start, 0xc33faa064000UL);
  EXPECT_EQ(e.end, 0xc33faa0d3000UL);
  EXPECT_EQ(e.offset, 0UL);
  EXPECT_STREQ(e.name, "/vendor/lib64/hw/android.hardware.composer.hwc3-service.pixel.so");
}

// Copied and adapted from system/unwinding/libunwindstack/tests/MapsTest.cpp,
// MapsTest.verify_large_values. Verifies that large 64-bit addresses and file offsets are parsed
// without truncation.
TEST(ParseMapsLine, LargeValues) {
  MapsEntry e = {};
  // Keep the libunwindstack-style large 64-bit values, but use an increasing address range because
  // parse_maps_line() rejects start >= end.
  const char* line = "f12345678abcdef8-fabcdef012345678 rwxp f0b0d0f010305070 00:00 0";
  ASSERT_TRUE(parse_maps_line(line, &e));
  EXPECT_EQ(e.start, 0xf12345678abcdef8UL);
  EXPECT_EQ(e.end, 0xfabcdef012345678UL);
  EXPECT_EQ(e.offset, 0xf0b0d0f010305070UL);
  EXPECT_STREQ(e.name, "");
}

// Copied and adapted from system/unwinding/libunwindstack/tests/MapsTest.cpp,
// MapsTest.parse_permissions. Verifies that parse_maps_line() preserves the permission string and
// that maps_entry_is_executable() classifies executable mappings the same way the production
// backtrace filters do.
TEST(ParseMapsLine, PermissionsParsed) {
  MapsEntry e = {};

  ASSERT_TRUE(parse_maps_line("1000-2000 ---s 00000000 00:00 0", &e));
  EXPECT_STREQ(e.perms, "---s");
  EXPECT_FALSE(maps_entry_is_executable(e));

  ASSERT_TRUE(parse_maps_line("2000-3000 r--s 00000000 00:00 0", &e));
  EXPECT_STREQ(e.perms, "r--s");
  EXPECT_FALSE(maps_entry_is_executable(e));

  ASSERT_TRUE(parse_maps_line("3000-4000 -w-s 00000000 00:00 0", &e));
  EXPECT_STREQ(e.perms, "-w-s");
  EXPECT_FALSE(maps_entry_is_executable(e));

  ASSERT_TRUE(parse_maps_line("4000-5000 --xp 00000000 00:00 0", &e));
  EXPECT_STREQ(e.perms, "--xp");
  EXPECT_TRUE(maps_entry_is_executable(e));

  ASSERT_TRUE(parse_maps_line("5000-6000 rwxp 00000000 00:00 0", &e));
  EXPECT_STREQ(e.perms, "rwxp");
  EXPECT_TRUE(maps_entry_is_executable(e));
}

// Copied and adapted from system/unwinding/libunwindstack/tests/MapsTest.cpp,
// MapsTest.verify_parse_line. Verifies that an empty input line is rejected.
TEST(ParseMapsLine, EmptyLine) {
  MapsEntry e = {};
  EXPECT_FALSE(parse_maps_line("", &e));
}

TEST(ParseMapsLine, InvalidNoHyphen) {
  MapsEntry e = {};
  EXPECT_FALSE(parse_maps_line("not a maps line", &e));
}

TEST(ParseMapsLine, InvalidStartEqualsEnd) {
  MapsEntry e = {};
  // start == end should return false (start < end check)
  EXPECT_FALSE(parse_maps_line("7f8a000000-7f8a000000 r-xp 00000000 fe:01 0", &e));
}

// Copied and adapted from system/unwinding/libunwindstack/tests/MapsTest.cpp,
// MapsTest.verify_parse_line. Verifies that a descending address range is rejected.
TEST(ParseMapsLine, StartGreaterThanEnd) {
  MapsEntry e = {};
  EXPECT_FALSE(parse_maps_line("7f8a010000-7f8a000000 r-xp 00000000 fe:01 0  /lib.so", &e));
}

// Copied and adapted from system/unwinding/libunwindstack/tests/MapsTest.cpp,
// MapsTest.verify_parse_line. Verifies that a truncated address range is rejected.
TEST(ParseMapsLine, TruncatedLine) {
  MapsEntry e = {};
  EXPECT_FALSE(parse_maps_line("7f8a000000-", &e));
}

TEST(ParseMapsLine, MultipleSpacesBeforeName) {
  MapsEntry e = {};
  // Real maps lines sometimes have extra spacing before the name.
  const char* line = "7f8a000000-7f8a010000 r-xp 00000000 fe:01 12345                  /foo.so";
  ASSERT_TRUE(parse_maps_line(line, &e));
  EXPECT_STREQ(e.name, "/foo.so");
}

TEST(ParseMapsLine, DeletedLibrary) {
  MapsEntry e = {};
  const char* line =
      "7f8a000000-7f8a010000 r-xp 00000000 fe:01 12345  /system/lib64/libfoo.so (deleted)";
  ASSERT_TRUE(parse_maps_line(line, &e));
  EXPECT_STREQ(e.name, "/system/lib64/libfoo.so (deleted)");
}

// ===== for_each_line_from_fd tests =====

TEST(ForEachLine, BasicLines) {
  int fd = pipe_with_content("line1\nline2\nline3\n");
  std::vector<std::string> lines;
  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    lines.emplace_back(line);
    return true;
  });
  EXPECT_EQ(close(fd), 0) << "close read end: " << strerror(errno);
  ASSERT_EQ(lines.size(), 3u);
  EXPECT_EQ(lines[0], "line1");
  EXPECT_EQ(lines[1], "line2");
  EXPECT_EQ(lines[2], "line3");
}

TEST(ForEachLine, NoTrailingNewline) {
  int fd = pipe_with_content("line1\npartial");
  std::vector<std::string> lines;
  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    lines.emplace_back(line);
    return true;
  });
  EXPECT_EQ(close(fd), 0) << "close read end: " << strerror(errno);
  ASSERT_EQ(lines.size(), 2u);
  EXPECT_EQ(lines[0], "line1");
  EXPECT_EQ(lines[1], "partial");
}

TEST(ForEachLine, EmptyInput) {
  int fd = pipe_with_content("");
  std::vector<std::string> lines;
  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    lines.emplace_back(line);
    return true;
  });
  EXPECT_EQ(close(fd), 0) << "close read end: " << strerror(errno);
  EXPECT_TRUE(lines.empty());
}

TEST(ForEachLine, EarlyStop) {
  int fd = pipe_with_content("first\nsecond\nthird\n");
  std::vector<std::string> lines;
  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    lines.emplace_back(line);
    return lines.size() < 2;  // Stop after second line.
  });
  EXPECT_EQ(close(fd), 0) << "close read end: " << strerror(errno);
  ASSERT_EQ(lines.size(), 2u);
  EXPECT_EQ(lines[0], "first");
  EXPECT_EQ(lines[1], "second");
}

TEST(ForEachLine, SmallBufferOversizedLine) {
  // Buffer of 16 bytes, line is 30+ chars. It should be truncated, and subsequent lines should
  // still be delivered.
  int fd = pipe_with_content("this_line_is_way_too_long_for_buf\nshort\n");
  std::vector<std::string> lines;
  for_each_line_from_fd<16>(fd, [&](const char* line) -> bool {
    lines.emplace_back(line);
    return true;
  });
  EXPECT_EQ(close(fd), 0) << "close read end: " << strerror(errno);
  ASSERT_GE(lines.size(), 2u);
  // First line should be truncated to 15 chars (kMaxData = 16-1).
  EXPECT_EQ(lines[0].size(), 15u);
  EXPECT_EQ(lines[0], "this_line_is_wa");
  // Second line should be intact.
  EXPECT_EQ(lines.back(), "short");
}

// Copied and adapted from system/unwinding/libunwindstack/tests/MapsTest.cpp,
// MapsTest.file_buffer_cross. Verifies that a valid maps line split across the fixed-size read
// buffer is reconstructed correctly rather than being truncated or misparsed.
TEST(ForEachLine, ValidLineCrossesReadBoundary) {
  char path[] = "/tmp/mte_suppression_maps.XXXXXX";
  int fd = mkstemp(path);
  ASSERT_GE(fd, 0) << strerror(errno);

  std::string filler(55, 'x');
  filler.push_back('\n');
  const char* target = "1-2 r-xp 0 0:0 0 /x\n";
  std::string contents = filler + target;
  ASSERT_EQ(static_cast<ssize_t>(contents.size()),
            TEMP_FAILURE_RETRY(write(fd, contents.data(), contents.size())));
  ASSERT_EQ(0, lseek(fd, 0, SEEK_SET));

  std::vector<std::string> lines;
  for_each_line_from_fd<64>(fd, [&](const char* line) -> bool {
    lines.emplace_back(line);
    return true;
  });

  EXPECT_EQ(close(fd), 0) << "close read end: " << strerror(errno);
  EXPECT_EQ(unlink(path), 0) << "unlink temp file: " << strerror(errno);
  ASSERT_EQ(lines.size(), 2u);

  MapsEntry e = {};
  ASSERT_TRUE(parse_maps_line(lines[1].c_str(), &e));
  EXPECT_EQ(e.start, 0x1UL);
  EXPECT_EQ(e.end, 0x2UL);
  EXPECT_EQ(e.offset, 0UL);
  EXPECT_STREQ(e.name, "/x");
}

TEST(ForEachLine, SingleNewline) {
  int fd = pipe_with_content("\n");
  std::vector<std::string> lines;
  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    lines.emplace_back(line);
    return true;
  });
  EXPECT_EQ(close(fd), 0) << "close read end: " << strerror(errno);
  ASSERT_EQ(lines.size(), 1u);
  EXPECT_EQ(lines[0], "");
}

TEST(ForEachLine, EmptyLines) {
  int fd = pipe_with_content("\n\n\n");
  std::vector<std::string> lines;
  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    lines.emplace_back(line);
    return true;
  });
  EXPECT_EQ(close(fd), 0) << "close read end: " << strerror(errno);
  ASSERT_EQ(lines.size(), 3u);
  for (const auto& l : lines) {
    EXPECT_EQ(l, "");
  }
}

// ===== Integration: for_each_line_from_fd + parse_maps_line =====

TEST(MapsIntegration, RealMapsLines) {
  const char* maps_content =
      "0000dca159606000-0000dca159688fff r--p 00000000 fe:30 3236  "
      "/vendor/lib64/libexynosdisplay.so\n"
      "0000dca15968a000-0000dca1597bcfff r-xp 00084000 fe:30 3236  "
      "/vendor/lib64/libexynosdisplay.so\n"
      "0000dca1597be000-0000dca1597c6fff r--p 001b8000 fe:30 3236  "
      "/vendor/lib64/libexynosdisplay.so\n"
      "0000dca1597ca000-0000dca1597cafff rw-p 001c4000 fe:30 3236  "
      "/vendor/lib64/libexynosdisplay.so\n"
      "7f8b000000-7f8b001000 rw-p 00000000 00:00 0  [anon:stack_and_tls:5529]\n"
      "7ffc9e9b0000-7ffc9e9d1000 rw-p 00000000 00:00 0  [stack]\n";

  int fd = pipe_with_content(maps_content);
  std::vector<MapsEntry> entries;
  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    MapsEntry e = {};
    if (parse_maps_line(line, &e)) {
      entries.push_back(e);
    }
    return true;
  });
  EXPECT_EQ(close(fd), 0) << "close read end: " << strerror(errno);

  ASSERT_EQ(entries.size(), 6u);

  // First entry: offset-0 read-only mapping of libexynosdisplay.so from the actual tombstone
  // layout.
  EXPECT_EQ(entries[0].start, 0xdca159606000UL);
  EXPECT_EQ(entries[0].end, 0xdca159688fffUL);
  EXPECT_EQ(entries[0].offset, 0UL);
  EXPECT_STREQ(entries[0].name, "/vendor/lib64/libexynosdisplay.so");

  // Second entry: executable text mapping at a non-zero file offset.
  EXPECT_EQ(entries[1].offset, 0x84000UL);
  EXPECT_STREQ(entries[1].name, "/vendor/lib64/libexynosdisplay.so");

  // Third and fourth entries: later read-only and writable segments from the same DSO.
  EXPECT_EQ(entries[2].offset, 0x1b8000UL);
  EXPECT_EQ(entries[3].offset, 0x1c4000UL);

  // Fifth entry: anonymous mapping.
  EXPECT_STREQ(entries[4].name, "[anon:stack_and_tls:5529]");

  // Sixth entry: stack.
  EXPECT_STREQ(entries[5].name, "[stack]");
}

TEST(MapsIntegration, FilterBaseMapping) {
  // Simulate a simple "offset == 0 and name starts with '/'" filter using tombstone-derived vendor
  // DSO layouts where the executable mapping starts later in the file.
  const char* maps_content =
      "0000dca159606000-0000dca159688fff r--p 00000000 fe:30 3236  "
      "/vendor/lib64/libexynosdisplay.so\n"
      "0000dca15968a000-0000dca1597bcfff r-xp 00084000 fe:30 3236  "
      "/vendor/lib64/libexynosdisplay.so\n"
      "7f8b000000-7f8b001000 rw-p 00000000 00:00 0\n"
      "0000dca159407000-0000dca159409fff r--p 00000000 fe:30 4567  "
      "/vendor/lib64/libvendorgraphicbuffer.so\n";

  int fd = pipe_with_content(maps_content);
  std::vector<MapsEntry> base_mappings;
  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    MapsEntry e = {};
    if (parse_maps_line(line, &e) && e.offset == 0 && e.name[0] == '/') {
      base_mappings.push_back(e);
    }
    return true;
  });
  EXPECT_EQ(close(fd), 0) << "close read end: " << strerror(errno);

  // Only the two base (offset=0) named mappings should pass.
  ASSERT_EQ(base_mappings.size(), 2u);
  EXPECT_STREQ(base_mappings[0].name, "/vendor/lib64/libexynosdisplay.so");
  EXPECT_STREQ(base_mappings[1].name, "/vendor/lib64/libvendorgraphicbuffer.so");
}

TEST(MapsIntegration, FilterBaseMappingAllowsExecutableOffsetZero) {
  // AOSP arm64 builds normally use -Wl,-z,separate-code and
  // -Wl,-z,separate-loadable-segments; see build/soong/cc/config/arm64_device.go. Those defaults
  // tend to produce a read-only offset-0 map followed by a later executable map. Model the
  // opposite case here: a .so not linked with those flags, where the offset-0 file-backed mapping
  // is itself executable. This verifies that the simple offset==0 base-mapping filter still
  // accepts that layout.
  const char* maps_content =
      "1000-2000 r-xp 00000000 fe:01 111  /vendor/lib64/libflatlayout.so\n"
      "2000-2800 r--p 00010000 fe:01 111  /vendor/lib64/libflatlayout.so\n"
      "2800-3000 rw-p 00018000 fe:01 111  /vendor/lib64/libflatlayout.so\n"
      "4000-5000 r--p 00000000 fe:01 222  /vendor/lib64/libother.so\n";

  int fd = pipe_with_content(maps_content);
  std::vector<MapsEntry> base_mappings;
  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    MapsEntry e = {};
    if (parse_maps_line(line, &e) && e.offset == 0 && e.name[0] == '/') {
      base_mappings.push_back(e);
    }
    return true;
  });
  EXPECT_EQ(close(fd), 0) << "close read end: " << strerror(errno);

  ASSERT_EQ(base_mappings.size(), 2u);
  EXPECT_STREQ(base_mappings[0].name, "/vendor/lib64/libflatlayout.so");
  EXPECT_STREQ(base_mappings[0].perms, "r-xp");
  EXPECT_EQ(base_mappings[0].offset, 0UL);
  EXPECT_STREQ(base_mappings[1].name, "/vendor/lib64/libother.so");
  EXPECT_STREQ(base_mappings[1].perms, "r--p");
  EXPECT_EQ(base_mappings[1].offset, 0UL);
}
