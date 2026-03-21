// Device tests for match_backtrace(). These build fake backtrace arrays from dlsym() addresses and
// verify strict positional matching against patterns. Requires an aarch64 device because real DSOs
// are needed for hash-based symbol lookup.

#include "backtrace.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <string.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <string>

using namespace mte_suppression;

static_assert(kMaxDsos >= 2,
              "backtrace_match_test exercises successful cross-DSO matching and needs at least "
              "two DSO slots");

// ===== Helpers =====

static std::string get_test_lib_dir() {
  char self[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", self, sizeof(self) - 1);
  if (len <= 0) return ".";
  self[len] = '\0';
  return dirname(self);
}

static void* g_hash_helper_handle = nullptr;

static void load_hash_helper() {
  if (g_hash_helper_handle) return;
  std::string path = get_test_lib_dir() + "/libdso_test_hash_helper.so";
  g_hash_helper_handle = dlopen(path.c_str(), RTLD_NOW);
  if (!g_hash_helper_handle) {
    g_hash_helper_handle = dlopen("libdso_test_hash_helper.so", RTLD_NOW);
  }
}

static MapsEntry find_dso_mapping(const char* dso_name) {
  MapsEntry result{};
  int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  EXPECT_GE(fd, 0) << "open /proc/self/maps: " << strerror(errno);
  if (fd < 0) return result;

  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    MapsEntry entry{};
    if (!parse_maps_line(line, &entry) || entry.offset != 0 || entry.name[0] != '/') return true;
    const char* basename = strrchr(entry.name, '/');
    basename = basename ? basename + 1 : entry.name;
    if (strcmp(basename, dso_name) == 0) {
      result = entry;
      return false;
    }
    return true;
  });
  EXPECT_EQ(close(fd), 0) << "close /proc/self/maps: " << strerror(errno);
  return result;
}

// Build a DsoSearchCtx with resolved DsoInfo entries for the given DSO names. Returns the number of
// DSOs, or -1 on failure.
static int setup_ctx(const char* const* dso_names, int num_dsos, DsoSearchCtx* ctx) {
  for (int i = 0; i < num_dsos; i++) {
    MapsEntry mapping = find_dso_mapping(dso_names[i]);
    if (mapping.start == 0) return -1;
    // parse_dso_elf() takes the end of the initial offset=0 maps entry so it can bound the
    // bootstrap Ehdr/Phdr reads before any PT_LOAD-derived ranges exist.
    if (!parse_dso_elf(mapping.start, mapping.end, &ctx->infos[i])) return -1;
    ctx->infos[i].valid = true;
  }
  ctx->found = num_dsos;
  ctx->count = num_dsos;
  return num_dsos;
}

// ===== Test fixture =====

class BacktraceMatchTest : public ::testing::Test {
 protected:
  void SetUp() override {
    load_hash_helper();
    ASSERT_NE(g_hash_helper_handle, nullptr) << "Failed to dlopen libdso_test_hash_helper.so";
  }
};

// ===== Tests =====

// Two-frame pattern in libc.so: atoi -> close. Build a backtrace with the real dlsym addresses. It
// should match.
TEST_F(BacktraceMatchTest, ExactMatchSucceeds) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  void* close_addr = dlsym(RTLD_DEFAULT, "close");
  ASSERT_NE(atoi_addr, nullptr);
  ASSERT_NE(close_addr, nullptr);

  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr),
                           reinterpret_cast<uintptr_t>(close_addr)};

  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}, {"libc.so", "close"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("test_exact", 10, kFrames[0], kFrames[1]);
  SuppressionPattern pat = kPatternDef.view();

  const char* dso_names[] = {"libc.so"};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(setup_ctx(dso_names, 1, &ctx), 1);

  int frame_dso_map[] = {0, 0};
  EXPECT_TRUE(match_backtrace(backtrace, 2, pat, ctx, frame_dso_map));
}

// Same pattern, but the backtrace has the wrong function at position 1. It should fail immediately
// at frame[1].
TEST_F(BacktraceMatchTest, WrongFunctionFails) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  void* write_addr = dlsym(RTLD_DEFAULT, "write");
  ASSERT_NE(atoi_addr, nullptr);
  ASSERT_NE(write_addr, nullptr);

  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr),
                           reinterpret_cast<uintptr_t>(write_addr)};

  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}, {"libc.so", "close"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("test_wrong", 10, kFrames[0], kFrames[1]);
  SuppressionPattern pat = kPatternDef.view();

  const char* dso_names[] = {"libc.so"};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(setup_ctx(dso_names, 1, &ctx), 1);

  int frame_dso_map[] = {0, 0};
  EXPECT_FALSE(match_backtrace(backtrace, 2, pat, ctx, frame_dso_map));
}

// Backtrace shorter than the pattern. It should fail.
TEST_F(BacktraceMatchTest, BacktraceTooShortFails) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  ASSERT_NE(atoi_addr, nullptr);

  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr)};

  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}, {"libc.so", "close"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("test_short", 10, kFrames[0], kFrames[1]);
  SuppressionPattern pat = kPatternDef.view();

  const char* dso_names[] = {"libc.so"};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(setup_ctx(dso_names, 1, &ctx), 1);

  int frame_dso_map[] = {0, 0};
  EXPECT_FALSE(match_backtrace(backtrace, 1, pat, ctx, frame_dso_map));
}

// Cross-DSO pattern: frame[0] in libc.so, frame[1] in libdso_test_hash_helper.so.
TEST_F(BacktraceMatchTest, CrossDsoMatchSucceeds) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  void* add_addr = dlsym(g_hash_helper_handle, "dso_test_add");
  ASSERT_NE(atoi_addr, nullptr);
  ASSERT_NE(add_addr, nullptr);

  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr),
                           reinterpret_cast<uintptr_t>(add_addr)};

  constexpr FramePattern kFrames[] = {
      {"libc.so", "atoi"},
      {"libdso_test_hash_helper.so", "dso_test_add"},
  };
  constexpr auto kPatternDef =
      MakeSuppressionPatternDef("test_cross_dso", 10, kFrames[0], kFrames[1]);
  SuppressionPattern pat = kPatternDef.view();

  const char* dso_names[] = {"libc.so", "libdso_test_hash_helper.so"};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(setup_ctx(dso_names, 2, &ctx), 2);

  int frame_dso_map[] = {0, 1};
  EXPECT_TRUE(match_backtrace(backtrace, 2, pat, ctx, frame_dso_map));
}

// Cross-DSO pattern, but the backtrace has the DSOs swapped. It should fail at frame[0].
TEST_F(BacktraceMatchTest, CrossDsoWrongOrderFails) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  void* add_addr = dlsym(g_hash_helper_handle, "dso_test_add");
  ASSERT_NE(atoi_addr, nullptr);
  ASSERT_NE(add_addr, nullptr);

  // Backtrace has helper first, libc second (opposite of pattern).
  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(add_addr),
                           reinterpret_cast<uintptr_t>(atoi_addr)};

  constexpr FramePattern kFrames[] = {
      {"libc.so", "atoi"},
      {"libdso_test_hash_helper.so", "dso_test_add"},
  };
  constexpr auto kPatternDef =
      MakeSuppressionPatternDef("test_cross_dso_wrong", 10, kFrames[0], kFrames[1]);
  SuppressionPattern pat = kPatternDef.view();

  const char* dso_names[] = {"libc.so", "libdso_test_hash_helper.so"};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(setup_ctx(dso_names, 2, &ctx), 2);

  int frame_dso_map[] = {0, 1};
  EXPECT_FALSE(match_backtrace(backtrace, 2, pat, ctx, frame_dso_map));
}

TEST_F(BacktraceMatchTest, StaleRawLrSkipsToNextFrame) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  void* close_addr = dlsym(RTLD_DEFAULT, "close");
  ASSERT_NE(atoi_addr, nullptr);
  ASSERT_NE(close_addr, nullptr);

  // Model the AArch64 non-leaf case directly at the matcher level:
  //   bt[0] = PC in frame[0]
  //   bt[1] = raw LR, but still inside frame[0]'s function, so it is stale
  //   bt[2] = the real caller frame that should satisfy frame[1]
  //
  // This keeps the unit test focused on match_backtrace()'s bt[1] skip logic instead of depending
  // on capture_backtrace() to synthesize that shape for us.
  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr),
                           reinterpret_cast<uintptr_t>(atoi_addr),
                           reinterpret_cast<uintptr_t>(close_addr)};

  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}, {"libc.so", "close"}};
  constexpr auto kPatternDef =
      MakeSuppressionPatternDef("test_stale_lr_skip", 10, kFrames[0], kFrames[1]);
  SuppressionPattern pat = kPatternDef.view();

  const char* dso_names[] = {"libc.so"};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(setup_ctx(dso_names, 1, &ctx), 1);

  int frame_dso_map[] = {0, 0};
  EXPECT_TRUE(match_backtrace(backtrace, 3, pat, ctx, frame_dso_map));
}

TEST_F(BacktraceMatchTest, StaleRawLrWithOnlyTwoFramesFailsSecondMatch) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  ASSERT_NE(atoi_addr, nullptr);

  // Same stale-LR setup as the test above, but with no bt[2]. Once match_backtrace() recognizes
  // bt[1] as stale, the second pattern frame has nowhere left to match and the result must be a
  // clean failure rather than an out-of-bounds read or accidental success.
  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr),
                           reinterpret_cast<uintptr_t>(atoi_addr)};

  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}, {"libc.so", "close"}};
  constexpr auto kPatternDef =
      MakeSuppressionPatternDef("test_stale_lr_too_short", 10, kFrames[0], kFrames[1]);
  SuppressionPattern pat = kPatternDef.view();

  const char* dso_names[] = {"libc.so"};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(setup_ctx(dso_names, 1, &ctx), 1);

  int frame_dso_map[] = {0, 0};
  EXPECT_FALSE(match_backtrace(backtrace, 2, pat, ctx, frame_dso_map));
}

TEST_F(BacktraceMatchTest, SingleFramePatternStillMatchesWithStaleRawLr) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  ASSERT_NE(atoi_addr, nullptr);

  // A one-frame pattern should still match even if bt[1] is stale. The stale-LR check may notice
  // bt[1], but there is no second pattern frame to consume it, so the overall answer must remain a
  // match.
  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr),
                           reinterpret_cast<uintptr_t>(atoi_addr)};

  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}};
  constexpr auto kPatternDef =
      MakeSuppressionPatternDef("test_single_frame_stale_lr", 10, kFrames[0]);
  SuppressionPattern pat = kPatternDef.view();

  const char* dso_names[] = {"libc.so"};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(setup_ctx(dso_names, 1, &ctx), 1);

  int frame_dso_map[] = {0};
  EXPECT_TRUE(match_backtrace(backtrace, 2, pat, ctx, frame_dso_map));
}

// Address in the middle of a function still matches.
TEST_F(BacktraceMatchTest, MiddleOfFunctionMatches) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  ASSERT_NE(atoi_addr, nullptr);

  // Offset +4 into atoi (simulates a return address mid-function).
  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr) + 4};

  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("test_middle", 10, kFrames[0]);
  SuppressionPattern pat = kPatternDef.view();

  const char* dso_names[] = {"libc.so"};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(setup_ctx(dso_names, 1, &ctx), 1);

  int frame_dso_map[] = {0};
  EXPECT_TRUE(match_backtrace(backtrace, 1, pat, ctx, frame_dso_map));
}

// Backtrace has extra trailing frames beyond the pattern. It should still match because the pattern
// is a prefix of the backtrace.
TEST_F(BacktraceMatchTest, ExtraTrailingFramesStillMatches) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  void* close_addr = dlsym(RTLD_DEFAULT, "close");
  void* write_addr = dlsym(RTLD_DEFAULT, "write");
  ASSERT_NE(atoi_addr, nullptr);
  ASSERT_NE(close_addr, nullptr);
  ASSERT_NE(write_addr, nullptr);

  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr),
                           reinterpret_cast<uintptr_t>(close_addr),
                           reinterpret_cast<uintptr_t>(write_addr)};

  // Pattern only has 2 frames, backtrace has 3.
  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}, {"libc.so", "close"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("test_extra", 10, kFrames[0], kFrames[1]);
  SuppressionPattern pat = kPatternDef.view();

  const char* dso_names[] = {"libc.so"};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(setup_ctx(dso_names, 1, &ctx), 1);

  int frame_dso_map[] = {0, 0};
  EXPECT_TRUE(match_backtrace(backtrace, 3, pat, ctx, frame_dso_map));
}

// Verify there is no sliding: if frame[0] does not match bt[0] but would match bt[1], the match
// should still fail because matching is strictly positional.
TEST_F(BacktraceMatchTest, NoSlidingWindow) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  void* close_addr = dlsym(RTLD_DEFAULT, "close");
  ASSERT_NE(atoi_addr, nullptr);
  ASSERT_NE(close_addr, nullptr);

  // Backtrace: close, atoi. Pattern wants atoi at position 0.
  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(close_addr),
                           reinterpret_cast<uintptr_t>(atoi_addr)};

  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("test_no_slide", 10, kFrames[0]);
  SuppressionPattern pat = kPatternDef.view();

  const char* dso_names[] = {"libc.so"};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(setup_ctx(dso_names, 1, &ctx), 1);

  int frame_dso_map[] = {0};
  EXPECT_FALSE(match_backtrace(backtrace, 2, pat, ctx, frame_dso_map));
}

// Invalid DSO (valid=false) causes immediate failure.
TEST_F(BacktraceMatchTest, InvalidDsoFails) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  ASSERT_NE(atoi_addr, nullptr);

  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr)};

  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("test_invalid_dso", 10, kFrames[0]);
  SuppressionPattern pat = kPatternDef.view();

  DsoSearchCtx ctx = {};
  ctx.infos[0].valid = false;
  ctx.found = 1;
  ctx.count = 1;

  int frame_dso_map[] = {0};
  EXPECT_FALSE(match_backtrace(backtrace, 1, pat, ctx, frame_dso_map));
}
