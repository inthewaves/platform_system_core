// Device tests for capture_backtrace(): real signal-based tests plus synthetic ucontext edge-case
// tests. Requires an aarch64 device.

#include "backtrace.h"

#include <dlfcn.h>
#include <signal.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <bionic/android_current_thread_stack_limits.h>

using namespace mte_suppression;

// ============================================================================
// Option 1: Real signal handler tests
// ============================================================================

// Global state shared between the signal handler and the test.
static uintptr_t g_bt[32] = {};
static int g_bt_depth = 0;
static ucontext_t g_uc = {};

static void sigusr1_handler(int, siginfo_t*, void* uc_void) {
  auto* uc = static_cast<ucontext_t*>(uc_void);
  g_uc = *uc;
  g_bt_depth = capture_backtrace(uc, g_bt, 32);
}

// noinline call chain so we get distinct frames in the backtrace.
__attribute__((noinline)) static void depth_3() {
  raise(SIGUSR1);
}
__attribute__((noinline)) static void depth_2() {
  depth_3();
}
__attribute__((noinline)) static void depth_1() {
  depth_2();
}

class CaptureBacktraceSignalTest : public ::testing::Test {
 protected:
  struct sigaction old_sa_ = {};

  void SetUp() override {
    memset(g_bt, 0, sizeof(g_bt));
    g_bt_depth = 0;
    memset(&g_uc, 0, sizeof(g_uc));

    struct sigaction sa = {};
    sa.sa_sigaction = sigusr1_handler;
    sa.sa_flags = SA_SIGINFO;
    sigemptyset(&sa.sa_mask);
    ASSERT_EQ(sigaction(SIGUSR1, &sa, &old_sa_), 0) << strerror(errno);
  }

  void TearDown() override { sigaction(SIGUSR1, &old_sa_, nullptr); }
};

TEST_F(CaptureBacktraceSignalTest, CapturesReasonableDepth) {
  depth_1();
  // depth_1 -> depth_2 -> depth_3 -> raise -> signal handler captures backtrace. We should get at
  // least PC + LR + a few FP chain frames.
  EXPECT_GE(g_bt_depth, 4) << "Expected at least 4 frames (PC + LR + 2 FP chain)";
}

TEST_F(CaptureBacktraceSignalTest, AllFramesNonZero) {
  depth_1();
  for (int i = 0; i < g_bt_depth; i++) {
    EXPECT_NE(g_bt[i], 0u) << "Frame " << i << " is zero";
  }
}

TEST_F(CaptureBacktraceSignalTest, PcIsInCodeRegion) {
  depth_1();
  ASSERT_GE(g_bt_depth, 1);
  // PC should resolve via dladdr() because it lies in a mapped executable region.
  Dl_info info = {};
  EXPECT_NE(dladdr(reinterpret_cast<void*>(g_bt[0]), &info), 0)
      << "PC " << reinterpret_cast<void*>(g_bt[0]) << " does not resolve via dladdr";
}

TEST_F(CaptureBacktraceSignalTest, FramesResolveViaDladdr) {
  depth_1();
  // At least the first few frames should resolve via dladdr().
  int resolved = 0;
  for (int i = 0; i < g_bt_depth && i < 6; i++) {
    Dl_info info = {};
    if (dladdr(reinterpret_cast<void*>(g_bt[i]), &info) != 0) {
      resolved++;
    }
  }
  EXPECT_GE(resolved, 3) << "Expected at least 3 frames resolvable via dladdr";
}

// ============================================================================
// Option 2: Synthetic ucontext tests (edge cases)
// ============================================================================

// Helper: build a ucontext_t with specific register values.
static ucontext_t make_uc(uintptr_t pc, uintptr_t lr, uintptr_t fp, uintptr_t sp) {
  ucontext_t uc = {};
  uc.uc_mcontext.pc = pc;
  uc.uc_mcontext.regs[SC_REG_LR] = lr;
  uc.uc_mcontext.regs[SC_REG_FP] = fp;
  uc.uc_mcontext.sp = sp;
  return uc;
}

TEST(CaptureBacktraceSynthetic, BufSizeTooSmallReturnsZero) {
  ucontext_t uc = make_uc(0x1000, 0x2000, 0, 0);
  uintptr_t buf[1] = {};
  EXPECT_EQ(capture_backtrace(&uc, buf, 0), 0);
  EXPECT_EQ(capture_backtrace(&uc, buf, 1), 0);
}

TEST(CaptureBacktraceSynthetic, NullFpStopsAfterPcAndLr) {
  ucontext_t uc = make_uc(0x1000, 0x2000, 0, 0x100);
  uintptr_t buf[8] = {};
  int depth = capture_backtrace(&uc, buf, 8);
  EXPECT_EQ(depth, 2);
  EXPECT_EQ(buf[0], 0x1000u);
  EXPECT_EQ(buf[1], 0x2000u);
}

TEST(CaptureBacktraceSynthetic, UnalignedFpStopsAfterPcAndLr) {
  // FP = 0x1001 is not 16-byte aligned.
  ucontext_t uc = make_uc(0x1000, 0x2000, 0x1001, 0x100);
  uintptr_t buf[8] = {};
  int depth = capture_backtrace(&uc, buf, 8);
  EXPECT_EQ(depth, 2);
}

TEST(CaptureBacktraceSynthetic, FpBelowSpStopsAfterPcAndLr) {
  // FP (0x100) < SP (0x200).
  ucontext_t uc = make_uc(0x1000, 0x2000, 0x100, 0x200);
  uintptr_t buf[8] = {};
  int depth = capture_backtrace(&uc, buf, 8);
  EXPECT_EQ(depth, 2);
}

TEST(CaptureBacktraceSynthetic, FpAboveActiveMappingStopsAfterPcAndLr) {
  uint8_t stack_var = 0;
  uintptr_t sp = reinterpret_cast<uintptr_t>(&stack_var);
  uintptr_t stack_bottom = 0;
  uintptr_t fp = 0;
  ASSERT_TRUE(android_find_current_thread_stack_limits(&stack_bottom, &fp));
  ucontext_t uc = make_uc(0x1000, 0x2000, fp, sp);
  uintptr_t buf[8] = {};
  int depth = capture_backtrace(&uc, buf, 8);

  EXPECT_EQ(depth, 2);
  EXPECT_EQ(buf[0], 0x1000u);
  EXPECT_EQ(buf[1], 0x2000u);
}

TEST(CaptureBacktraceSynthetic, FpRecordEndOverflowStopsAfterPcAndLr) {
  uint8_t stack_var = 0;
  uintptr_t sp = reinterpret_cast<uintptr_t>(&stack_var);
  // 16-byte aligned and above SP, but adding sizeof(frame_record) wraps.
  uintptr_t fp = UINTPTR_MAX - 15;
  ucontext_t uc = make_uc(0x1000, 0x2000, fp, sp);
  uintptr_t buf[8] = {};
  int depth = capture_backtrace(&uc, buf, 8);

  EXPECT_EQ(depth, 2);
  EXPECT_EQ(buf[0], 0x1000u);
  EXPECT_EQ(buf[1], 0x2000u);
}

TEST(CaptureBacktraceSynthetic, ValidFpChainWalks) {
  // Build a 3-frame FP chain on the heap. Each frame record is {next_fp, lr} and must be 16-byte
  // aligned and monotonically increasing.
  const size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);

  auto* frames = static_cast<uintptr_t*>(mem);
  // Layout:
  //   frame 0 at offset 0:  {next_fp = offset 32, lr = 0x3000}
  //   frame 1 at offset 32: {next_fp = offset 64, lr = 0x4000}
  //   frame 2 at offset 64: {next_fp = 0,         lr = 0x5000}
  // The walk reads LR from each frame before checking next_fp, so frame 2's LR is captured before
  // next_fp = 0 terminates the walk.
  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  frames[0] = base + 32;  // next FP
  frames[1] = 0x3000;     // LR
  frames[4] = base + 64;  // next FP (at offset 32)
  frames[5] = 0x4000;     // LR
  frames[8] = 0;          // next FP = 0 (terminates after this frame's LR)
  frames[9] = 0x5000;     // LR

  ucontext_t uc = make_uc(0x1000, 0x2000, base, base);
  uintptr_t buf[8] = {};
  int depth = capture_backtrace(&uc, buf, 8);

  EXPECT_EQ(depth, 5);  // PC + LR + 3 FP chain frames
  EXPECT_EQ(buf[0], 0x1000u);
  EXPECT_EQ(buf[1], 0x2000u);
  EXPECT_EQ(buf[2], 0x3000u);
  EXPECT_EQ(buf[3], 0x4000u);
  EXPECT_EQ(buf[4], 0x5000u);

  munmap(mem, page_size);
}

TEST(CaptureBacktraceSynthetic, BufSizeLimitsDepth) {
  // Same chain as above, but buf_size = 3 should cap the result at 3 frames.
  const size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);

  auto* frames = static_cast<uintptr_t*>(mem);
  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  frames[0] = base + 32;
  frames[1] = 0x3000;
  frames[4] = base + 64;
  frames[5] = 0x4000;
  frames[8] = 0;
  frames[9] = 0x5000;

  ucontext_t uc = make_uc(0x1000, 0x2000, base, base);
  uintptr_t buf[3] = {};
  int depth = capture_backtrace(&uc, buf, 3);

  EXPECT_EQ(depth, 3);  // PC + LR + 1 FP chain frame (capped)
  EXPECT_EQ(buf[0], 0x1000u);
  EXPECT_EQ(buf[1], 0x2000u);
  EXPECT_EQ(buf[2], 0x3000u);

  munmap(mem, page_size);
}

TEST(CaptureBacktraceSynthetic, NullLrInChainStops) {
  // Frame with LR = 0 should terminate the walk.
  const size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);

  auto* frames = static_cast<uintptr_t*>(mem);
  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  frames[0] = base + 32;  // next FP
  frames[1] = 0;          // LR = 0 -> stop

  ucontext_t uc = make_uc(0x1000, 0x2000, base, base);
  uintptr_t buf[8] = {};
  int depth = capture_backtrace(&uc, buf, 8);

  EXPECT_EQ(depth, 2);  // PC + LR only (first FP chain frame has LR=0)
  EXPECT_EQ(buf[0], 0x1000u);
  EXPECT_EQ(buf[1], 0x2000u);

  munmap(mem, page_size);
}

TEST(CaptureBacktraceSynthetic, NonMonotonicFpStops) {
  // Frame 0's next_fp points backward instead of growing. The walk should stop.
  const size_t page_size = static_cast<size_t>(sysconf(_SC_PAGESIZE));
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);

  auto* frames = static_cast<uintptr_t*>(mem);
  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  // Put first frame at offset 64, with next_fp pointing back to offset 32.
  uintptr_t fp0 = base + 64;
  frames[8] = base + 32;  // next FP goes backward
  frames[9] = 0x3000;     // LR

  ucontext_t uc = make_uc(0x1000, 0x2000, fp0, base);
  uintptr_t buf[8] = {};
  int depth = capture_backtrace(&uc, buf, 8);

  // Gets PC + LR + the frame from fp0 (LR = 0x3000), then next_fp goes backward and the walk stops.
  EXPECT_EQ(depth, 3);
  EXPECT_EQ(buf[0], 0x1000u);
  EXPECT_EQ(buf[1], 0x2000u);
  EXPECT_EQ(buf[2], 0x3000u);

  munmap(mem, page_size);
}

TEST(CaptureBacktraceSynthetic, UnmappedFpStopsGracefully) {
  // FP points to unmapped memory, so safe_read() should return false. Use an address in the middle
  // of a hole above any reasonable mapping.
  ucontext_t uc = make_uc(0x1000, 0x2000, 0x7DEAD0000000ULL, 0x100);
  uintptr_t buf[8] = {};
  int depth = capture_backtrace(&uc, buf, 8);
  EXPECT_EQ(depth, 2);  // PC + LR only; FP points to unmapped memory.
}

TEST(CaptureBacktraceSynthetic, PcEqualsLrEmitsBoth) {
  // capture_backtrace() always emits the raw LR, even when PC == LR. Stale LR detection is handled
  // by match_backtrace(), not capture_backtrace().
  ucontext_t uc = make_uc(0x1000, 0x1000, 0, 0x100);
  uintptr_t buf[8] = {};
  int depth = capture_backtrace(&uc, buf, 8);

  EXPECT_EQ(depth, 2);  // PC + LR (both emitted even though equal)
  EXPECT_EQ(buf[0], 0x1000u);
  EXPECT_EQ(buf[1], 0x1000u);
}

TEST(StackBounds, MainThreadStackBoundsFromMapsFindsCurrentStackVma) {
  uint8_t stack_var = 0;
  uintptr_t sp = reinterpret_cast<uintptr_t>(&stack_var);
  uintptr_t stack_bottom = 0;
  uintptr_t stack_top = 0;
  uintptr_t metadata_bottom = 0;
  uintptr_t metadata_top = 0;

  ASSERT_TRUE(android_find_current_thread_stack_limits(&metadata_bottom, &metadata_top));

  ASSERT_TRUE(get_main_thread_stack_bounds_from_maps(sp, metadata_top, &stack_bottom, &stack_top));
  EXPECT_LE(stack_bottom, sp);
  EXPECT_LT(sp, stack_top);
  EXPECT_LE(metadata_top, stack_top);
}

TEST(StackBounds, MainThreadStackBoundsFromMapsRejectsMismatchedTop) {
  uint8_t stack_var = 0;
  uintptr_t sp = reinterpret_cast<uintptr_t>(&stack_var);
  uintptr_t stack_bottom = 0;
  uintptr_t stack_top = 0;

  // stack_top must be in the same VMA as SP. Zero guarantees a mismatch.
  EXPECT_FALSE(get_main_thread_stack_bounds_from_maps(sp, 0, &stack_bottom, &stack_top));
}
