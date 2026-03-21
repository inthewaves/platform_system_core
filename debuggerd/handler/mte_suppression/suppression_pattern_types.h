// Types and helper builders for MTE crash suppression stack patterns.

#pragma once

#include <array>
#include <span>

namespace mte_suppression {

// A single frame in a stack-trace pattern: DSO basename plus exact function name. If we ever need
// it, this could be extended with wildcard forms such as:
//   { *, * } for any frame
//   { somedsoname.so, * } for any symbol in one DSO
struct FramePattern {
  // Exact basename of the DSO, for example "libvendorgraphicbuffer.so".
  const char* _Nonnull dso_name;
  // Exact mangled symbol name. See the kMteSuppressions comment below.
  const char* _Nonnull func_name;
};

constexpr FramePattern FP(const char* _Nonnull dso_name, const char* _Nonnull func_name) {
  return {
      .dso_name = dso_name,
      .func_name = func_name,
  };
}

inline constexpr int kDefaultReenableTimerMs = 10;

// A named stack trace pattern. Frame 0 = PC, frame 1+ = callers. Each frame's DSO+function must be
// found in the corresponding position of the actual backtrace (PC, LR, FP chain).
struct SuppressionPattern {
  // Human-readable label for logging.
  const char* _Nonnull name;
  // Frames to match.
  std::span<const FramePattern> frames;
  // CLOCK_THREAD_CPUTIME_ID timer in ms before re-enabling MTE.
  int reenable_timer_ms = kDefaultReenableTimerMs;
};

template <size_t N>
struct SuppressionPatternDef {
  const char* _Nonnull name;
  std::array<FramePattern, N> frames;
  int reenable_timer_ms = kDefaultReenableTimerMs;

  // Build the lightweight span view used by kPatterns. The SuppressionPatternDef objects cannot go
  // directly into one array because SuppressionPatternDef<N> has a different type for each frame
  // count N. This is just small constexpr value construction: name pointer, span, and timer.
  constexpr SuppressionPattern view() const {
    return {
        .name = name,
        .frames = frames,
        .reenable_timer_ms = reenable_timer_ms,
    };
  }
};

template <typename... Frames>
constexpr auto MakeSuppressionPatternDef(const char* _Nonnull name, int reenable_timer_ms,
                                         Frames... frames) {
  static_assert(sizeof...(Frames) > 0, "SuppressionPatternDef must contain at least one frame");
  return SuppressionPatternDef<sizeof...(Frames)>{
      .name = name,
      .frames = std::array<FramePattern, sizeof...(Frames)>{frames...},
      .reenable_timer_ms = reenable_timer_ms,
  };
}

// How to match the process identity for a suppression entry.
enum class BinaryMatchType {
  // Match against /proc/self/exe (native daemons).
  kExePath,
  // Match against /proc/self/cmdline (app packages via app_process64).
  kCmdline,
};

// A binary and all its suppression patterns.
struct BinarySuppression {
  // How to identify the process.
  BinaryMatchType match_type;
  // Executable path or package name, depending on match_type.
  const char* _Nonnull binary;
  // Stack trace patterns for this binary.
  std::span<const SuppressionPattern> patterns;
};

}  // namespace mte_suppression
