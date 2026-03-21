#include "handler_mte_suppression.h"

#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/ucontext.h>
#include <unistd.h>
#include <array>

#ifdef __aarch64__
#include <async_safe/log.h>

#include "backtrace.h"
#include "dso_lookup_util.h"
#include "maps_dso_search.h"
#include "maps_util.h"
#include "safe_read.h"
#include "suppression_pattern.h"

namespace mte_suppression {

// Poison getpid/gettid to prevent accidental use of libc-cached values in the signal handler.
#pragma GCC poison getpid gettid

// ============================================================================
// Generic MTE crash suppression framework.
//
// Allows suppressing known MTE crashes by matching the faulting stack trace against static
// patterns. Each pattern specifies an exact DSO basename and exact mangled symbol name for each
// frame. A pattern matches when every frame is found, in order, in the PC plus return-address
// chain.
//
// Symbol lookup uses ELF hash tables (DT_GNU_HASH / DT_HASH) for O(1) name-to-address resolution.
// An alternative linear .dynsym scan (address-to-name, reading symbol count from ELF section
// headers on disk like libunwindstack) was benchmarked but rejected: about 16 ms average vs 1.3 ms
// for hash lookup on a 3000-symbol test DSO, and about 19 ms vs 9 ms on real vendor DSOs with
// roughly 2700 symbols. The linear scan is simpler (~50 lines vs ~230) and handles DSOs missing
// DT_HASH, but the 10-15x slowdown is unnecessary given that all target DSOs have DT_GNU_HASH.
//
// To add a new suppression, see README.md.
// ============================================================================

// From debuggerd_handler.cpp Avoid other libc/libbase helpers here so we do not allocate or
// accidentally call something disallowed in the signal-handler path.
static const char* get_command_no_alloc(char* command, const size_t length) {
  int fd = async_safe_open_readonly_cloexec("/proc/self/cmdline");
  if (fd == -1) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "Opening /proc/self/cmdline failed: %s",
                          strerrorname_np(errno));
    return nullptr;
  }
  // Force the buffer to be NUL-terminated even if the first argument is longer than the buffer.
  // That may truncate argv[0], but the truncated basename is still usable for suppression matching.
  command[length - 1] = '\0';
  ssize_t bytes = TEMP_FAILURE_RETRY(read(fd, command, length - 1));
  async_safe_close(fd);
  if (bytes <= 0) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "/proc/self/cmdline read error: %s",
                          bytes == -1 ? strerrorname_np(errno) : "zero bytes read");
    return nullptr;
  }

  // Find the basename of the first argument in the command-line.
  const char* arg0 = strrchr(command, '/');
  return arg0 != nullptr ? &arg0[1] : command;
}

static const BinarySuppression* find_binary_suppression(const char* exe_path, const char* cmdline) {
  for (const auto& entry : kMteSuppressions) {
    switch (entry.match_type) {
      case BinaryMatchType::kExePath:
        if (strcmp(exe_path, entry.binary) == 0) return &entry;
        break;
      case BinaryMatchType::kCmdline:
        if (cmdline != nullptr && strcmp(cmdline, entry.binary) == 0) return &entry;
        break;
    }
  }
  return nullptr;
}

// --- Core matching engine ----------------------------------------------------

// Check whether the current crash matches any suppression pattern. Returns the pattern name on
// match, or nullptr.
//
// On each SEGV_MTESERR, this function:
//   1. Checks the process binary against each static pattern. If nothing
//      matches, the function exits and the binary crashes normally.
//   2. Scans /proc/self/maps to find the DSOs referenced by matching patterns
//      and reads their ELF headers for symbol/hash-table pointers.
//   3. Captures a backtrace from the faulting ucontext.
//   4. For each pattern frame, scans forward through the backtrace for an
//      address in the correct DSO and function via hash-based symbol lookup.
//
// There is no caching; every crash does a fresh maps scan and ELF parse. Crashes are rare, since
// the process is about to die or be suppressed, so simplicity is preferred over per-crash
// performance.

// Signal handler safety:
//
// This runs inside debuggerd_signal_handler on the direct path or via debuggerd_handle_signal on
// the sigchain path for app processes. Both paths share the same signal-handler properties:
//  - SA_ONSTACK: executes on bionic's per-thread alternate signal stack (~32KB on AArch64).
//  - SA_EXPOSE_TAGBITS: si_addr includes MTE tag bits.
//  - sa_mask (filled via sigfillset, applied by rt_sigaction): all signals are
//    blocked while the handler runs. This blocks only asynchronous delivery.
//    Per sigprocmask(2), if SIGSEGV is generated while blocked, for example by
//    dereferencing a corrupt pointer, the result is undefined. safe_read
//    (process_vm_readv) is essential to avoid this.
//  - async-signal-safe only: no heap allocation, no stdio.
//
// Reading /proc/self/maps and ELF data through raw syscalls and process_vm_readv stays within the
// async-signal-safe subset. All ELF memory reads use safe_read() so corrupt data cannot fault the
// handler.
MteSuppressionResult mte_check_suppressions(siginfo_t* info, ucontext_t* uc) {
  // We only support synchronous MTE errors (SEGV_MTESERR). Asynchronous errors (SEGV_MTEAERR) have
  // inaccurate backtraces because the reported pc is not the actual faulting instruction.
  if (info->si_code != SEGV_MTESERR) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "mte_suppress: not MTESERR (si_code=%d)",
                          info->si_code);
    return {};
  }

  if constexpr (max_binary_path_len() == 0) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "mte_suppress: no patterns are active");
    return {};
  }
  static_assert(kMteSuppressions.empty() || max_binary_path_len() > 0,
                "max_binary_path_len() must be non-zero when any suppression is active");

  // Check which binary we are.
  char exe_path[max_binary_path_len() + 1];
  ssize_t exe_len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
  if (exe_len <= 0) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "mte_suppress: readlink failed (%zd)", exe_len);
    return {};
  }
  exe_path[exe_len] = '\0';

  // For app processes (app_process64), read /proc/self/cmdline to get the package name. After
  // zygote specialization, cmdline is set to that package name. This is weaker than /proc/self/exe
  // because /proc/self/cmdline reflects process memory rather than mm->exe_file.
  const char* cmdline = nullptr;
  char cmdline_buf[max_binary_path_len() + 1];
  if (strcmp(exe_path, "/system/bin/app_process64") == 0) {
    if constexpr (!is_any_app_suppression_pattern_active()) {
      async_safe_format_log(ANDROID_LOG_WARN, "libc", "mte_suppress: no app patterns are active");
      return {};
    }

    cmdline = get_command_no_alloc(cmdline_buf, sizeof(cmdline_buf));
  }

  async_safe_format_log(ANDROID_LOG_WARN, "libc", "mte_suppress: check exe=%s cmdline=%s", exe_path,
                        cmdline ? cmdline : "(null)");

  const BinarySuppression* bin = find_binary_suppression(exe_path, cmdline);
  if (bin == nullptr) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc",
                          "mte_suppress: no suppressions for exe='%s' cmdline='%s'", exe_path,
                          cmdline ? cmdline : "(null)");
    return {};
  }

  // Capture backtrace from the faulting context.
  uintptr_t backtrace[kMaxFrames + 2] = {};
  size_t bt_depth = capture_backtrace(uc, backtrace, kMaxFrames + 2);
  if (bt_depth <= 0) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "mte_suppress: unable to capture backtrace");
    return {};
  }

  async_safe_format_log(ANDROID_LOG_WARN, "libc", "mte_suppress: bt_depth=%zu pc=%p", bt_depth,
                        reinterpret_cast<void*>(backtrace[0]));

  for (const auto& pat : bin->patterns) {
    // Do executable-frame classification and pattern-specific DSO collection in one /proc/self/maps
    // scan so both decisions see the same VMA snapshot. There is no cross-pattern caching. If
    // several patterns reference overlapping DSOs, each pattern repeats this scan for simplicity.
    bool bt_in_exec_map[kMaxFrames + 2] = {};
    int frame_dso_map[kMaxFrames] = {};
    DsoSearchCtx ctx = {};
    int num_dsos = collect_executable_frames_and_find_pattern_dsos_for_backtrace(
        pat, backtrace, bt_depth, bt_in_exec_map, frame_dso_map, &ctx);
    if (num_dsos < 0) continue;

    // All DSOs must be found for this pattern to be checked.
    if (ctx.found != num_dsos) {
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "mte_suppress: pattern '%s' skipped (found %d/%d DSOs)", pat.name,
                            ctx.found, num_dsos);
      continue;
    }

    if (match_backtrace(backtrace, bt_depth, pat, ctx, frame_dso_map)) {
      async_safe_format_log(ANDROID_LOG_WARN, "libc", "mte_suppress: MATCH pattern='%s' pc=%p",
                            pat.name, reinterpret_cast<void*>(backtrace[0]));
      return {pat.name, pat.reenable_timer_ms};
    }
  }
  async_safe_format_log(ANDROID_LOG_WARN, "libc", "mte_suppress: no pattern matched");
  return {};
}

}  // namespace mte_suppression
#endif  // __aarch64__
