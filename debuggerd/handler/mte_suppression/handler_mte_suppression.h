#pragma once

#include <signal.h>
#include <sys/ucontext.h>

namespace mte_suppression {

// Result of checking MTE suppression patterns against a crash.
struct MteSuppressionResult {
  // Matched pattern name, or nullptr if no pattern matched.
  const char* _Nullable pattern_name;
  // Per-pattern CLOCK_THREAD_CPUTIME_ID timer in ms before re-enabling MTE.
  int reenable_timer_ms;
};

// Check if the current MTE crash matches any known MTE suppression pattern. Returns the matched
// pattern name and its configured re-enable timer on match, or `{nullptr, 0}` if no pattern
// matched.
//
// Caller must save/restore errno before calling, for example via ErrnoRestorer, because this
// function uses syscalls that clobber errno (process_vm_readv, readlink, openat, read).
#ifdef __aarch64__
MteSuppressionResult mte_check_suppressions(siginfo_t* info, ucontext_t* uc);
#else
inline MteSuppressionResult mte_check_suppressions(siginfo_t*, ucontext_t*) {
  return {};
}
#endif

}  // namespace mte_suppression
