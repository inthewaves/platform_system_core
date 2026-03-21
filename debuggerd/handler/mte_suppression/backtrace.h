// Backtrace capture and matching for MTE crash suppression. This file keeps the stack-walk and
// pattern-match logic separate from the signal-handler entry point so it can be unit-tested.

#pragma once

#include <signal.h>
#include <stdint.h>
#include <sys/ucontext.h>

#include <async_safe/log.h>
#include <bionic/android_current_thread_stack_limits.h>
#include <bionic/pac.h>

#include "dso_lookup_util.h"
#include "maps_dso_search.h"
#include "maps_util.h"
#include "safe_read.h"
#include "suppression_pattern.h"

namespace mte_suppression {

// ============================================================================
// Backtrace capture
// ============================================================================

// sigcontext register indices for AArch64 (kernel regs[31] = x0..x30).
inline constexpr int SC_REG_FP = 29;  // x29 = frame pointer
inline constexpr int SC_REG_LR = 30;  // x30 = link register

inline bool get_main_thread_stack_bounds_from_maps(uintptr_t sp, uintptr_t stack_top,
                                                   uintptr_t* stack_bottom,
                                                   uintptr_t* resolved_stack_top) {
  // pthread_internal_t commonly leaves stack_bottom == 0 on the main thread. In that case, use a
  // narrow /proc/self/maps fallback for the single VMA that contains both SP and the known
  // stack_top, without using stdio in the signal-handler path.
  int fd = async_safe_open_readonly_cloexec("/proc/self/maps");
  if (fd < 0) return false;

  bool found = false;
  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    MapsEntry entry = {};
    if (!parse_maps_line(line, &entry)) return true;
    if (sp >= entry.start && sp < entry.end && stack_top >= entry.start && stack_top <= entry.end) {
      *stack_bottom = entry.start;
      *resolved_stack_top = entry.end;
      found = true;
      return false;
    }
    return true;
  });
  async_safe_close(fd);
  return found;
}

inline bool get_active_stack_bounds(uintptr_t sp, uintptr_t* stack_bottom, uintptr_t* stack_top) {
  stack_t ss = {};
  if (sigaltstack(nullptr, &ss) == 0 && (ss.ss_flags & SS_ONSTACK)) {
    // The handler itself runs on altstack, but the interrupted SP in ucontext is usually the
    // regular thread stack. Only use altstack bounds if the interrupted SP actually lies within the
    // alternate stack range. This is the same distinction made by bionic's frame-pointer walker in
    // bionic/libc/bionic/android_unsafe_frame_pointer_chase.cpp.
    uintptr_t top;
    if (__builtin_add_overflow(reinterpret_cast<uintptr_t>(ss.ss_sp), ss.ss_size, &top)) {
      return false;
    }
    uintptr_t bottom = reinterpret_cast<uintptr_t>(ss.ss_sp);
    if (sp >= bottom && sp < top) {
      *stack_bottom = bottom;
      *stack_top = top;
      return true;
    }
  }

  // Use bionic's per-thread stack metadata directly instead of scanning /proc/self/maps on every
  // unwind. android_find_current_thread_stack_limits() is a narrow platform wrapper over
  // __get_thread()->stack_top/stack_bottom, matching the metadata consumed by
  // bionic/libc/bionic/android_unsafe_frame_pointer_chase.cpp. This is also
  // safe for the linker fallback path: the linker already uses __get_thread() directly for its own
  // thread-local state.
  uintptr_t top = 0;
  uintptr_t bottom = 0;
  if (!android_find_current_thread_stack_limits(&bottom, &top)) return false;
  if (top == 0 || sp >= top) return false;

  if (bottom != 0 && sp >= bottom) {
    *stack_bottom = bottom;
    *stack_top = top;
    return true;
  }

  // On the main thread, bionic commonly knows only the upper end of the stack. The main thread is
  // initialized in
  // bionic/libc/bionic/__libc_init_main_thread.cpp, which sets stack_top from
  // argv but leaves stack_bottom as 0. Regular pthread-created threads get both bounds populated in
  // bionic/libc/bionic/pthread_create.cpp.
  //
  // The bionic helper intentionally leaves main-thread stack_bottom == 0 as-is. In the signal
  // handler, recover the missing lower bound with a narrow /proc/self/maps fallback: find the
  // single VMA that contains both the interrupted SP and the known stack_top. That avoids a full
  // general-purpose stack discovery pass.
  return bottom == 0 && get_main_thread_stack_bounds_from_maps(sp, top, stack_bottom, stack_top);
}

// Capture a backtrace from a signal ucontext using frame-pointer chain walking. Frame records are
// read via safe_read(), which uses process_vm_readv so a bad FP fails with EFAULT instead of
// faulting the handler. Returns the number of frames captured.
//
// Output layout: bt[0] = faulting PC, bt[1] = raw LR (x30), bt[2+] = FP chain.
//
// For leaf functions (no bl/frame setup), LR holds the real caller. For non-leaf functions, LR may
// be stale after a bl. match_backtrace detects the stale case by checking whether bt[1] falls
// within the same function as bt[0] and skips it if so.
//
// Leaf function example -- VendorGraphicBufferMeta::init (stallion BD6A libvendorgraphicbuffer.so):
//
// clang-format off
//   5680: bti   c                     // branch target identification
//   5684: cbz   x1, 5790              // null check on native_handle*
//   5688: ldr   w8, [x1]              // MTE fault: PC = 0x5688, reading stale handle
// clang-format on
//
// No stp, no bl, and no frame-pointer setup. LR holds the real caller (printLayer), so bt[1] is not
// in the same function as bt[0] and is kept.
//
// Non-leaf function example -- inner() (libmte_suppression_test_a.so):
//
// clang-format off
//   4038: stp   x29, x30, [sp, #16]  // prologue saves caller's LR to stack
//   403c: add   x29, sp, #0x10       // sets up frame pointer
//   4040: mov   w0, #0x1             // malloc(1)
//   4044: bl    <malloc>             // sets LR = 0x4048 (next insn, inside inner)
//   4048: ldrb  w8, [x0, #16]        // MTE fault: PC = LR = 0x4048
// clang-format on
//
// bt[1] (LR = 0x4048) is inside inner(), the same function as bt[0]. It is skipped, and bt[2] from
// the FP chain provides the real caller (middle).
//
// Non-leaf with gap -- gap_trigger() (libmte_suppression_test_crash.so):
//
// clang-format off
//   54130: paciasp
//   54134: stp   x29, x30, [sp, #-0x20]!
//   54138: str   x19, [sp, #0x10]
//   5413c: mov   x29, sp
//   54140: mov   w0, #0x1
//   54144: bl    <malloc>              // LR = 0x54148
//   54148: mov   x19, x0               // save malloc result in callee-saved reg
//   5414c: bl    <noop_int>            // LR = 0x54150
//   54150: adrp  x8, ...               // \
//   54154: ldr   x8, [x8, ...]         //  | store noop_int return value to side_effect
//   54158: str   w0, [x8]              // /
//   5415c: ldrb  w8, [x19, #0x10]      // MTE fault: PC = 0x5415c !=  LR = 0x54150
// clang-format on
//
// Unlike trigger(), where bl malloc is immediately followed by the faulting ldrb (giving LR == PC
// == 0x54048), noop_int() returns a value that the compiler stores via three instructions
// (0x54150-0x54158) before the faulting load at 0x5415c. LR (0x54150) != PC (0x5415c), but both are
// inside gap_trigger (0x54130-0x54170). match_backtrace detects the stale LR by checking the
// function address range, not PC == LR.
//
// AArch64 frame pointer convention:
//   *FP       = saved FP (previous frame's FP)
//   *(FP + 8) = saved LR (return address into the caller)
inline size_t capture_backtrace(ucontext_t* uc, uintptr_t* buf, size_t buf_size) {
  size_t n = 0;

  if (buf_size < 2) return 0;

  buf[n++] = __bionic_clear_pac_bits(uc->uc_mcontext.pc);               // bt[0] = faulting PC
  buf[n++] = __bionic_clear_pac_bits(uc->uc_mcontext.regs[SC_REG_LR]);  // bt[1] = raw LR

  uintptr_t fp = uc->uc_mcontext.regs[SC_REG_FP];
  uintptr_t sp = uc->uc_mcontext.sp;
  uintptr_t stack_bottom = 0;
  uintptr_t stack_top = 0;
  bool have_stack_bounds = get_active_stack_bounds(sp, &stack_bottom, &stack_top);

  while (n < buf_size) {
    // AAPCS64 "The Stack"
    // (https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#the-stack)
    // requires SP to remain 16-byte aligned and to stay within the thread's stack extent. Apply the
    // same basic invariants to the captured FP walk here: reject unaligned frame pointers and any
    // frame record that falls outside the resolved stack range.

    // Validate FP: must be non-null, 16-byte aligned (AArch64 ABI), and at or above SP (a FP below
    // SP points into already-popped stack space).
    if (fp == 0 || (fp & 0xF) || fp < sp) break;
    if (have_stack_bounds) {
      if (fp < stack_bottom) break;

      uintptr_t frame_end;
      // The frame record is 2 uintptr_t words: {saved_fp, saved_lr}. Check that fp +
      // sizeof(frame_record) does not wrap before comparing it against stack_top; a corrupted fp
      // near UINTPTR_MAX could otherwise overflow back into a low address and falsely appear
      // in-bounds.
      if (__builtin_add_overflow(fp, 2 * sizeof(uintptr_t), &frame_end)) break;
      if (frame_end > stack_top) break;
    }

    // Read the frame record via safe_read (process_vm_readv) so that an invalid FP returns false
    // rather than triggering a recursive SIGSEGV.
    uintptr_t frame[2] = {};
    if (!safe_read(frame, fp, sizeof(frame))) break;

    uintptr_t lr = __bionic_clear_pac_bits(frame[1]);
    if (lr == 0) break;
    buf[n++] = lr;

    // FP must grow monotonically upward through the stack.
    if (frame[0] <= fp) break;
    fp = frame[0];
  }
  return n;
}

// ============================================================================
// Backtrace matching
// ============================================================================

// Match a backtrace against a single suppression pattern. Returns true if every pattern frame
// matches the corresponding backtrace frame strictly by position, with stale-LR detection at bt[1].
//
// bt[0] = PC, bt[1] = raw LR, bt[2+] = FP chain. After matching frame[0] at bt[0], we check whether
// bt[1] (raw LR) also falls within frame[0]'s function. If so, the faulting function is non-leaf
// and LR was clobbered by a bl, so we skip bt[1] and match frame[1] at bt[2] instead. This is
// similar to how libunwind's get_frame_state() (extrarepos/libunwind/src/aarch64/Gstep.c) detects
// frame-record creation by scanning for stp/mov instructions, but simpler: we just check whether LR
// landed back in the same function.
//
// frame_dso_map[i] maps pattern frame i to ctx->infos[frame_dso_map[i]].
inline bool match_backtrace(const uintptr_t* backtrace, size_t bt_depth,
                            const SuppressionPattern& pat, const DsoSearchCtx& ctx,
                            const int* frame_dso_map) {
  size_t bt_offset = 0;  // bt index = frame_idx + bt_offset

  for (size_t frame_idx = 0; frame_idx < pat.frames.size(); frame_idx++) {
    size_t bt_idx = frame_idx + bt_offset;
    if (bt_idx >= bt_depth) {
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "mte_suppress: no match for frame[%zu] '%s' (bt too short)", frame_idx,
                            pat.frames[frame_idx].func_name);
      return false;
    }
    const DsoInfo& dso = ctx.infos[frame_dso_map[frame_idx]];
    const char* func_name = pat.frames[frame_idx].func_name;

    if (func_matches(backtrace[bt_idx], &dso, func_name)) {
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "mte_suppress: matched frame[%zu] '%s' at bt[%zu]=%p", frame_idx,
                            func_name, bt_idx, reinterpret_cast<void*>(backtrace[bt_idx]));

      // After matching frame[0], check if bt[1] (raw LR) is inside the same function. If so, LR was
      // clobbered by a bl and is stale -- skip it.
      if (frame_idx == 0 && bt_offset == 0 && bt_depth >= 2 &&
          func_matches(backtrace[1], &dso, func_name)) {
        bt_offset = 1;
        async_safe_format_log(ANDROID_LOG_WARN, "libc",
                              "mte_suppress: bt[1]=%p is in same function '%s', skipping stale LR",
                              reinterpret_cast<void*>(backtrace[1]), func_name);
      }
    } else {
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "mte_suppress: no match for frame[%zu] '%s' in '%s'", frame_idx,
                            func_name, pat.frames[frame_idx].dso_name);
      return false;
    }
  }
  return true;
}

}  // namespace mte_suppression
