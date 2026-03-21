#include <stdlib.h>

namespace mte_suppression_test_crash {

// Returns the freed pointer so the caller can fault on the stale address without adding an
// extra instruction gap after the final call.
static __attribute__((noinline)) char* free_and_return(char* p) {
  free(p);
  return p;
}

// Triggers an MTE heap use-after-free read. Reading through the stale pointer keeps the fault in
// the same allocation slot, which avoids the flaky guard-page ACCERR seen with the older
// malloc(1) + p[16] out-of-bounds test.
__attribute__((noinline, visibility("default")))
void trigger() {
  volatile char c = static_cast<volatile char*>(free_and_return(static_cast<char*>(malloc(1))))[0];
  (void)c;
}

// Side-effect target to prevent tail call optimization and ICF.
// Without this, the compiler turns the wrappers into tail calls (`b trigger`),
// so they never appear on the backtrace.  The volatile write after trigger()
// forces a `bl trigger` + return sequence, giving each wrapper its own frame.
// Different values also prevent ICF (Identical Code Folding).
volatile int side_effect;

// Two wrappers that both call trigger().  The suppression pattern only matches
// the call stack through suppressed_path, so unsuppressed_path should crash.
__attribute__((noinline, visibility("default")))
void suppressed_path() {
  trigger();
  side_effect = 1;
}

__attribute__((noinline, visibility("default")))
void unsuppressed_path() {
  trigger();
  side_effect = 2;
}

// Leaf function: receives a stale tagged pointer and accesses it without any function calls. No
// stp/bl/frame pointer setup, so the raw LR register holds the real caller address. This mirrors
// VendorGraphicBufferMeta::init in production.
__attribute__((noinline, visibility("default")))
void leaf_trigger(char* p) {
  volatile char c = static_cast<volatile char*>(p)[0];
  (void)c;
}

// Wrapper that allocates then frees a tagged pointer and calls leaf_trigger. side_effect write
// prevents tail-call optimization of leaf_trigger.
__attribute__((noinline, visibility("default")))
void leaf_suppressed_path() {
  char* p = free_and_return(static_cast<char*>(malloc(1)));
  leaf_trigger(p);
  side_effect = 3;
}

// Non-leaf with gap: calls free_and_return, then noop_int (which returns a value used after the
// faulting load), then faults. The compiler must insert at least one instruction between
// bl noop_int's return point and the faulting ldrb (to save or use the return value), so LR
// points to a different address than PC, but both are inside gap_trigger.
//
// This tests that stale-LR detection checks the function address range
// (st_value to st_value+st_size), not just LR == PC. Compare with trigger() where
// bl free_and_return is immediately followed by the faulting ldrb, giving LR == PC.
//
// Current aarch64 builds disassemble to this relevant shape in
// out/host/linux-x86/testcases/mte_suppression_test/libmte_suppression_test_crash.so
// (`llvm-objdump -d -C --no-show-raw-insn ...`):
//
// clang-format off
//   gap_trigger:
//     paciasp
//     stp   x29, x30, [sp, ...]
//     str   x19, [sp, ...]
//     mov   x29, sp
//     mov   w0, #0x1
//     bl    <malloc>
//     mov   x19, x0                 // save stale pointer before the free helper call
//     bl    <free_and_return local helper>
//     bl    <noop_int>              // LR = B
//   B: adrp  x8, ...
//     ldr   x8, [x8, ...]
//     str   w0, [x8]                // store noop_int return value; LR still = B
//     ldrb  w8, [x19]               // MTE fault: PC = B+0xc; LR = B
// clang-format on
//
// PC != LR, both inside gap_trigger. bt[1] is stale and should be skipped.
__attribute__((noinline, visibility("default")))
int noop_int() {
  // Returns a value so the caller must handle it after the bl, inserting
  // instructions between bl's return point and the faulting load.
  return side_effect;
}

__attribute__((noinline, visibility("default")))
void gap_trigger() {
  char* p = free_and_return(static_cast<char*>(malloc(1)));
  side_effect = noop_int();  // bl noop_int; compiler emits store after return, before fault
  volatile char c = static_cast<volatile char*>(p)[0];
  // MTE fault: PC here, LR = return point of bl noop_int above
  (void)c;
}

__attribute__((noinline, visibility("default")))
void gap_suppressed_path() {
  gap_trigger();
  side_effect = 4;
}

}  // namespace mte_suppression_test_crash

// 3000 dummy symbols with random names to inflate .dynsym, matching real vendor
// DSOs (e.g. libexynosdisplay.so has ~2700 symbols). Random names ensure the
// mangled symbol order is worst-case for linear scan benchmarks.
namespace mte_suppression_test_dummy {
#define DUMMY(name, id) \
  __attribute__((noinline, visibility("default"))) void name() { \
    mte_suppression_test_crash::side_effect = id; \
  }
#include "dummy_syms.inc"
#undef DUMMY
}  // namespace mte_suppression_test_dummy
