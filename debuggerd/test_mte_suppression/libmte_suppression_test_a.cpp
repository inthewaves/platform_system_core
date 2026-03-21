#include <stdlib.h>

namespace mte_cross_dso_test {

static volatile int side_effect;

static __attribute__((noinline)) char* free_and_return(char* p) {
  free(p);
  return p;
}

// Triggers an MTE heap use-after-free read.
__attribute__((noinline, visibility("default")))
void inner() {
  volatile char c = static_cast<volatile char*>(free_and_return(static_cast<char*>(malloc(1))))[0];
  (void)c;
}

// Same-DSO middle: calls inner() within this .so.
// Has the same mangled name as libmte_suppression_test_b.so's middle().
__attribute__((noinline, visibility("default")))
void middle() {
  inner();
  side_effect = 1;
}

// Calls whichever middle function pointer is passed in.
__attribute__((noinline, visibility("default")))
void outer(void (*mid)()) {
  mid();
  side_effect = 2;
}

}  // namespace mte_cross_dso_test
