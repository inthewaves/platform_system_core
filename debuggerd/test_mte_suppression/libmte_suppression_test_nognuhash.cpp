#include <stdlib.h>

// Identical to libmte_suppression_test_crash but compiled with --hash-style=sysv
// (DT_HASH only, no DT_GNU_HASH). Tests that the suppression handler falls back
// to ELF hash lookup when GNU hash is unavailable.
namespace mte_suppression_test_nognuhash {

static __attribute__((noinline)) char* free_and_return(char* p) {
  free(p);
  return p;
}

__attribute__((noinline, visibility("default")))
void trigger() {
  volatile char c = static_cast<volatile char*>(free_and_return(static_cast<char*>(malloc(1))))[0];
  (void)c;
}

volatile int side_effect;

__attribute__((noinline, visibility("default")))
void suppressed_path() {
  trigger();
  side_effect = 1;
}

}  // namespace mte_suppression_test_nognuhash
