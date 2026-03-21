// Tiny shared library built with --hash-style=both (DT_HASH + DT_GNU_HASH). Used by
// dso_lookup_util_test to exercise elf_hash_lookup against a DSO that is guaranteed to have
// DT_HASH, regardless of the platform default.

#include <stdint.h>

extern "C" {

__attribute__((noinline, visibility("default"))) int dso_test_add(int a, int b) {
  return a + b;
}

__attribute__((noinline, visibility("default"))) int dso_test_mul(int a, int b) {
  return a * b;
}

__attribute__((noinline, visibility("default"))) uint64_t dso_test_identity(uint64_t x) {
  return x;
}

}  // extern "C"
