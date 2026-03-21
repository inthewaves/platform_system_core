namespace mte_cross_dso_test {

// Resolved from libmte_suppression_test_a.so at load time.
void inner();

static volatile int side_effect;

// Cross-DSO middle: same mangled name as so_a's middle(), but lives in a
// different .so.  The suppression pattern requires middle to come from this
// .so, so calling through so_a's middle should NOT match.
__attribute__((noinline, visibility("default")))
void middle() {
  inner();
  side_effect = 3;
}

}  // namespace mte_cross_dso_test
