#include <dlfcn.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// Declared in libmte_suppression_test_crash.so.
namespace mte_suppression_test_crash {
void suppressed_path();
void unsuppressed_path();
void leaf_suppressed_path();
void gap_suppressed_path();
}

// Declared in libmte_suppression_test_nognuhash.so (DT_HASH only, no DT_GNU_HASH).
namespace mte_suppression_test_nognuhash {
void suppressed_path();
}

// Declared in libmte_suppression_test_a.so.
namespace mte_cross_dso_test {
void middle();
void outer(void (*mid)());
}

static __attribute__((noinline)) char* free_and_return(char* p) {
  free(p);
  return p;
}

int main(int argc, char** argv) {
  // Print args so the Java host test can identify our tombstones.
  for (int i = 0; i < argc; i++) {
    printf("arg[%d]=%s\n", i, argv[i]);
  }

  bool use_suppressed = false;
  bool use_unsuppressed = false;
  bool direct = false;
  bool cross_dso = false;
  bool same_dso = false;
  bool nognuhash = false;
  bool leaf = false;
  bool gap = false;
  for (int i = 1; i < argc; i++) {
    if (strcmp(argv[i], "--suppressed") == 0) {
      use_suppressed = true;
    } else if (strcmp(argv[i], "--unsuppressed") == 0) {
      use_unsuppressed = true;
    } else if (strcmp(argv[i], "--direct") == 0) {
      direct = true;
    } else if (strcmp(argv[i], "--cross-dso") == 0) {
      cross_dso = true;
    } else if (strcmp(argv[i], "--same-dso") == 0) {
      same_dso = true;
    } else if (strcmp(argv[i], "--nognuhash") == 0) {
      nognuhash = true;
    } else if (strcmp(argv[i], "--leaf") == 0) {
      leaf = true;
    } else if (strcmp(argv[i], "--gap") == 0) {
      gap = true;
    }
  }

  if (direct) {
    // Trigger MTE fault directly in main(), no .so involved.
    volatile char c = static_cast<volatile char*>(free_and_return(static_cast<char*>(malloc(1))))[0];
    (void)c;
  } else if (use_unsuppressed) {
    // Call through unsuppressed_path() -> trigger().
    // This call stack does NOT match the suppression pattern.
    mte_suppression_test_crash::unsuppressed_path();
  } else if (use_suppressed) {
    // Call through suppressed_path() -> trigger().
    // This call stack matches the suppression pattern.
    mte_suppression_test_crash::suppressed_path();
  } else if (cross_dso) {
    // outer@so_a -> middle@so_b -> inner@so_a.
    // The suppression pattern requires middle from so_b, so this matches.
    void* handle = dlopen("libmte_suppression_test_b.so", RTLD_NOW | RTLD_LOCAL);
    if (!handle) {
      printf("dlopen failed: %s\n", dlerror());
      return 1;
    }
    auto b_middle = reinterpret_cast<void (*)()>(
        dlsym(handle, "_ZN18mte_cross_dso_test6middleEv"));
    if (!b_middle) {
      printf("dlsym failed: %s\n", dlerror());
      return 1;
    }
    mte_cross_dso_test::outer(b_middle);
  } else if (same_dso) {
    // outer@so_a -> middle@so_a -> inner@so_a.
    // The suppression pattern requires middle from so_b, but here middle is
    // from so_a, so this should NOT match.
    mte_cross_dso_test::outer(&mte_cross_dso_test::middle);
  } else if (nognuhash) {
    // Call through suppressed_path() -> trigger() in the no-GNU-hash DSO.
    // This DSO has only DT_HASH (--hash-style=sysv), testing ELF hash fallback.
    mte_suppression_test_nognuhash::suppressed_path();
  } else if (leaf) {
    // Call through leaf_suppressed_path() -> leaf_trigger().
    // leaf_trigger is a leaf function (no bl/frame setup), so the raw LR
    // register holds the real caller address. Tests that match_backtrace
    // correctly matches frame[1] at bt[1] without needing the 1-slide.
    mte_suppression_test_crash::leaf_suppressed_path();
  } else if (gap) {
    // Call through gap_suppressed_path() -> gap_trigger().
    // gap_trigger calls malloc then noop() before faulting. bl noop clobbers
    // LR to an address inside gap_trigger but != the faulting PC. Tests that
    // stale-LR detection uses function range, not just LR == PC.
    mte_suppression_test_crash::gap_suppressed_path();
  } else {
    printf("usage: %s --suppressed|--unsuppressed|--direct|--cross-dso|--same-dso|--nognuhash|--leaf|--gap\n",
           argv[0]);
    return 1;
  }

  printf("mte_suppression_test: survived\n");
  return 0;
}
