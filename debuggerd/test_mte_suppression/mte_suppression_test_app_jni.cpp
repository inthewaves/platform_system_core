// JNI wrapper for MTE suppression test crash functions.
// This lets an Android app trigger the same crash paths as the native test binary.

#include <dlfcn.h>
#include <jni.h>
#include <stdlib.h>
#include <string.h>

// Declared in libmte_suppression_test_crash.so.
namespace mte_suppression_test_crash {
void suppressed_path();
void unsuppressed_path();
void leaf_suppressed_path();
void gap_suppressed_path();
}

// Declared in libmte_suppression_test_nognuhash.so.
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

extern "C" {

JNIEXPORT void JNICALL
Java_com_android_tests_debuggerd_mtesuppression_CrashActivity_nativeSuppressedCrash(
    JNIEnv*, jclass) {
  mte_suppression_test_crash::suppressed_path();
}

JNIEXPORT void JNICALL
Java_com_android_tests_debuggerd_mtesuppression_CrashActivity_nativeUnsuppressedCrash(
    JNIEnv*, jclass) {
  mte_suppression_test_crash::unsuppressed_path();
}

JNIEXPORT void JNICALL
Java_com_android_tests_debuggerd_mtesuppression_CrashActivity_nativeDirectCrash(
    JNIEnv*, jclass) {
  volatile char c = static_cast<volatile char*>(free_and_return(static_cast<char*>(malloc(1))))[0];
  (void)c;
}

JNIEXPORT void JNICALL
Java_com_android_tests_debuggerd_mtesuppression_CrashActivity_nativeCrossDsoCrash(
    JNIEnv*, jclass) {
  void* handle = dlopen("libmte_suppression_test_b.so", RTLD_NOW | RTLD_LOCAL);
  if (!handle) return;
  auto b_middle = reinterpret_cast<void (*)()>(
      dlsym(handle, "_ZN18mte_cross_dso_test6middleEv"));
  if (!b_middle) return;
  mte_cross_dso_test::outer(b_middle);
}

JNIEXPORT void JNICALL
Java_com_android_tests_debuggerd_mtesuppression_CrashActivity_nativeSameDsoCrash(
    JNIEnv*, jclass) {
  mte_cross_dso_test::outer(&mte_cross_dso_test::middle);
}

JNIEXPORT void JNICALL
Java_com_android_tests_debuggerd_mtesuppression_CrashActivity_nativeNoGnuHashCrash(
    JNIEnv*, jclass) {
  mte_suppression_test_nognuhash::suppressed_path();
}

JNIEXPORT void JNICALL
Java_com_android_tests_debuggerd_mtesuppression_CrashActivity_nativeLeafCrash(
    JNIEnv*, jclass) {
  mte_suppression_test_crash::leaf_suppressed_path();
}

JNIEXPORT void JNICALL
Java_com_android_tests_debuggerd_mtesuppression_CrashActivity_nativeGapCrash(
    JNIEnv*, jclass) {
  mte_suppression_test_crash::gap_suppressed_path();
}

}  // extern "C"
