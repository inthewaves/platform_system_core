// Static suppression table. To add a new suppression, see README.md. Each backtrace pattern matches
// any backtrace with that prefix.

#pragma once

#include <algorithm>

#include "suppression_pattern_types.h"

namespace mte_suppression {

namespace hwc3_pixel {
inline constexpr const char* _Nonnull kBinary =
    "/vendor/bin/hw/android.hardware.composer.hwc3-service.pixel";
// HWC crash -> init restarts HWC -> init restarts SurfaceFlinger -> system_server sees
// SurfaceFlinger die -> soft reboot.
inline constexpr auto kIgnoreLayerBuffer = MakeSuppressionPatternDef(
    "hwc_stale_ignore_layer_buffer",
    // 50ms: printDebugInfos iterates all ignoreLayers, stale pointers recur every frame.
    // Theoretically, this timer becomes less sufficient the more often the bug triggers, because
    // every external-display disconnect and reconnect adds more stale pointers to mIgnoreLayers.
    // With too small a re-enable timer, MTE crashes will recur constantly. The other occurrences
    // should be absorbed by tombstone-generation rate limiting.
    50,
    // #00 VendorGraphicBufferMeta::init (PC)
    FP("libvendorgraphicbuffer.so",
       "_ZN6vendor8graphics23VendorGraphicBufferMeta4initEPK13native_handle"),
    // #01 ExynosLayer::printLayer
    FP("libexynosdisplay.so", "_ZN11ExynosLayer10printLayerEv"),
    // #02 ExynosDisplay::printDebugInfos
    FP("libexynosdisplay.so", "_ZN13ExynosDisplay15printDebugInfosERN7android7String8E"),
    // #03 ExynosDisplay::deliverWinConfigData
    FP("libexynosdisplay.so", "_ZN13ExynosDisplay20deliverWinConfigDataEv"),
    // #04 gs101::ExynosExternalDisplayModule::deliverWinConfigData
    FP("libexynosdisplay.so", "_ZN5gs10127ExynosExternalDisplayModule20deliverWinConfigDataEv"),
    // #05 ExynosDisplay::presentDisplay
    FP("libexynosdisplay.so", "_ZN13ExynosDisplay14presentDisplayEPi"),
    // #06 ExynosExternalDisplay::presentDisplay
    FP("libexynosdisplay.so", "_ZN21ExynosExternalDisplay14presentDisplayEPi"));

// This crash can happen immediately after we suppress hwc_stale_ignore_layer_buffer. This dump path
// is covered by the same MTE-off window because printDebugInfos calls printLayer and then dump for
// each layer in the same loop iteration.
inline constexpr auto kIgnoreLayerDump = MakeSuppressionPatternDef(
    "hwc_stale_ignore_layer_dump",
    50,  // same loop as printLayer, same stale-pointer bug
    // #00 VendorGraphicBufferMeta::init (PC)
    FP("libvendorgraphicbuffer.so",
       "_ZN6vendor8graphics23VendorGraphicBufferMeta4initEPK13native_handle"),
    // #01 ExynosLayer::dump (alternate caller, same bug as printLayer path)
    FP("libexynosdisplay.so", "_ZN11ExynosLayer4dumpERN7android7String8E"),
    // #02 ExynosDisplay::printDebugInfos
    FP("libexynosdisplay.so", "_ZN13ExynosDisplay15printDebugInfosERN7android7String8E"),
    // #03 ExynosDisplay::deliverWinConfigData
    FP("libexynosdisplay.so", "_ZN13ExynosDisplay20deliverWinConfigDataEv"),
    // #04 gs101::ExynosExternalDisplayModule::deliverWinConfigData
    FP("libexynosdisplay.so", "_ZN5gs10127ExynosExternalDisplayModule20deliverWinConfigDataEv"),
    // #05 ExynosDisplay::presentDisplay
    FP("libexynosdisplay.so", "_ZN13ExynosDisplay14presentDisplayEPi"),
    // #06 ExynosExternalDisplay::presentDisplay
    FP("libexynosdisplay.so", "_ZN21ExynosExternalDisplay14presentDisplayEPi"));

// MTE crash during adb shell dumpsys SurfaceFlinger
inline constexpr auto kIgnoreLayerMiniDump = MakeSuppressionPatternDef(
        "hwc_stale_ignore_layer_minidump",
        50,  // same loop as printLayer, same stale-pointer bug
        FP("libvendorgraphicbuffer.so",
           "_ZN6vendor8graphics23VendorGraphicBufferMeta4initEPK13native_handle"),
        FP("libexynosdisplay.so", "_ZN11ExynosLayer8miniDumpER12TableBuilder"),
        // #02 ExynosDisplay::printDebugInfos
        FP("libexynosdisplay.so", "_ZN13ExynosDisplay8miniDumpERN7android7String8E"),
        // #03 ExynosDisplay::deliverWinConfigData
        FP("libexynosdisplay.so", "_ZN12ExynosDevice4dumpERN7android7String8ERKNSt3__16vectorINS3_12basic_stringIcNS3_11char_traitsIcEENS3_9allocatorIcEEEENS8_ISA_EEEE"));

inline constexpr SuppressionPattern kPatterns[] = {
    kIgnoreLayerBuffer.view(),
    kIgnoreLayerDump.view(),
    kIgnoreLayerMiniDump.view(),
};
}  // namespace hwc3_pixel

#if ANDROID_DEBUGGABLE
namespace mte_test {
inline constexpr const char* _Nonnull kBinary = "/data/local/tmp/mte_suppression_test_crash";
inline constexpr auto kTestSuppression = MakeSuppressionPatternDef(
    "test_mte_suppression", 10,
    FP("libmte_suppression_test_crash.so", "_ZN26mte_suppression_test_crash7triggerEv"),
    FP("libmte_suppression_test_crash.so", "_ZN26mte_suppression_test_crash15suppressed_pathEv"));
inline constexpr auto kNoGnuHashSuppression = MakeSuppressionPatternDef(
    "test_nognuhash_suppression", 10,
    FP("libmte_suppression_test_nognuhash.so", "_ZN30mte_suppression_test_nognuhash7triggerEv"),
    FP("libmte_suppression_test_nognuhash.so",
       "_ZN30mte_suppression_test_nognuhash15suppressed_pathEv"));
inline constexpr auto kLeafSuppression = MakeSuppressionPatternDef(
    "test_leaf_suppression", 10,
    FP("libmte_suppression_test_crash.so", "_ZN26mte_suppression_test_crash12leaf_triggerEPc"),
    FP("libmte_suppression_test_crash.so",
       "_ZN26mte_suppression_test_crash20leaf_suppressed_pathEv"));
inline constexpr auto kGapSuppression = MakeSuppressionPatternDef(
    "test_gap_suppression", 10,
    FP("libmte_suppression_test_crash.so", "_ZN26mte_suppression_test_crash11gap_triggerEv"),
    FP("libmte_suppression_test_crash.so",
       "_ZN26mte_suppression_test_crash19gap_suppressed_pathEv"));
inline constexpr auto kCrossDsoSuppression = MakeSuppressionPatternDef(
    "test_cross_dso_suppression", 10,
    FP("libmte_suppression_test_a.so", "_ZN18mte_cross_dso_test5innerEv"),
    FP("libmte_suppression_test_b.so", "_ZN18mte_cross_dso_test6middleEv"),
    FP("libmte_suppression_test_a.so", "_ZN18mte_cross_dso_test5outerEPFvvE"));
inline constexpr SuppressionPattern kPatterns[] = {
    kTestSuppression.view(), kNoGnuHashSuppression.view(), kLeafSuppression.view(),
    kGapSuppression.view(),  kCrossDsoSuppression.view(),
};
}  // namespace mte_test

namespace mte_test_app {
inline constexpr const char* _Nonnull kPackage = "com.android.tests.debuggerd.mtesuppression";
inline constexpr const char* _Nonnull kPackageExtracted =
    "com.android.tests.debuggerd.mtesuppression.extracted";
}  // namespace mte_test_app
#endif

inline constexpr auto kMteSuppressions = std::array{
    BinarySuppression{BinaryMatchType::kExePath, hwc3_pixel::kBinary, hwc3_pixel::kPatterns},
#if ANDROID_DEBUGGABLE
    BinarySuppression{BinaryMatchType::kExePath, mte_test::kBinary, mte_test::kPatterns},
    BinarySuppression{BinaryMatchType::kCmdline, mte_test_app::kPackage, mte_test::kPatterns},
    BinarySuppression{BinaryMatchType::kCmdline, mte_test_app::kPackageExtracted,
                      mte_test::kPatterns},
#endif
};

// ============================================================================
// Static assertions and properties derived from kMteSuppressions
// ============================================================================

constexpr bool cstr_equal(const char* _Nonnull a, const char* _Nonnull b) {
  for (; *a != '\0' && *b != '\0'; a++, b++) {
    if (*a != *b) return false;
  }
  return *a == '\0' && *b == '\0';
}

constexpr size_t max_pattern_frame_count() {
  size_t max_count = 0;
  for (const auto& bin : kMteSuppressions) {
    for (const auto& pat : bin.patterns) {
      size_t count = pat.frames.size();
      if (count > max_count) max_count = count;
    }
  }
  return max_count;
}

// Maximum pattern depth supported by the current static table. Keep this at least 1 so the
// signal-handler scratch arrays remain well-formed even if the table is empty in some build
// configuration.
inline constexpr size_t kMaxFrames = std::max(size_t{1}, max_pattern_frame_count());

constexpr int max_pattern_dso_count() {
  int max_count = 0;
  for (const auto& bin : kMteSuppressions) {
    for (const auto& pat : bin.patterns) {
      int count = 0;
      for (size_t frame_idx = 0; frame_idx < pat.frames.size(); frame_idx++) {
        bool already_seen = false;
        for (size_t prev_idx = 0; prev_idx < frame_idx; prev_idx++) {
          if (cstr_equal(pat.frames[prev_idx].dso_name, pat.frames[frame_idx].dso_name)) {
            already_seen = true;
            break;
          }
        }
        if (!already_seen) count++;
      }
      max_count = std::max(max_count, count);
    }
  }
  return max_count;
}

// Maximum number of unique DSO names referenced by one SuppressionPattern. This is derived from
// the current static table and kept at least 2 so cross-DSO scratch state stays well-formed even
// if the table temporarily collapses to only single-DSO patterns in some build configuration.
inline constexpr int kMaxDsos = std::max(2, max_pattern_dso_count());

// Returns the longest binary/package string in the table, or the length of
// "/system/bin/app_process64" (whichever is greater). The exe_path buffer must be large enough for
// app_process64 even when only kCmdline entries exist.
constexpr size_t max_binary_path_len() {
  if (kMteSuppressions.empty()) {
    return 0;
  }
  size_t max_len = std::char_traits<char>::length("/system/bin/app_process64");
  for (const auto& binarySuppression : kMteSuppressions) {
    size_t len = std::char_traits<char>::length(binarySuppression.binary);
    if (len > max_len) max_len = len;
  }
  return max_len;
}

constexpr bool is_any_app_suppression_pattern_active() {
  for (const auto& binarySuppression : kMteSuppressions) {
    if (binarySuppression.match_type == BinaryMatchType::kCmdline) {
      return true;
    }
  }
  return false;
}

constexpr bool all_binary_paths_unique() {
  for (size_t i = 0; i < kMteSuppressions.size(); i++) {
    for (size_t j = i + 1; j < kMteSuppressions.size(); j++) {
      const char* a = kMteSuppressions[i].binary;
      const char* b = kMteSuppressions[j].binary;
      if (cstr_equal(a, b)) return false;
    }
  }
  return true;
}
static_assert(all_binary_paths_unique(), "each BinarySuppression must have a unique binary path");

constexpr bool all_patterns_valid() {
  for (const auto& bin : kMteSuppressions) {
    if (bin.binary == nullptr || bin.patterns.empty()) return false;
    for (const auto& pat : bin.patterns) {
      if (pat.name == nullptr || pat.reenable_timer_ms <= 0) return false;
      size_t count = pat.frames.size();
      if (count == 0 || count > kMaxFrames) return false;
      for (const auto& frame : pat.frames) {
        if (frame.dso_name == nullptr || frame.func_name == nullptr) return false;
      }
    }
  }
  return true;
}
static_assert(all_patterns_valid(),
              "every BinarySuppression must have non-null binary with 1+ patterns, each with "
              "non-null name, reenable_timer_ms > 0, 1..derived kMaxFrames frames, and non-null "
              "dso_name/func_name per frame");

}  // namespace mte_suppression
