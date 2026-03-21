// /proc/self/maps DSO search for MTE crash suppression. This file keeps the basename/SONAME-based
// DSO resolution logic separate from the signal-handler entry point so it can be unit-tested on
// aarch64 devices.
//
// Scans /proc/self/maps to find DSOs by basename for normal DSOs or by DT_SONAME for APK-embedded
// DSOs, then resolves their ELF symbol/hash-table pointers via parse_dso_elf.
//
// We use /proc/self/maps instead of dl_iterate_phdr because debuggerd_handler.cpp is compiled into
// libc itself. At link time, dl_iterate_phdr resolves to the static implementation in
// bionic/libc/bionic/dl_iterate_phdr_static.cpp, which reports only the main
// executable and the vdso, not dynamically loaded shared libraries. The linker's full
// implementation (__loader_dl_iterate_phdr in
// bionic/linker/dlfcn.cpp) walks the solist but is not accessible from within
// libc.

#pragma once

#include <string.h>
#include <unistd.h>

#include <async_safe/log.h>

#include "dso_lookup_util.h"
#include "maps_util.h"
#include "suppression_pattern.h"

namespace mte_suppression {

// Maximum number of basename/SONAME candidate DSOs collected for one pattern before we reject the
// match. This is not derived from the static pattern table; it depends on runtime process state,
// for example:
//   - how many /proc/self/maps entries share a basename
//   - how many APK entries expose the same DT_SONAME
//   - how many duplicate copies of one DSO are mapped in the process
// libunwindstack explicitly synthesizes multiple APKs in one process in
// system/unwinding/libunwindstack/tests/ElfCacheTest.cpp with app_one.apk and app_two.apk. Real
// app processes can also load multiple APK paths via split APKs, feature APKs, etc.
inline constexpr int kMaxPatternDsoCandidates = kMaxDsos * 3;

// Context for backtrace-driven DSO resolution that collects candidate DSOs by name and records
// whether any slot became ambiguous.
struct DsoSearchCtx {
  // DSO names to search for, matched against the maps basename or DT_SONAME for APK-embedded DSOs.
  const char* _Nullable names[kMaxDsos];
  // Resolved DSO info, parallel to names[].
  DsoInfo infos[kMaxDsos];
  // True when multiple distinct DSOs matched the same requested name.
  bool ambiguous[kMaxDsos];
  // Number of DSO slots requested for this pattern.
  int count;
  // Number of DSO slots resolved so far.
  int found;
};

struct PatternDsoCandidate {
  // Unique DSO slot within the current pattern.
  int dso_slot;
  // Candidate DSO for that slot.
  DsoInfo info;
};

// Try to turn one file-backed maps entry into a resolved ELF candidate for one pattern DSO slot.
// Normal DSOs can match directly from the offset=0 file name, while APK-backed entries need
// parse_dso_elf() to recover the embedded ELF metadata and DT_SONAME from the mapped bytes.
inline bool resolve_pattern_dso_candidate(const MapsEntry& entry, const DsoSearchCtx& ctx,
                                          int* _Nonnull slot, DsoInfo* _Nonnull candidate) {
  *slot = -1;
  *candidate = {};

  if (entry.offset == 0) {
    // Normal DSOs are matched by basename from the offset=0 file-backed mapping.
    // Later r-x/r--/rw- mappings for the same .so are not added as separate candidates.
    const char* slash = strrchr(entry.name, '/');
    const char* match_name = slash ? slash + 1 : entry.name;
    for (int dso_idx = 0; dso_idx < ctx.count; dso_idx++) {
      if (strcmp(match_name, ctx.names[dso_idx]) == 0) {
        *slot = dso_idx;
        break;
      }
    }
    return *slot >= 0 && parse_dso_elf(entry.start, entry.end, candidate);
  }

  // APK-embedded DSOs are identified by DT_SONAME from the mapped embedded ELF, not by the .apk
  // path itself. Actual tombstones in
  // docs/bugreports/vendor-crash-recent-tombstones/tombstones/tombstone_22 and tombstone_28 show
  // plain `/data/app/.../base.apk` entries in the memory map and
  // `/data/app/.../base.apk!libmte_suppression_test_a.so` /
  // `/data/app/.../base.apk!libmte_suppression_test_crash.so` in the backtrace. The maps path
  // shows only the APK; the actual library identity comes from DT_SONAME. libunwindstack formats
  // the `apk!soname.so` spelling in system/unwinding/libunwindstack/MapInfo.cpp
  // MapInfo::GetFullName().
  size_t name_len = strlen(entry.name);
  if (name_len < 4 || strcmp(entry.name + name_len - 4, ".apk") != 0 ||
      !parse_dso_elf(entry.start, entry.end, candidate) || candidate->soname[0] == '\0') {
    return false;
  }

  for (int dso_idx = 0; dso_idx < ctx.count; dso_idx++) {
    if (strcmp(candidate->soname, ctx.names[dso_idx]) == 0) {
      *slot = dso_idx;
      return true;
    }
  }
  return false;
}

// Check whether this candidate DSO can explain at least one executable backtrace entry for one of
// the pattern frames that references dso_slot. This is the key filter that disambiguates same-name
// DSOs. A basename or SONAME match is not enough unless the candidate also matches the actual
// crashing backtrace captured from ucontext. bt_in_exec_map is only a coarse "this captured
// backtrace address falls in an executable VMA at all" filter, but it prevents stack/data
// addresses or stale LR values from being treated as code matches for this DSO.
inline bool dso_matches_any_pattern_backtrace_frame(const DsoInfo& dso, int dso_slot,
                                                    const SuppressionPattern& pat,
                                                    const int* _Nonnull frame_dso_map,
                                                    const uintptr_t* _Nonnull backtrace,
                                                    const bool* _Nonnull bt_in_exec_map,
                                                    size_t bt_depth) {
  for (size_t frame_idx = 0; frame_idx < pat.frames.size(); frame_idx++) {
    if (frame_dso_map[frame_idx] != dso_slot) continue;
    for (size_t bt_idx = 0; bt_idx < bt_depth; bt_idx++) {
      if (!bt_in_exec_map[bt_idx]) continue;
      if (func_matches(backtrace[bt_idx], &dso, pat.frames[frame_idx].func_name)) return true;
    }
  }
  return false;
}

// Collapse repeated DSO names in one SuppressionPattern into unique per-pattern slots.
//
// Output:
//   - frame_dso_map[frame_idx] = the unique DSO slot referenced by that pattern frame
//   - ctx->names[0..count) = the distinct DSO names to resolve for this pattern
//
// Main purpose: later code can resolve each unique DSO once, then let every frame that references
// that DSO point back to the same resolved DsoInfo slot.
inline int build_pattern_dso_slots(const SuppressionPattern& pat, int* _Nonnull frame_dso_map,
                                   DsoSearchCtx* _Nonnull ctx) {
  const char* dso_names[kMaxDsos] = {};
  int num_dsos = 0;
  for (size_t frame_idx = 0; frame_idx < pat.frames.size(); frame_idx++) {
    int slot = -1;
    for (int dso_idx = 0; dso_idx < num_dsos; dso_idx++) {
      if (strcmp(dso_names[dso_idx], pat.frames[frame_idx].dso_name) == 0) {
        slot = dso_idx;
        break;
      }
    }
    if (slot < 0 && num_dsos < kMaxDsos) {
      slot = num_dsos;
      dso_names[num_dsos++] = pat.frames[frame_idx].dso_name;
    }
    if (slot < 0) return -1;
    frame_dso_map[frame_idx] = slot;
  }

  *ctx = {};
  for (int dso_idx = 0; dso_idx < num_dsos; dso_idx++) ctx->names[dso_idx] = dso_names[dso_idx];
  ctx->count = num_dsos;
  return num_dsos;
}

// Scan /proc/self/maps once for this pattern, doing two jobs against the same kernel-provided VMA
// snapshot:
//   1. classify which captured backtrace entries lie in executable mappings
//   2. collect only the DSO candidates relevant to this pattern
//
// Parameters:
//   - pat: suppression pattern whose unique DSOs need to be resolved
//   - backtrace / bt_depth: captured PC/LR/FP-chain frames to classify and use for disambiguation
//   - bt_in_exec_map: output array parallel to backtrace; set true for backtrace[i] values that
//     fall inside an executable VMA, left false for stack/heap/data/non-code addresses
//   - frame_dso_map: output array parallel to pat.frames; frame_dso_map[frame_idx] gives the
//     unique per-pattern DSO slot used by that frame. That slot is an index into ctx->names[],
//     ctx->infos[], and ctx->ambiguous[], so later code can resolve one DSO once and let every
//     frame that names it reuse the same resolved DsoInfo.
//   - ctx: output DSO-resolution state for those slots (ctx->names[], ctx->infos[], ctx->count)
//
// Returns the number of unique DSO slots referenced by pat, or -1 if the pattern shape itself
// cannot be represented with the fixed-size scratch state.
//
// libunwindstack reaches a similar consistency point by centralizing map ownership in
// system/unwinding/libunwindstack/MapInfo.cpp.
inline int collect_executable_frames_and_find_pattern_dsos_for_backtrace(
    const SuppressionPattern& pat, const uintptr_t* _Nonnull backtrace, size_t bt_depth,
    bool* _Nonnull bt_in_exec_map, int* _Nonnull frame_dso_map, DsoSearchCtx* _Nonnull ctx) {
  if (bt_depth == 0) return -1;

  // Collapse repeated DSO names in the pattern into per-pattern slots once up front. All later
  // matching and ambiguity tracking works in terms of these slots rather than frame indices.
  const int num_dsos = build_pattern_dso_slots(pat, frame_dso_map, ctx);
  if (num_dsos < 0) return -1;

  for (size_t i = 0; i < bt_depth; i++) bt_in_exec_map[i] = false;

  // This helper intentionally scans the full /proc/self/maps snapshot. Collect same-name candidates
  // first, then disambiguate them against the actual backtrace after the scan. Even after one maps
  // entry successfully parses into a DsoInfo, keep reading later lines: the same single pass still
  // needs to fill bt_in_exec_map and collect other candidates for different slots or same-name
  // ambiguities. This keeps the maps walk single-pass while still rejecting ambiguous matches.
  PatternDsoCandidate candidates[kMaxPatternDsoCandidates] = {};
  int candidate_count = 0;

  int fd = async_safe_open_readonly_cloexec("/proc/self/maps");
  if (fd < 0) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc", "mte_suppress: open maps failed");
    // Keep the already-built slot mapping. Callers can still see how many unique DSOs the pattern
    // needs, but none of them will resolve because infos[] stays invalid.
    return num_dsos;
  }

  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    MapsEntry entry{};
    if (!parse_maps_line(line, &entry)) return true;

    // /proc/self/maps layouts vary, so executability is only used to classify captured backtrace
    // entries, not to decide whether a file-backed entry is relevant for DSO discovery. Actual
    // device tombstones show libexynosdisplay.so maps like:
    //
    // clang-format off
    //   0000dca1'59606000-0000dca1'59688fff r--         0     83000  /vendor/lib64/libexynosdisplay.so
    //   0000dca1'5968a000-0000dca1'597bcfff r-x     84000    133000  /vendor/lib64/libexynosdisplay.so
    //   0000dca1'597be000-0000dca1'597c6fff r--    1b8000      9000  /vendor/lib64/libexynosdisplay.so
    //   0000dca1'597ca000-0000dca1'597cafff rw-    1c4000      1000  /vendor/lib64/libexynosdisplay.so
    // clang-format on
    //
    // system/unwinding/libunwindstack/tests/ElfCacheTest.cpp also synthesizes APK-backed DSOs with
    // only non-zero-offset mappings:
    //   7000-8000 r--s 00001000 00:00 0 app_one.apk
    //   8000-9000 r-xs 00005000 00:00 0 app_one.apk
    //   9000-a000 r--s 00004000 00:00 0 app_two.apk
    //   a000-b000 r-xs 00005000 00:00 0 app_two.apk
    //   b000-c000 r--s 00008000 00:00 0 app_two.apk
    //   c000-d000 r-xs 00009000 00:00 0 app_two.apk
    // Record only "this captured backtrace address lies in executable memory". If this entry is
    // not executable, keep scanning anyway: the mapping we use to parse ELF header data does not
    // need to be executable, and APK entries also do not need to be executable here.
    if (maps_entry_is_executable(entry)) {
      for (size_t bt_idx = 0; bt_idx < bt_depth; bt_idx++) {
        if (bt_in_exec_map[bt_idx]) continue;
        if (backtrace[bt_idx] >= entry.start && backtrace[bt_idx] < entry.end) {
          bt_in_exec_map[bt_idx] = true;
        }
      }
    }

    // Only file-backed path entries can participate in basename or APK matching. Skip anonymous
    // and pseudo-path maps such as [heap], [stack], and blank-name entries.
    if (entry.name[0] != '/') {
      return true;
    }

    int slot = -1;
    DsoInfo candidate{};
    if (!resolve_pattern_dso_candidate(entry, *ctx, &slot, &candidate)) {
      return true;
    }

    if (candidate_count >= kMaxPatternDsoCandidates) {
      // Keep a fixed-size candidate set so the signal-handler path never needs heap allocation.
      // Hitting this cap means the maps layout is more complex than the current suppression model
      // expects, so reject this pattern instead of silently dropping candidates.
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "mte_suppress: too many DSO candidates for pattern '%s'", pat.name);
      candidate_count = -1;
      return false;
    }
    candidates[candidate_count].dso_slot = slot;
    candidates[candidate_count].info = candidate;
    candidate_count++;
    return true;
  });

  async_safe_close(fd);
  if (candidate_count < 0) return -1;

  // Turn the raw candidate set into resolved slots by asking each same-name DSO whether it can
  // explain at least one executable backtrace entry referenced by this pattern.
  for (int candidate_idx = 0; candidate_idx < candidate_count; candidate_idx++) {
    const int dso_idx = candidates[candidate_idx].dso_slot;
    const DsoInfo& candidate = candidates[candidate_idx].info;
    if (ctx->ambiguous[dso_idx]) continue;

    if (!dso_matches_any_pattern_backtrace_frame(candidate, dso_idx, pat, frame_dso_map, backtrace,
                                                 bt_in_exec_map, bt_depth)) {
      continue;
    }

    // First matching candidate claims this slot. If a later candidate with a different base also
    // matches, mark the slot ambiguous so this suppression pattern is rejected instead of picking
    // one DSO arbitrarily.
    if (!ctx->infos[dso_idx].valid) {
      ctx->infos[dso_idx] = candidate;
      ctx->infos[dso_idx].valid = true;
      ctx->found++;
      async_safe_format_log(
          ANDROID_LOG_WARN, "libc", "mte_suppress: selected DSO '%s' [%p-%p) exec=[%p-%p) base=%p",
          ctx->names[dso_idx], reinterpret_cast<void*>(candidate.load_start),
          reinterpret_cast<void*>(candidate.load_end),
          reinterpret_cast<void*>(candidate.exec_start),
          reinterpret_cast<void*>(candidate.exec_end), reinterpret_cast<void*>(candidate.base));
    } else if (ctx->infos[dso_idx].base != candidate.base) {
      // Two different mapped DSOs with the same requested name both matched the crashing
      // backtrace. Clear the slot and reject this pattern rather than picking one arbitrarily.
      uintptr_t prior_base = ctx->infos[dso_idx].base;
      ctx->infos[dso_idx] = {};
      ctx->ambiguous[dso_idx] = true;
      ctx->found--;
      async_safe_format_log(ANDROID_LOG_WARN, "libc",
                            "mte_suppress: ambiguous DSO '%s' with bases %p and %p",
                            ctx->names[dso_idx], reinterpret_cast<void*>(prior_base),
                            reinterpret_cast<void*>(candidate.base));
    }
  }

  return num_dsos;
}
}  // namespace mte_suppression
