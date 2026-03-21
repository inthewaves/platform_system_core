# MTE crash suppression

Vendor binaries and shared libraries may contain memory safety bugs that we cannot fix because we do
not have the source code. Sometimes these bugs are fatal and cause issues such as reboots. This
directory contains code that lets `debuggerd_handler` suppress a small number of known synchronous
MTE crashes instead of always killing the process.

The basic idea is simple: when a synchronous MTE fault (`SEGV_MTESERR`) happens, debuggerd checks
whether the crashing process and its top stack frames match one of a few statically configured
suppression patterns. Each pattern names an exact process, an exact sequence of shared libraries,
and exact mangled function names for the top frames of the crash. If everything matches, debuggerd
treats the crash as a known bug, temporarily disables MTE for that thread, and lets execution
continue. If anything does not match, the crash proceeds normally.

Asynchronous MTE faults (`SEGV_MTEAERR`) are intentionally not supported. Their reported PC is not
reliably the faulting instruction, so the backtrace is not accurate enough for exact stack-pattern
matching.

This is intentionally much smaller and stricter than the normal tombstone unwinding path. The usual
`crash_dump` / `libunwindstack` flow runs out of process after debuggerd forks, which is
appropriate for producing a full tombstone but too late and too expensive for a suppression
decision on the faulting thread. Suppression has to happen immediately inside the signal handler,
before handing off to the normal crash path, and it must stay within
[async-signal-safe](https://man7.org/linux/man-pages/man7/signal-safety.7.html) operations. That
is why this code uses a simple frame-pointer-based backtrace, reads `/proc/self/maps` directly, and
reconstructs just enough ELF metadata from mapped shared libraries to answer "does this PC belong
to this exact function in this exact `.so`?"

Because this code runs while handling an MTE fault, it is already executing after the kernel has
delivered a `SIGSEGV` for a memory-safety violation. In other words, this is still a kind of
segmentation fault: MTE is just providing a more precise reason for the fault, such as a tag
mismatch on a bad memory access. By the time the handler runs, the crashing thread may already have
corrupted stack state or corrupted mapped ELF metadata. For that reason, the code treats most
in-process state as untrusted. Stack frame records, ELF headers, dynamic sections, hash tables, and
symbol tables may all be corrupted. It therefore does not dereference crash-state pointers
directly. Instead, it uses bounded `process_vm_readv` reads, exact DSO and symbol matching, and
explicit range checks derived from `/proc/self/maps` and ELF program headers. This is the same
general defensive approach used by `libunwindstack` when unwinding crash state, and it is
consistent with other crash-dump systems such as Breakpad.[^breakpad]

At a high level, the suppression check works like this:

1. Identify the crashing process from `/proc/self/exe` (or app package from `/proc/self/cmdline`).
2. Capture a small backtrace from the signal `ucontext`.
3. Find the shared libraries referenced by the suppression pattern in `/proc/self/maps`.
4. Read their mapped ELF metadata to recover symbol lookup tables.
5. Verify that each captured frame falls inside the exact named function from the exact named
   library in the pattern.

## Concepts

- [ELF](https://man7.org/linux/man-pages/man5/elf.5.html) stands for "Executable and Linkable
  Format". It is the standard file format used for executables and shared libraries on Android and
  Linux.
- A shared library is a `.so` file. In ELF terminology, a shared library is a shared object; in
  this README, "DSO" means "dynamic shared object". The dynamic loader interfaces for shared
  objects are described in [dlopen(3)](https://man7.org/linux/man-pages/man3/dlopen.3.html).
- `.dynsym` is the dynamic symbol table: the subset of symbols that the runtime linker keeps for
  dynamic linking and symbol lookup. The ELF file format is described in
  [elf(5)](https://man7.org/linux/man-pages/man5/elf.5.html), and the Arm64 ELF ABI symbol-table
  details are in
  [AAELF64, "Symbol Table"](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#symbol-table).
- `PT_LOAD` and `PT_DYNAMIC` are ELF program-header types. Roughly: `PT_LOAD` entries describe the
  loadable memory ranges of the ELF image, and `PT_DYNAMIC` points at the dynamic-linking metadata
  used to find symbol tables, string tables, and hash tables. See
  [elf(5)](https://man7.org/linux/man-pages/man5/elf.5.html),
  [AAELF64, "Program Header"](https://github.com/ARM-software/abi-aa/blob/main/aaelf64/aaelf64.rst#program-header),
  and
  [SYSVABI64, "Dynamic Section"](https://github.com/ARM-software/abi-aa/blob/main/sysvabi64/sysvabi64.rst#dynamic-section).
- On AArch64, `x30` is the link register (LR). Call instructions such as `bl` write the return
  address there, unless the function saves it to the stack first. The Arm64 procedure call standard
  documents this in
  [AAPCS64, "General-purpose Registers"](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#general-purpose-registers).
- A frame-pointer chain is a simple linked list of stack frames. On AArch64 Android builds,
  non-leaf functions normally keep a frame pointer in `x29` and save the previous frame record on
  the stack, which is why this code can do a simple frame-pointer walk instead of full DWARF
  unwinding in the signal handler. See
  [AAPCS64, "The Stack"](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#the-stack)
  and
  [AAPCS64, "The Frame Pointer"](https://github.com/ARM-software/abi-aa/blob/main/aapcs64/aapcs64.rst#the-frame-pointer).

## Scope and behavior

Suppressions are scoped to specific processes, matched either by binary path (`/proc/self/exe` for
native daemons) or by package name (`/proc/self/cmdline` for apps running under `app_process64`).
Only crashes in a listed process are considered. Within a matching binary, each pattern specifies a
sequence of shared library + mangled function name pairs. Matching is done by symbol name, not by
instruction offset: a frame matches if the backtrace address falls anywhere within that function's
`[st_value, st_value + st_size)` range. This means patterns are stable across recompilations of
vendor binaries and shared libraries as long as the function names and parameter / return types
don't change, but is [more permissive than exact PCs](#matching-is-more-permissive-than-exact-pcs).

When a backtrace matches a known suppression pattern, we use the same mechanism as permissive MTE to
suppress the pattern. MTE is disabled temporarily for the faulting thread using a
`CLOCK_THREAD_CPUTIME_ID` timer, configured per pattern via `reenable_timer_ms`. The shared type
default is 10ms, while the current HWC patterns use 50ms. See [Re-enable timer](#re-enable-timer)
below for the tradeoffs.

Tombstone generation is also rate-limited for suppressed crashes. The first crash always generates a
tombstone, but repeated suppressed crashes within a short window can skip tombstone generation
entirely. See [Tombstone rate limiting](#tombstone-rate-limiting) below for details.

## Adding a new suppression pattern

In practice, patterns should use frames from shared libraries (`.so`), not from the main
executable. The current lookup path relies on `.dynsym`, and most executable-internal functions are
not present there. See [Limitations](#limitations) for details.

1. Get the exact mangled symbol names from the crashing tombstone backtrace. For example, given:

   ```
   signal 11 (SIGSEGV), code 9 (SEGV_MTESERR), fault addr 0x0700c2433e158c00
     #00 pc 0x5688  /vendor/lib64/libvendorgraphicbuffer.so (VendorGraphicBufferMeta::init+8)
     #01 pc 0xd2a18 /vendor/lib64/libexynosdisplay.so (ExynosLayer::printLayer+88)
     #02 pc 0xaaa2c /vendor/lib64/libexynosdisplay.so (ExynosDisplay::printDebugInfos+780)
   ```

   Look up the full mangled names from the shared libraries (example from
   `stallion-BD6A.251031.001.A4`):

   ```bash
   $ readelf -sW libvendorgraphicbuffer.so | grep 'VendorGraphicBufferMeta.*init'
   25: 0000000000005680   276 FUNC  GLOBAL DEFAULT  16 _ZN6vendor8graphics23VendorGraphicBufferMeta4initEPK13native_handle

   $ readelf -sW libexynosdisplay.so | grep 'ExynosLayer.*printLayer'
   2282: 00000000000d29c0  1144 FUNC  GLOBAL DEFAULT  16 _ZN11ExynosLayer10printLayerEv

   $ readelf -sW libexynosdisplay.so | grep 'ExynosDisplay.*printDebugInfos'
   1945: 00000000000aa720  1220 FUNC  GLOBAL DEFAULT  16 _ZN13ExynosDisplay15printDebugInfosERN7android7String8E
   ```

   As a side note, if you don't have the .so, you can use `c++filt` to verify syntax of a mangled
   name. It should return back the function name in C++ syntax:

   ```bash
   $ echo '_ZN13ExynosDisplay15printDebugInfosERN7android7String8E' | c++filt
   ExynosDisplay::printDebugInfos(android::String8&)
   ```

2. In `suppression_pattern.h`, find the existing namespace for the binary and add a pattern
   definition plus a `SuppressionPattern` view in its `kPatterns[]` array. The shared types and
   helper builders live in `suppression_pattern_types.h`; use `FP("libfoo.so", "mangled_name")`
   to keep frame entries short. Each frame maps to a tombstone backtrace line: frame 0 is the PC
   (faulting instruction), frame 1+ are callers.

   The `reenable_timer_ms` field at the end controls how long MTE stays disabled after suppression.
   The shared default is 10ms, which is enough for one-shot crashes. Set it higher if the bug is
   hit repeatedly in a loop (see [Re-enable timer](#re-enable-timer)):

   ```cpp
   inline constexpr auto kOneShot = MakeSuppressionPatternDef(
       "some_one_shot_crash", 10,
       FP("libfoo.so", "_ZN3Foo7triggerEv"),
       FP("libfoo.so", "_ZN3Foo6callerEv"));

   inline constexpr auto kHwc = MakeSuppressionPatternDef(
       "hwc_stale_ignore_layer_buffer", 50,
       // #00 VendorGraphicBufferMeta::init (PC)
       FP("libvendorgraphicbuffer.so",
          "_ZN6vendor8graphics23VendorGraphicBufferMeta4initEPK13native_handle"),
       // #01 ExynosLayer::printLayer (caller)
       FP("libexynosdisplay.so", "_ZN11ExynosLayer10printLayerEv"),
       // #02 ExynosDisplay::printDebugInfos (caller's caller)
       FP("libexynosdisplay.so",
          "_ZN13ExynosDisplay15printDebugInfosERN7android7String8E"));

   inline constexpr SuppressionPattern kPatterns[] = {
       kOneShot.view(),
       kHwc.view(),  // 50ms: loop iterates stale pointers, each one faults
   };
   ```

   When you add a backtrace pattern, it will match _any_ backtrace with that starting pattern.

3. If the process doesn't have a namespace yet, create one and add a `BinarySuppression` entry
   to `kMteSuppressions`. Each entry has a `BinaryMatchType` that determines how the process is
   identified:

   **For native daemons** (matched by `/proc/self/exe`):

   ```cpp
   namespace hwc3_pixel {
   inline constexpr const char* kBinary =
       "/vendor/bin/hw/android.hardware.composer.hwc3-service.pixel";
   inline constexpr auto kSomePattern = MakeSuppressionPatternDef(
       "some_pattern", 10,
       // add FramePattern entries here
       FP("libfoo.so", "_ZN3Foo7triggerEv"));
   inline constexpr SuppressionPattern kPatterns[] = {
       kSomePattern.view(),
   };
   }  // namespace hwc3_pixel

   // In kMteSuppressions:
   BinarySuppression{BinaryMatchType::kExePath, hwc3_pixel::kBinary, hwc3_pixel::kPatterns},
   ```

   **For apps** (matched by package name from `/proc/self/cmdline`). All apps run under
   `app_process64`, so the binary path is the same for every app. Instead, we match the package
   name, which is set as the command line after Zygote specialization:

   ```cpp
   namespace vendor_camera_app {
   inline constexpr const char* kPackage = "com.vendor.camera";
   inline constexpr auto kSomePattern = MakeSuppressionPatternDef(
       "some_pattern", 10,
       // add FramePattern entries here
       FP("libfoo.so", "_ZN3Foo7triggerEv"));
   inline constexpr SuppressionPattern kPatterns[] = {
       kSomePattern.view(),
   };
   }  // namespace vendor_camera_app

   // In kMteSuppressions:
   BinarySuppression{BinaryMatchType::kCmdline, vendor_camera_app::kPackage,
                     vendor_camera_app::kPatterns},
   ```

   Note that support for matching backtraces in apps currently doesn't have signature checking. For
   bundled / preinstalled apps, this should be fine. For user-installed apps, we might as well tell
   them to just disable MTE for the app. (MTE cannot be disabled for preinstalled apps.)

Since `BinarySuppression` uses `std::span`, multiple processes can share the same pattern array:

```cpp
BinarySuppression{BinaryMatchType::kExePath, binary_a::kBinary, shared::kPatterns},
BinarySuppression{BinaryMatchType::kExePath, binary_b::kBinary, shared::kPatterns},
```

A process can also reuse individual patterns from another namespace in its own `kPatterns[]`
(resolved at compile time since everything is `constexpr`):

```cpp
namespace shared {
inline constexpr auto kPatternA = MakeSuppressionPatternDef(
   "shared_pattern_a", 10,
   // frames for shared_pattern_a
   FP("libfoo.so", "_ZN3Foo1aEv"));
inline constexpr auto kPatternB = MakeSuppressionPatternDef(
   "shared_pattern_b", 10,
   // frames for shared_pattern_b
   FP("libfoo.so", "_ZN3Foo1bEv"));
inline constexpr SuppressionPattern kPatterns[] = {
   kPatternA.view(),
   kPatternB.view(),
};
}  // namespace shared

namespace binary_c {
inline constexpr const char* kBinary = "/vendor/bin/hw/some-service";
inline constexpr auto kSpecificPattern = MakeSuppressionPatternDef(
   "binary_c_specific", 10,
   // frames for binary_c_specific
   FP("libbar.so", "_ZN3Bar8specificEv"));
inline constexpr SuppressionPattern kPatterns[] = {
   shared::kPatternA.view(),  // reuse shared_pattern_a from shared
   kSpecificPattern.view(),
};
}  // namespace binary_c
```

### Requirements for symbol names

- See [Limitations](#limitations)
- Must be exact mangled names (full Itanium ABI mangling including parameter types), not prefixes. 
  This enables O(1) hash-based lookup via DT_GNU_HASH / DT_HASH.
- The function must have nonzero `st_size` in `.dynsym` (all normal C++ methods do; hand-written 
  assembly without `.size` directives won't work).
- `STT_GNU_IFUNC` symbols are not currently supported (bionic/libc/private/bionic_ifuncs.h), e.g. 
  using `memcpy`. For an IFUNC, its `st_value` in `.dynsym` points to the resolver function 
  (bionic/libc/arch-arm64/ifuncs.cpp), not the actual implementation. The resolver returns the real 
  function address at runtime.

## Running tests

### Unit tests (atest)

```bash
# maps_util.h tests, runs on host (no device needed). Covers parse_maps_line(),
# large 64-bit address/offset values, and for_each_line_from_fd() buffer-boundary reconstruction.
atest mte_suppression_maps_test

# ELF hash / symbol helper tests, device only (aarch64)
atest mte_suppression_elf_lookup_test

# safe_read()/safe_read_cstring() tests, device only (aarch64). Covers page-split
# process_vm_readv() reads across unmapped and PROT_NONE holes plus 256/257-byte string boundaries.
atest mte_suppression_safe_read_test

# DSO parsing + symbol lookup tests, device only (aarch64). Covers synthetic non-zero load bias and
# non-zero file-offset ELF mappings in addition to real-DSO symbol resolution.
atest mte_suppression_dso_lookup_test

# /proc/self/maps DSO search + dedup tests, device only (aarch64)
atest mte_suppression_maps_dso_search_test

# backtrace matching logic tests, device only (aarch64)
atest mte_suppression_backtrace_match_test

# backtrace capture (FP chain walking) tests, device only (aarch64)
atest mte_suppression_capture_backtrace_test

# Run all seven via TEST_MAPPING group. You should be on an aarch64 device.
atest --test-mapping system/core/debuggerd/handler/mte_suppression:grapheneos
```

Some of these targeted tests intentionally mirror libunwindstack coverage so that the local
signal-handler-safe helpers stay aligned with the upstream `process_vm_readv()`, string-read, maps
parsing, and ELF-load-bias behaviors.

### End-to-end device tests

The integration tests in `debuggerd/test_mte_suppression/` exercise the full suppression flow
(trigger real MTE crashes, verify process survives or crashes depending on the test):

```bash
atest mte_suppression_test
```

This requires a device with MTE enabled (Pixel 8+).

The tests are split into `MteSuppressionNativeTest` and `MteSuppressionAppTest`. Each test triggers 
a real MTE fault and checks whether the process survives or crashes. The crash modes tested are:

- **suppressed**: call stack matches a suppression pattern, process should survive
- **unsuppressed**: call stack does not match any pattern, process should crash
- **cross-dso**: pattern spans multiple shared libraries (so_a -> so_b -> so_a), survives
- **same-dso**: `outer -> middle -> inner` all come from
  `libmte_suppression_test_a.so`, but the suppression pattern requires
  `middle()` from `libmte_suppression_test_b.so`. The `middle()` symbol name is
  the same in both DSOs, so this verifies that matching is by exact DSO+symbol,
  not symbol name alone. Process should crash
- **nognuhash**: DSO has only DT_HASH (no DT_GNU_HASH), falls back to ELF hash, survives
- **leaf**: faulting function is a leaf (no frame setup), raw LR holds real caller, survives.
  See [Backtrace capture and stale LR detection](#backtrace-capture-and-stale-lr-detection),
  Case 1
- **gap**: non-leaf function where LR and PC differ, but both still fall within the same
  function, survives. See [Backtrace capture and stale LR detection](#backtrace-capture-and-stale-lr-detection),
  Case 3
- **direct**: fault with no usable shared-library stack pattern, crashes

Native tests run these modes against a matched binary (exe path in suppression table) and
an unmatched binary (same code, different name not in table: all modes crash). App tests
run the same modes against a matched package with both embedded native libs (DSOs resolved
via DT_SONAME from APK mappings) and extracted native libs (DSOs resolved via basename),
plus an unmatched package (all modes crash).

## Limitations

### Some classes of memory bugs don't always manifest as `SEGV_MTESERR`

Some classes of memory bugs are not reliably suppressible because they may usually manifest as
`SEGV_MTESERR`, but can also manifest as a different signal code such as `SEGV_ACCERR`. Linear
overflows for small (slab) allocations are one example.

#### Linear overflows for small (slab) allocations depend on the slot boundary

MTE suppression only runs when the fault stays in tagged, accessible memory and reaches the kernel
as `SEGV_MTESERR`. On GrapheneOS, this boundary is also shaped by `external/hardened_malloc`,
which uses inaccessible guard slabs and other protected regions around allocations. If the same
underlying bug crosses into that allocator-managed inaccessible memory instead, it can show up as
`SEGV_ACCERR` and will not be suppressed.

This is the same slab-edge issue that hardened_malloc's own Android memtag tests had to avoid. It
is also addressed by commit
[88b3c1a](https://github.com/GrapheneOS/hardened_malloc/commit/88b3c1acf9cfc8dd6957671d5c3ab4bcbf53c429)
(`memtag_test: fix sporadic failures of overflow/underflow tests`).

The current synthetic crashes use a same-slot use-after-free read to avoid this boundary. The old
version of the tests used a linear heap overflow read:

```cpp
volatile char* p = static_cast<char*>(malloc(1));
volatile char c = p[16];
(void)c;
```

That old test shape was flaky on GrapheneOS, because the intended `SEGV_MTESERR` could sometimes
turn into `SEGV_ACCERR` instead. This showed up most often in this benchmark because it runs 10
iterations:

```bash
atest mte_suppression_test:com.android.tests.debuggerd.MteSuppressionNativeTest#testSuppressionBenchmark
```

The hardened_malloc interaction is easier to see as a slab-layout problem:

1. `malloc(1)` first reserves 8 extra bytes for slab-canary space, then rounds into the 16-byte
   size class. The actual sizing flow in `external/hardened_malloc/h_malloc.c` is:

   ```cpp
   h_malloc(1)
     -> adjust_size_for_canary(1) = 1 + 8 = 9
     -> get_size_info(9)
     -> align(9, 16) = 16
     -> class = ((9 - 1) >> 4) + 1 = 1
   ```

   `size_class_slots[] = 256` for class 1, and `get_slab_size()` packs those 256 slots into one
   4096-byte slab page. With MTE enabled, `set_canary()` does not write the canary bytes, but the
   space is still reserved for sizing, so the slot layout stays the same.
2. The old test read `p[16]`, which is 16 bytes past the pointer returned by `malloc(1)` and
   therefore lands in the next 16-byte slot. This matters for MTE because Arm defines a 16-byte
   "tag granule": each 16-byte region of taggable memory has a 4-bit allocation tag, and loads or
   stores compare that against the pointer's logical tag. See the
   [Memtag ABI extension for AArch64](https://github.com/ARM-software/abi-aa/blob/main/memtagabielf64/memtagabielf64.rst#introduction).
   So `p[16]` is the first access that can leave the original tagged 16-byte chunk and hit a
   different one.
3. `external/hardened_malloc/config/default.mk` sets `CONFIG_GUARD_SLABS_INTERVAL := 1`, so each
   slab page is followed by a guard slab that never gets `PROT_READ|PROT_WRITE`:

   `[slab page: slots 0-255] [guard slab: inaccessible] [slab page] [guard slab] ...`
4. If the allocation lands in slot 255, that slot occupies offsets 4080-4095 within the slab page.
   Then, `p[16]` touches offset 4096 which is the first byte of the following guard slab.

That gives two outcomes for `malloc(1)`, depending on which slot the allocation lands in:

- Slots 0-254: `p[16]` lands in the next neighbor slot within the same slab, which produces an MTE
  tag mismatch, so the test usually gets `SEGV_MTESERR`.
- Slot 255: `p[16]` lands in the inaccessible guard slab, so the page fault happens before MTE tag
  checking and the test gets `SEGV_ACCERR` instead. With MTE enabled, the skipped slab stays at
  the initial `PROT_MTE` mapping rather than becoming `PROT_READ|PROT_WRITE`. This does not get
  suppressed, because MTE suppression only handles `SEGV_MTESERR`.

If the 16-byte slab is completely fresh and all 256 slots are free, the chance that `malloc(1)`
lands in slot 255 is exactly 1/256. If the slab state is unknown, `get_free_slot()` picks a random 
start index and then returns the first free slot found. So the probability of getting slot 255 
depends on the occupancy pattern:

- If slot 255 is already occupied, the probability is 0.
- If slot 255 is free, the probability is at least 1/256, because choosing start index 255 makes
  the scan check slot 255 first and return it immediately. It can be much larger if many preceding
  slots are occupied, since any of those slots would scan forward into 255.

The benchmark runs 10 fresh crashing processes, so the chance of seeing at least one `SEGV_ACCERR`
is about $1 - (255/256)^{10} \approx 3.8\%$ under the fresh-slab model. Of course, fresh process 
doesn't guarantee fresh slabs.

To generalize: For `p = malloc(N)`, let $S$ be the rounded slab slot size that `hardened_malloc`
actually allocates after canary adjustment and size-class rounding in
[`external/hardened_malloc/h_malloc.c`](https://github.com/GrapheneOS/hardened_malloc/blob/main/h_malloc.c).
At the language level, every `p[k]` with $k \ge N$ is already out-of-bounds, but for a linear
overflow, the fault type depends on when the access leaves the slot and what lies after it.

- $0 \le k < S$: Still inside the same slab slot, so for a live linear overflow, this has not yet
  reached a different allocation tag or inaccessible region. For example, a 32-byte ($S = 32$) slot
  covers two 16-byte MTE granules, $[0,16)$ and $[16,32)$, and both still belong to the same live
  allocation. In hardened_malloc, the same allocation tag is applied across the whole live slot, so
  both granules still use the same tag.
- $k = S$: First byte outside the slot; this is the analogue of the old `malloc(1)` then `p[16]`
  case. If the allocation is not in the last slot of the slab, this reaches the next slot and can
  produce `SEGV_MTESERR`. If the allocation is in the last slot, or if the class has only one slot
  per slab, this reaches the following guard slab instead and can produce `SEGV_ACCERR`.
- $k > S$: The access is already past the end of the slot, so the exact outcome depends on what
  lies further ahead, such as more bytes in the next slot, the guard slab after the last slot, or
  unmapped memory beyond that.

More examples:

- If $N = 16376$, then $S = 16384$, the largest class with more than one slot. That class has 4
  slots per slab, so `p[S]` reaches the next slot for the first 3 positions and the guard slab for
  the last one, making the fresh-slab `SEGV_ACCERR` probability roughly $1/4$.
- If $N = 131064$, then $S = 131072$, the largest small/slab class. That class has only one slot
  per slab, so `p[S]` is the first byte past the slot and immediately hits the following guard
  slab, giving `SEGV_ACCERR`. There are no neighbors.

We can generalize even further. Let $r$ be the number of right-neighbor slots between the allocation
and the end of the slab, let $P$ be any same-slab padding bytes between the end of the last slot
and the start of the guard slab, and let $G$ be the guard slab size for that class. Then:

This diagram shows what `p[k]` accesses as `k` increases:

```text
[ p = malloc(N) | right neighbor 1 | ... | right neighbor r | slab padding P ] [ guard slab ]
                ^                                            ^                 ^
                k = S                                        k = (r + 1)S      k = (r + 1)S + P
                 <---------- r right-neighbor slots ---------><------ P ------->
```

- the interval $S \le k < (r + 1)S$ lands in one of the $r$ right-neighbor slots and can produce
  `SEGV_MTESERR`
- the interval $(r + 1)S \le k < (r + 1)S + P$ lands in same-slab padding after the last slot, if
  any
- the interval $(r + 1)S + P \le k < (r + 1)S + P + G$ lands in the guard slab and gives
  `SEGV_ACCERR`

For hardened_malloc, the guard slab is the same size as the slab for that size class. For many of
the relevant size classes here, $P = 0$, so the first byte after the last slot is already the first
byte of the guard slab. One example where $P \ne 0$ is the 48-byte size class: it has 85 slots, so
$85 \cdot 48 = 4080$ but the slab size is 4096, which leaves $P = 16$ bytes of same-slab padding
after the last slot before the guard slab begins.

The same reasoning applies symmetrically to linear underflows on the left side of the allocation:
left-neighbor slots can produce `SEGV_MTESERR`, while stepping past the first slot of the slab into
the preceding guard slab can produce `SEGV_ACCERR`.

The same reasoning extends to the top end of the slab allocator too.

### Only `.dynsym` symbols can be used in patterns

Patterns can only use symbols that appear in `.dynsym` (the dynamic symbol table). `.dynsym` only
contains symbols needed for runtime dynamic linking: exports that other `.so` files link against,
and imports the executable needs from `.so` files. Internal methods of an executable (like
`HalImpl::presentDisplay` in the HWC3 binary[^hwc3-hal]) are never placed in `.dynsym` because
nothing `dlsym()`s them or links against them at runtime.

Those symbols still exist in `.gnu_debugdata` (MiniDebugInfo), which is how tombstones resolve
them. Decompressing `.gnu_debugdata` would require linking `liblzma` into
`libdebuggerd_handler_core`, which we want to avoid.

- system/unwinding/libunwindstack has LZMA support but runs it out-of-process in the `crash_dump` 
  daemon, not in the signal handler.
- [libunwind](https://github.com/libunwind/libunwind) has `.gnu_debugdata` support using a
  custom mmap-based allocator to avoid malloc.

Shared libraries are different: their exported functions must stay in `.dynsym` because other code
calls them across the dynamic linking boundary. In practice, this means frames in shared libraries
are usable for patterns but frames in the main executable are not. For example, given this
tombstone backtrace:

```
  #00 pc 0x5688   /vendor/lib64/libvendorgraphicbuffer.so (VendorGraphicBufferMeta::init(native_handle const*)+8)
  #01 pc 0xd2a18  /vendor/lib64/libexynosdisplay.so (ExynosLayer::printLayer()+88)
  #02 pc 0xaaa2c  /vendor/lib64/libexynosdisplay.so (ExynosDisplay::printDebugInfos(android::String8&)+780)
  #03 pc 0xabd20  /vendor/lib64/libexynosdisplay.so (ExynosDisplay::deliverWinConfigData()+128)
  #04 pc 0x17ca4c /vendor/lib64/libexynosdisplay.so (gs101::ExynosExternalDisplayModule::deliverWinConfigData()+124)
  #05 pc 0xb2180  /vendor/lib64/libexynosdisplay.so (ExynosDisplay::presentDisplay(int*)+4288)
  #06 pc 0x10accc /vendor/lib64/libexynosdisplay.so (ExynosExternalDisplay::presentDisplay(int*)+588)
  #07 pc 0x22a94  /vendor/bin/hw/android.hardware.composer.hwc3-service.pixel (HalImpl::presentDisplay(...)+308)
  #08 pc 0x19140  /vendor/bin/hw/android.hardware.composer.hwc3-service.pixel (ComposerCommandEngine::executePresentDisplay(...)+96)
  #09 pc 0x18ba8  /vendor/bin/hw/android.hardware.composer.hwc3-service.pixel (ComposerCommandEngine::dispatchDisplayCommand(...)+8104)
  #10 pc 0x16978  /vendor/bin/hw/android.hardware.composer.hwc3-service.pixel (ComposerCommandEngine::execute(...)+248)
  #11 pc 0x120fc  /vendor/bin/hw/android.hardware.composer.hwc3-service.pixel (ComposerClient::executeCommands(...)+156)
  #12 pc 0x26c30  /vendor/lib64/android.hardware.graphics.composer3-V4-ndk.so (IComposerClient_onTransact+1552)
```

Frames #00-#06 are in shared libraries and have `.dynsym` entries. Frames #07-#11 are in the main
executable where those symbols only exist in `.gnu_debugdata`, so they can't be used in patterns.
Frame #12 is in a shared library again (AIDL-generated), but is framework code that may change
across Android versions.

### Matching is more permissive than exact PCs

Matching by symbol name rather than instruction offset is a tradeoff: patterns survive vendor
binary recompilations without updates, but are more permissive than exact PCs. A pattern will
suppress any crash whose backtrace passes through the same sequence of functions, even if the
faulting instruction differs from the original crash that the suppression pattern comes from. To
mitigate this, use as many frames as the tombstone provides. `kMaxFrames` is derived from the
current suppression table, so adding a deeper pattern automatically increases the runtime scratch
buffers to match. Keep in mind that only
[shared library frames](#only-dynsym-symbols-can-be-used-in-patterns) are usable.

## Implementation notes

The helper code in this directory is intentionally header-heavy. This keeps the small helpers easy 
to unit-test directly and also helps us avoid additional Soong module changes for upstream 
`debuggerd` modules such as `libdebuggerd_handler_core` (although it's likely as easy as adding a 
srcs Soong module)

We generally only use functions from POSIX.1 that are required to be async-signal-safe along with 
raw system calls such as `process_vm_readv` (see bionic/libc/SYSCALLS.TXT).

Note that we do not use linker functions from `libdl` such as `dladdr`, because

1. `debuggerd_handler.cpp` compiles into `libdebuggerd_handler_core`, a static library linked into
   both:
    - `libdebuggerd_handler` (normal processes which have `libdl`)
    - `libdebuggerd_handler_fallback` (the linker itself which doesn't link `libdl`)
2. Those methods are not required to be async-signal-safe. `libdl` functions use a mutex which imply 
   that they're not reentrant (even if the mutex itself is `PTHREAD_MUTEX_RECURSIVE`)

### Re-enable timer

Each `SuppressionPattern` has a `reenable_timer_ms` field that controls how long MTE stays disabled
on the faulting thread after suppression. This is a `CLOCK_THREAD_CPUTIME_ID` timer, so the thread
must actually execute on the CPU for the specified duration before MTE is re-enabled.

The default is 10ms, which is sufficient for one-shot crashes where a single instruction faults and
the process moves on. Set it higher when the underlying memory bug causes repeated faults in quick
succession. The HWC patterns (`hwc_stale_ignore_layer_buffer` and `hwc_stale_ignore_layer_dump`) use
50ms because `ExynosDisplay::printDebugInfos` iterates `mIgnoreLayers` (a vector of stale layer
pointers) and calls both `printLayer()` and `dump()` on each element in the same loop iteration.
Each call dereferences the stale `native_handle` pointer via `VendorGraphicBufferMeta::init`,
causing an MTE fault. With a 1ms timer, MTE would re-enable between calls within the same iteration,
triggering the full signal handler on each fault. A 50ms timer keeps MTE disabled long enough to
cover most iterations, reducing the number of signal handler invocations from one-per-fault to
typically one or two per `printDebugInfos` call. It does not guarantee full coverage: if the thread
accumulates 50ms of CPU time before the loop finishes (e.g., the vector has many elements), MTE
re-enables mid-loop and the dump path can still trigger a second suppression.

The timer value is a tradeoff: higher values reduce signal handler overhead but leave MTE disabled
longer, during which other (real) memory safety bugs on that thread would go undetected.

### Tombstone rate limiting

Tombstone generation for suppressed crashes is rate-limited to avoid freezing the process. When a
bug triggers hundreds of crashes in quick succession (e.g. the stale pointer loop above), generating
a tombstone for each one would hold `crash_mutex` for seconds per tombstone (ptrace attach, stack
dump, disk I/O), effectively freezing the process.

The first suppressed crash always generates a tombstone (for diagnostics). Subsequent suppressed
crashes within `mte_suppression_tombstone_ratelimit_ms` (in `debuggerd_handler.cpp`, currently
1000ms) skip tombstone generation entirely -- MTE is disabled and the timer is set, but no
crash_dump is spawned. The rate limit uses `CLOCK_MONOTONIC` (wall clock) and is tracked per-process
via a static variable. Permissive MTE is not rate-limited.

### Backtrace capture and stale LR detection

`capture_backtrace` (backtrace.h) captures return addresses from a signal ucontext: bt[0] = faulting
PC, bt[1] = raw LR (x30), bt[2+] = FP chain. On AArch64, x30 is the link register. The CPU writes
the return address there on `bl` / `blr` calls unless the function saves it to the stack first.
`match_backtrace` then checks whether bt[1] is stale (clobbered by a `bl` instruction in a
non-leaf function) by testing if both bt[0] and bt[1] fall within the same function's symbol
range. If so, bt[1] is skipped and matching continues at bt[2].

The instruction listings below come from the current built test DSO:

```bash
llvm-objdump -d -C --no-show-raw-insn out/host/linux-x86/testcases/mte_suppression_test/libmte_suppression_test_crash.so
```

There are three cases, illustrated with the test functions in
`libmte_suppression_test_crash.so`:

**Case 1: Leaf function (LR is valid)**

```cpp
void leaf_trigger(char* p) {
  volatile char c = static_cast<volatile char*>(p)[0];  // MTE fault on a stale freed pointer
}
```

```
leaf_trigger:
  54100: bti   c
  54104: sub   sp, sp, #0x10
  54108: ldrb  w8, [x0]               // MTE fault: PC is inside leaf_trigger
  5410c: strb  w8, [sp, #0xc]
  54110: ldrb  w8, [sp, #0xc]
  54114: add   sp, sp, #0x10
  54118: ret
```

The function has no `stp`, `bl`, or frame record. LR holds the real caller
(`leaf_suppressed_path`), so bt[1] is not in the same function as bt[0] and is kept.

**Case 2: Non-leaf function, LR == PC**

```cpp
static __attribute__((noinline)) char* free_and_return(char* p) {
  free(p);
  return p;
}

void trigger() {
  volatile char c =
      static_cast<volatile char*>(free_and_return(static_cast<char*>(malloc(1))))[0];  // MTE fault
}
```

```
trigger:
  54030: paciasp
  54034: sub   sp, sp, #0x20
  54038: stp   x29, x30, [sp, #0x10]
  5403c: add   x29, sp, #0x10
  54040: mov   w0, #0x1
  54044: bl    <malloc>
  54048: bl    <free_and_return local helper>  // LR = 0x5404c
  5404c: ldrb  w8, [x0]                        // MTE fault: PC = 0x5404c == LR
  54050: sturb w8, [x29, #-0x4]
  54054: ldurb w8, [x29, #-0x4]
  54058: ldp   x29, x30, [sp, #0x10]
  5405c: add   sp, sp, #0x20
  54060: retaa

free_and_return local helper:
  54070: paciasp
  54074: stp   x29, x30, [sp, #-0x20]!
  54078: str   x19, [sp, #0x10]
  5407c: mov   x29, sp
  54080: mov   x19, x0
  54084: bl    <free>
  54088: mov   x0, x19
  5408c: ldr   x19, [sp, #0x10]
  54090: ldp   x29, x30, [sp], #0x20
  54094: retaa
```

`trigger()` calls the local static helper that frees and returns the pointer. The faulting `ldrb`
is the very next instruction after that `bl`, so PC == LR. Both are inside `trigger`, so bt[1] is
stale and skipped.

**Case 3: Non-leaf function with gap, LR != PC**

```cpp
volatile int side_effect;

int noop_int() {
  return side_effect;
}

void gap_trigger() {
  char* p = free_and_return(static_cast<char*>(malloc(1)));
  side_effect = noop_int();
  volatile char c = static_cast<volatile char*>(p)[0];  // MTE fault
}
```

```
gap_trigger:
  54180: paciasp
  54184: stp   x29, x30, [sp, #-0x20]!
  54188: str   x19, [sp, #0x10]
  5418c: mov   x29, sp
  54190: mov   w0, #0x1
  54194: bl    <malloc>
  54198: mov   x19, x0                    // save stale pointer in callee-saved reg
  5419c: bl    <free_and_return local helper>
  541a0: bl    <noop_int>                 // LR = 0x541a4
  541a4: adrp  x8, ...
  541a8: ldr   x8, [x8, ...]
  541ac: str   w0, [x8]                   // store noop_int return value
  541b0: ldrb  w8, [x19]                  // MTE fault: PC = 0x541b0 != LR = 0x541a4
  541b4: strb  w8, [x29, #0x1c]
  541b8: ldrb  w8, [x29, #0x1c]
  541bc: ldr   x19, [sp, #0x10]
  541c0: ldp   x29, x30, [sp], #0x20
  541c4: retaa
```

The current build keeps the stale pointer in `x19` before the helper call, then `bl noop_int` sets
LR to the `adrp` at `0x541a4`. A few more instructions store the return value before the faulting
`ldrb` at `0x541b0`. LR != PC, but both are still inside `gap_trigger`. bt[1] is stale and
skipped. The stale-LR detection should thus use the function address range, not a simple PC == LR
check.

#### Alternative approaches

This is simpler than the approaches used by other unwinding libraries:

**libunwind** (`libunwind/src/aarch64/Gstep.c`, `get_frame_state()`): On DWARF unwind failure,
libunwind scans prologue instructions to determine if a frame record has been created. It detects
`stp x29, x30, [sp, #offset]` (bitmask `0xfe407fff` = `0xa8007bfd`), then `mov x29, sp` /
`add x29, sp, #imm` (bitmask `0xff0003ff` = `0x910003fd`), then `ldp x29, x30, [sp], #offset`
(bitmask `0xfe407fff` = `0xa8407bfd`). It tracks a state machine (`NONE` -> `AT_SP_OFFSET` ->
`AT_FP` -> `NONE`) to determine whether to read saved LR from SP+offset, FP+8, or use raw x30.
This implicitly handles stale LR: if the frame record exists (`AT_FP`), the saved LR on the stack
is used because it was saved before any `bl` clobbered x30.

**libunwindstack**: Relies on DWARF CFI (.eh_frame / .debug_frame) to determine register locations
for each frame. DWARF CFI (call frame information) is unwind metadata that describes where each
function saves registers and how to recover the caller's register state. CFI rules encode which
registers are saved where, so non-leaf functions' return addresses are read from the stack, not
from x30. There is no explicit stale-LR check. It falls back to raw LR only when DWARF fails
(`Unwinder.cpp:SetPcFromReturnAddress()`).

Our function-range check is adequate because we only need to match a known pattern, not produce a
complete backtrace. The tradeoff is that it does not handle edge cases where LR happens to land in a
different function at a valid-looking address (e.g., if a `bl` target returns to an address that
coincidentally falls in the faulting function's range).

### Existing unwinding libraries

Existing libraries to deal with unwinding stacks are:

- system/unwinding/libunwindstack: Generally not async-signal-safe, as it uses heap allocations.
- [libunwind](https://github.com/libunwind/libunwind): Unlike AOSP's libunwindstack, it has less
  validation and still trusts the integrity of the program to an extent. This is not suited for a
  signal handler context handling a (MTE) segfault.

Generally, we implemented backtraces in a similar way to AOSP's libunwindstack methods for
backtraces:

- libunwindstack uses many defensive patterns like using `process_vm_readv` to read memory (returns
  `-EFAULT` instead of faulting), overflow checks, and limits on traversal loops. We follow these
  practices in general. `process_vm_readv` has ~11x overhead vs bare `memcpy` due to the syscall
  transition, `mmap_lock` (read), and page table validation. From libunwindstack's own
  `unwind_benchmarks` on Pixel 10a:

  ```
  BM_local_unwind_uncached_process_memory                    72857 ns    72638 ns    10457
  BM_local_unwind_uncached_process_memory_unsafe_reads        6644 ns     6623 ns    99981
  ```

  ~73us per unwind with `process_vm_readv` (`MemoryLocal`) vs ~7us with bare `memcpy`
  (`MemoryLocalUnsafe`). libunwindstack has the unsafe path for Chromium's performance analysis,
  reading from known-valid memory-backed ELF mappings where the syscall overhead is unnecessary.
  `Memory.h` warns on `CreateProcessMemoryLocalUnsafe`: "This should only be used for performance.
  Using this could result in crashes if used to try and read stack data."[^unsafe-reads]

  The unsafe path is not an option here: we read potentially corrupt stack and ELF memory inside a
  signal handler for a MTE crash, so `memcpy` on a bad pointer would trigger a recursive SIGSEGV
  and could hide the original crash. `process_vm_readv` safely returns `-EFAULT`, letting us skip
  bad reads. The ~11x overhead is acceptable: crashes are rare (the process is about to die or be
  suppressed), and the entire suppression check still completes within a crash-path budget that is
  acceptable for this use case. On the vendor HWC crash, direct matches are now back in the roughly
  single-digit millisecond range after the current hardening/refactor pass, while slower cases are
  still confined to repeated-pattern or repeated-fault paths.
- Frame pointer (FP) chain walking to capture return addresses from the signal context.

  libunwindstack doesn't do this and instead relies on DWARF
  unwinding[^dwarf-unwinding], which appears to be more complex to implement in an
  async-signal-safe way for a signal handler. FP chain walking works, since clang has
  (non-leaf) frame pointers enabled for Android builds.[^clang-fp]
- `/proc/self/maps` parsing to identify which DSO each return address belongs to
- ELF program header parsing (`PT_DYNAMIC`, `PT_LOAD`) to locate symbol tables and compute load bias
- `DT_GNU_HASH` / `DT_HASH` lookup to find symbols by name in `.dynsym`, then verifying the
  return address falls within the symbol's `[st_value, st_value + st_size)` half-open interval.

  libunwindstack doesn't do this, because it's doing the reverse task: mapping addresses to names
  for a printable backtrace.

[^hwc3-hal]: This is an older version; the current version is no longer published:
https://cs.android.com/android/platform/superproject/main/+/main:hardware/google/graphics/common/hwc3/impl/HalImpl.h;l=98-100;bpv=1
[^dwarf-unwinding]: system/unwinding/libunwindstack/Unwinder.cpp's `elf->Step` call,
system/unwinding/libunwindstack/Elf.cpp's `Elf::Step`,
system/unwinding/libunwindstack/ElfInterface.cpp's `ElfInterface::Step`
[^clang-fp]: prebuilts/clang/host/linux-x86/clang-r563880c/clang_source_info.md references base
revision [386af4a5c64ab75eaee2448dc38f2e34a40bfed0](https://github.com/llvm/llvm-project/commits/386af4a5c64ab75eaee2448dc38f2e34a40bfed0).
This can change between AOSP versions.
[^unsafe-reads]: https://cs.android.com/android/_/android/platform/system/unwinding/+/9ebb4981c2b9ba73018702531ded8de9c169958a
[^breakpad]: Breakpad documents the same basic crash-handler constraints in
`src/client/linux/minidump_writer/minidump_writer.cc`: after `SIGSEGV`, the
address space may be compromised, so the handler avoids the dynamic linker,
libc wrappers, and heap allocation.
https://github.com/google/breakpad/blob/main/src/client/linux/minidump_writer/minidump_writer.cc
