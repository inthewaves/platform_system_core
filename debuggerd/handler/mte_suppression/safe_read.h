// Async-signal-safe memory reads via process_vm_readv

#pragma once

#include <stdint.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>
#include <algorithm>

namespace mte_suppression {

// Safe memory read via process_vm_readv. Returns false on any failure, such as unmapped memory or a
// partial read, instead of faulting.
//
// process_vm_readv acquires mmap_lock (read) on the target mm. That is safe in this handler because
// MTE signals are delivered at userspace return boundaries, after kernel locks have been released.
// libunwindstack uses the same syscall for local reads (Memory.cpp:MemoryLocal::Read).
// process_vm_readv is also allowed by Android's seccomp-BPF policy for both app and system
// processes (bionic/libc/SYSCALLS.TXT, not in SECCOMP_BLOCKLIST_APP.TXT).
//
// process_vm_readv is about 11x slower than bare memcpy for local reads (~73 us vs ~7 us per unwind
// on Pixel 10a; see libunwindstack/benchmarks/local_unwind_benchmarks.cpp,
// BM_local_unwind_uncached_process_memory vs BM_local_unwind_uncached_process_memory_unsafe_reads).
// libunwindstack has a separate MemoryLocalUnsafe class for Chromium-style performance analysis,
// where the data source is already trusted. Memory.h warns on CreateProcessMemoryLocalUnsafe that
// it should only be used for performance and can crash if used on stack data.
//
// The unsafe path is not an option here despite already being in a crash handler. We read
// potentially corrupt stack and ELF memory after an MTE fault, so memcpy on a bad pointer could
// raise SIGSEGV and hide the original crash. process_vm_readv instead fails with EFAULT, letting us
// skip bad reads.
//
// To reproduce the benchmark:
// clang-format off
//   m unwind_benchmarks
//   adb push $ANDROID_PRODUCT_OUT/data/benchmarktest64/unwind_benchmarks \
//       /data/local/tmp
//   adb shell /data/local/tmp/unwind_benchmarks/unwind_benchmarks \
//       --benchmark_filter='BM_local_unwind_uncached_process_memory'
// clang-format on
inline bool safe_read(void* dst, uintptr_t addr, size_t len) {
  // This runs in the original crashing process inside debuggerd_signal_handler or
  // debuggerd_handle_signal before debuggerd forks crash_dump, so bionic's normal cached getpid()
  // path is appropriate here.
  const pid_t pid = getpid();
  // Page-split process_vm_readv logic copied almost verbatim from
  // system/unwinding/libunwindstack/Memory.cpp ProcessVmRead(), aside from these differences:
  // - This is essentially ReadFully, so requested_len is tracked explicitly
  // - Failure paths return false instead of total_read
  // - errno-setting on overflow / UINTPTR_MAX checks is omitted
  const size_t requested_len = len;

  // Split up the remote read across page boundaries.
  // From the manpage:
  //   A partial read/write may result if one of the remote_iov elements points to an invalid
  //   memory region in the remote process.
  //
  //   Partial transfers apply at the granularity of iovec elements.  These system calls won't
  //   perform a partial transfer that splits a single iovec element.
  constexpr size_t kMaxIovecs = 64;
  struct iovec src_iovs[kMaxIovecs];

  uint64_t cur = addr;
  size_t total_read = 0;
  while (len > 0) {
    struct iovec dst_iov = {
        .iov_base = &reinterpret_cast<uint8_t*>(dst)[total_read],
        .iov_len = len,
    };

    size_t iovecs_used = 0;
    while (len > 0) {
      if (iovecs_used == kMaxIovecs) {
        break;
      }

      // struct iovec uses void* for iov_base.
      if (cur >= UINTPTR_MAX) {
        // errno = EFAULT;
        return false;
      }

      src_iovs[iovecs_used].iov_base = reinterpret_cast<void*>(cur);

      uintptr_t misalignment = cur & (getpagesize() - 1);
      size_t iov_len = getpagesize() - misalignment;
      iov_len = std::min(iov_len, len);

      len -= iov_len;
      if (__builtin_add_overflow(cur, iov_len, &cur)) {
        // errno = EFAULT;
        return false;
      }

      src_iovs[iovecs_used].iov_len = iov_len;
      ++iovecs_used;
    }

    ssize_t rc = process_vm_readv(pid, &dst_iov, 1, src_iovs, iovecs_used, 0);
    if (rc == -1) {
      return false;
    }
    total_read += rc;
  }

  // Memory.cpp ReadFully
  return total_read == requested_len;
}

// Safely read a NUL-terminated string with an explicit maximum source length. Returns false if the
// address is invalid, the source string is not terminated within max_len, or dst is too small to
// hold the full string plus NUL.
//
// On failure, dst is reset to the empty string rather than leaving behind a partial prefix.
// parse_dynamic() relies on this for DT_SONAME handling. A malformed or unterminated SONAME is
// treated as absent, matching libunwindstack's bounded string reads in
// system/unwinding/libunwindstack/ElfInterface.cpp.
inline bool safe_read_cstring(char* dst, size_t dst_size, uintptr_t addr, size_t max_len) {
  if (dst_size == 0) return false;
  dst[0] = '\0';

  // Chunked bounded-string read adapted from
  // system/unwinding/libunwindstack/Memory.cpp Memory::ReadString(). The main
  // change is writing into char* dst instead of std::string.
  char buffer[256];  // Large enough for 99% of symbol names.
  size_t size = 0;   // Number of bytes which were read into the buffer.
  for (size_t offset = 0; offset < max_len; offset += size) {
    uintptr_t chunk_addr;
    if (__builtin_add_overflow(addr, offset, &chunk_addr)) {
      dst[0] = '\0';
      return false;
    }

    // Look for the null terminator first so we can stop without reading the full remaining range.
    // If we know the end of valid memory range, do the reads in larger blocks.
    size_t read = std::min(sizeof(buffer), max_len - offset);
    if (!safe_read(buffer, chunk_addr, read)) {
      dst[0] = '\0';
      return false;  // We have not found the end of the string yet and cannot read more data.
    }
    size = read;

    size_t length = strnlen(buffer, size);  // Index of the null-terminator.
    if (length < size) {
      // We found the null-terminator.
      if (offset == 0) {
        // We did just a single read, so the buffer already contains the whole string.
        if (length + 1 > dst_size) {
          dst[0] = '\0';
          return false;
        }
        memcpy(dst, buffer, length + 1);
        return true;
      } else {
        // The buffer contains only the last block. The earlier blocks have already been copied into
        // dst, so just append the final block plus NUL.
        if (offset + length + 1 > dst_size) {
          dst[0] = '\0';
          return false;
        }
        memcpy(dst + offset, buffer, length + 1);
        return true;
      }
    }

    if (offset + size + 1 > dst_size) {
      dst[0] = '\0';
      return false;
    }
    memcpy(dst + offset, buffer, size);
  }

  dst[0] = '\0';
  return false;
}

// Safely read array element base[idx] of type T via process_vm_readv. Combines overflow-checked
// address computation with safe_read.
template <typename T>
inline bool safe_read_at(T* out, uintptr_t base, uintptr_t idx) {
  uintptr_t offset, addr;
  if (__builtin_mul_overflow(idx, static_cast<uintptr_t>(sizeof(T)), &offset)) return false;
  if (__builtin_add_overflow(base, offset, &addr)) return false;
  return safe_read(out, addr, sizeof(T));
}

}  // namespace mte_suppression
