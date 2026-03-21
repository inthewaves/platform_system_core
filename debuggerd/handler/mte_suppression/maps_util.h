// Async-signal-safe /proc/self/maps parsing and line-reading utilities. This file keeps the text
// parser separate from the signal-handler entry point so it can be unit-tested on the host without
// aarch64 or bionic dependencies.

#pragma once

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>

namespace mte_suppression {

// open(2)/close(2) are POSIX async-signal-safe, but bionic's libc entry points add optional
// fdtrack/fdsan layers that do not belong in this crash-handler path. open() routes through
// FDTRACK_CREATE() in bionic/libc/bionic/open.cpp and bionic/libc/private/bionic_fdtrack.h, which
// can invoke an installed __android_fdtrack_hook. close() routes through
// android_fdsan_close_with_tag() in bionic/libc/bionic/fdsan.cpp, which also runs FDTRACK_CLOSE().
// If libfdtrack installs its hook (bionic/libfdtrack/fdtrack.cpp), that callback takes mutexes,
// mutates std::vector state, and unwinds stacks. Use raw syscalls here to avoid that optional
// wrapper path.
inline int async_safe_open_readonly_cloexec(const char* path) {
  return static_cast<int>(syscall(__NR_openat, AT_FDCWD, path, O_RDONLY | O_CLOEXEC, 0));
}

inline int async_safe_close(int fd) {
  return static_cast<int>(syscall(__NR_close, fd));
}

struct MapsEntry {
  // Start address of this mapping.
  uintptr_t start;
  // End address of this mapping.
  uintptr_t end;
  // File offset shown in /proc/self/maps.
  uintptr_t offset;
  // Mapping permissions such as "r-xp".
  char perms[5];
  // Pathname field from /proc/self/maps, or empty if none.
  char name[256];
};

// Parse a lowercase hex number from a string, advancing the pointer past the consumed digits. Used
// to extract addresses and offsets from /proc/self/maps lines.
inline uintptr_t parse_hex(const char*& p) {
  uintptr_t val = 0;
  while ((*p >= '0' && *p <= '9') || (*p >= 'a' && *p <= 'f')) {
    val <<= 4;
    if (*p >= '0' && *p <= '9') {
      val |= (*p - '0');
    } else {
      val |= (*p - 'a' + 10);
    }
    p++;
  }
  return val;
}

// Parse one line from /proc/self/maps into a MapsEntry. Format: "start-end perms offset dev inode
// pathname"
inline bool parse_maps_line(const char* line, MapsEntry* out) {
  const char* cursor = line;
  auto skip_field = [&]() {
    while (*cursor && *cursor != ' ') cursor++;
  };
  auto skip_spaces = [&]() {
    while (*cursor == ' ') cursor++;
  };

  out->start = parse_hex(cursor);
  if (*cursor != '-') return false;
  cursor++;
  out->end = parse_hex(cursor);
  skip_spaces();
  size_t perms_len = 0;
  while (*cursor && *cursor != ' ' && perms_len < sizeof(out->perms) - 1) {
    out->perms[perms_len++] = *cursor++;
  }
  out->perms[perms_len] = '\0';
  skip_field();  // perms
  skip_spaces();
  out->offset = parse_hex(cursor);
  skip_spaces();
  skip_field();  // dev
  skip_spaces();
  skip_field();   // inode
  skip_spaces();  // pathname follows

  size_t name_len = 0;
  while (*cursor && *cursor != '\n' && name_len < sizeof(out->name) - 1) {
    out->name[name_len++] = *cursor++;
  }
  out->name[name_len] = '\0';
  return out->start < out->end;
}

// True if this /proc/self/maps entry has execute permission. We use this to distinguish actual code
// frames from arbitrary readable addresses when validating a captured backtrace against a
// suppression pattern.
inline bool maps_entry_is_executable(const MapsEntry& entry) {
  return entry.perms[0] != '\0' && entry.perms[2] == 'x';
}

// Async-signal-safe streaming line reader.
//
// Why not use stdlib? std::getline heap-allocates via std::string, fgets holds a FILE* mutex, and
// POSIX getline calls malloc. None are async-signal-safe.
//
// This reads from fd into an internal stack buffer, splits on '\n', and calls line_fn(line) for
// each complete line. line_fn receives a null-terminated string without the '\n'. Return false from
// line_fn to stop early.
//
// Template parameters are resolved at compile time: BufSize defaults to 1024, which is sufficient
// for /proc/self/maps lines, and F is the concrete lambda type, so the call stays inlined with no
// std::function.
template <size_t BufSize = 1024, typename F>
inline void for_each_line_from_fd(int fd, F&& line_fn) {
  static_assert(BufSize >= 2);
  char buf[BufSize];
  constexpr size_t kMaxData = BufSize - 1;  // Last byte reserved for '\0'.
  size_t used = 0;                          // Bytes of valid data in buf[0..used-1].

  for (;;) {
    // --- Step 1: Read more data into the buffer ---
    //
    // If there is no room left, a single line has exceeded the buffer. Deliver the truncated line,
    // discard the rest of it up to the next '\n', and continue with subsequent lines.
    size_t remaining;
    if (__builtin_sub_overflow(kMaxData, used, &remaining) || remaining == 0) {
      buf[kMaxData] = '\0';
      if (!line_fn(buf)) return;
      used = 0;
      // Drain the remainder of the oversized line.
      char discard[BufSize / 2];
      for (;;) {
        ssize_t d = TEMP_FAILURE_RETRY(read(fd, discard, sizeof(discard)));
        if (d <= 0) return;  // EOF/error while draining.
        char* nl = static_cast<char*>(memchr(discard, '\n', static_cast<size_t>(d)));
        if (nl) {
          // Found the end of the oversized line. Copy anything after '\n' into buf as the start of
          // the next line.
          size_t after = static_cast<size_t>(d) - static_cast<size_t>(nl + 1 - discard);
          if (after > 0 && after <= kMaxData) {
            memcpy(buf, nl + 1, after);
            used = after;
          }
          break;
        }
      }
      continue;
    }

    ssize_t n = TEMP_FAILURE_RETRY(read(fd, buf + used, remaining));
    if (n > 0) used += static_cast<size_t>(n);
    if (used == 0) break;  // Nothing in the buffer and nothing read. We're done
    buf[used] = '\0';

    // --- Step 2: Deliver every complete line ---
    char* cursor = buf;
    char* nl;
    while ((nl = strchr(cursor, '\n')) != nullptr) {
      *nl = '\0';
      if (!line_fn(cursor)) return;  // Caller asked to stop.
      cursor = nl + 1;
    }

    // --- Step 3: Compact leftovers ---
    //
    // Any data after the last '\n' is an incomplete line.  Shift it to the front so the next read()
    // appends to it.
    size_t leftover = used - static_cast<size_t>(cursor - buf);
    if (leftover > 0 && cursor != buf) memmove(buf, cursor, leftover);
    used = leftover;

    // --- Step 4: Handle EOF / read error ---
    if (n <= 0) {
      if (used > 0) {
        buf[used] = '\0';
        line_fn(buf);  // Flush any trailing partial line.
      }
      break;
    }
  }
}

}  // namespace mte_suppression
