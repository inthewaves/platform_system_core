// ELF DSO lookup utilities for MTE crash suppression. This file keeps ELF parsing and symbol lookup
// separate from the signal-handler entry point so they can be unit-tested on aarch64 devices.
//
// These functions use process_vm_readv through safe_read() to read ELF data from mapped memory. On
// device, process_vm_readv on self also works outside signal handlers.

#pragma once

#include <elf.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>

#include <async_safe/log.h>

#include "elf_lookup_util.h"
#include "safe_read.h"

namespace mte_suppression {

// ---------------------------------------------------------------------------
// Resolved DSO info: runtime segment ranges plus the dynamic-lookup tables needed for exact symbol
// matching.
//
// "Runtime address" here means the post-ASLR address seen in /proc/self/maps and in the crashing
// backtrace. ELF program headers and symbol tables usually describe addresses as file virtual
// addresses (p_vaddr / st_value), so this struct keeps enough state to translate between the two.
// ---------------------------------------------------------------------------

struct DsoInfo {
  // Runtime address where the ELF header is mapped.
  uintptr_t base;
  // Page-aligned minimum PT_LOAD p_vaddr.
  uintptr_t elf_load_bias;
  // Lowest PT_LOAD segment start in runtime address space.
  uintptr_t load_start;
  // Highest PT_LOAD segment end in runtime address space.
  uintptr_t load_end;
  // Coarse union of all PT_LOAD ranges, kept for logs and tests.
  uintptr_t code_start;
  // Coarse union of all PT_LOAD ranges, kept for logs and tests.
  uintptr_t code_end;
  // Lowest executable PT_LOAD segment start.
  uintptr_t exec_start;
  // Highest executable PT_LOAD segment end.
  uintptr_t exec_end;
  // Runtime address of DT_SYMTAB (.dynsym).
  uintptr_t symtab_addr;
  // Runtime address of DT_STRTAB (.dynstr).
  uintptr_t strtab_addr;
  // Runtime address of DT_GNU_HASH, or 0 if absent.
  uintptr_t gnu_hash_addr;
  // Runtime address of DT_HASH, or 0 if absent.
  uintptr_t hash_addr;
  // DT_SONAME string, for example "libfoo.so". Empty if absent.
  char soname[128];
  // True if the DSO parsed cleanly enough to use for matching.
  bool valid;
};

// Overflow-safe half-open range containment check for [addr, addr + size). Used throughout the ELF
// parser so corrupted pointers cannot wrap back into a low address and spuriously appear in-bounds.
inline bool range_contains(uintptr_t start, uintptr_t end, uintptr_t addr, size_t size) {
  uintptr_t addr_end;
  if (__builtin_add_overflow(addr, size, &addr_end)) return false;
  return addr >= start && addr_end <= end;
}

// True if the requested read stays within the DSO's total PT_LOAD coverage. This is stricter than
// plain safe_read(): the address must be readable and must still belong to the same DSO whose
// dynamic table we are parsing.
inline bool dso_contains_load_range(const DsoInfo* dso, uintptr_t addr, size_t size) {
  return dso->load_start < dso->load_end &&
         range_contains(dso->load_start, dso->load_end, addr, size);
}

// Translate an ELF virtual address (p_vaddr / d_ptr / st_value style) into the corresponding
// runtime address for this mapped DSO:
//   runtime_addr = base + (elf_vaddr - elf_load_bias)
//
// This is the same basic conversion the linker uses after ASLR rebases the DSO. We centralize it
// here because the parser has to apply this translation in several places, and the arithmetic is
// easy to misread in-line. The closest bionic equivalents are the load-bias and segment-address
// calculations in
// bionic/linker/linker_phdr.cpp phdr_table_get_load_size() and
// bionic/linker/linker_phdr.cpp ElfReader::LoadSegments(), plus the
// symbol-address handling in bionic/linker/linker_soinfo.cpp soinfo::resolve_symbol_address().
inline bool elf_vaddr_to_runtime_addr(uintptr_t base, uintptr_t elf_load_bias, uintptr_t elf_vaddr,
                                      uintptr_t* runtime_addr) {
  if (elf_vaddr < elf_load_bias) return false;
  return !__builtin_add_overflow(base, elf_vaddr - elf_load_bias, runtime_addr);
}

// Read element base[idx] only if the resulting address stays inside this DSO's PT_LOAD range. This
// prevents a corrupted in-memory DT_SYMTAB/DT_HASH/DT_GNU_HASH/DT_STRTAB pointer from redirecting
// symbol resolution into an unrelated readable mapping.
template <typename T>
inline bool safe_read_dso_at(T* out, const DsoInfo* dso, uintptr_t base, uintptr_t idx) {
  // The dynamic linker validates ELF metadata once during
  // bionic/linker/linker.cpp soinfo::prelink_image(), but this code reads already-mapped ELF state
  // in a crash handler after memory corruption. Mirror libunwindstack's "validate every read"
  // approach from system/unwinding/libunwindstack/Memory.cpp by rejecting table walks that leave
  // the DSO's own PT_LOAD coverage.
  uintptr_t offset;
  if (__builtin_mul_overflow(idx, static_cast<uintptr_t>(sizeof(T)), &offset)) return false;
  uintptr_t addr;
  if (__builtin_add_overflow(base, offset, &addr)) return false;
  if (!dso_contains_load_range(dso, addr, sizeof(T))) return false;
  return safe_read(out, addr, sizeof(T));
}

// ---------------------------------------------------------------------------
// ELF hash-based symbol lookup.
// ---------------------------------------------------------------------------

// Look up a symbol by exact name using the DT_GNU_HASH table. Returns true if found, fills sym_out
// with the matching symbol entry. Follows the same Bloom filter -> bucket -> chain walk algorithm
// as bionic's dynamic linker (bionic/linker/linker_soinfo.cpp:soinfo::gnu_lookup).
//
// GNU hash table layout (from DT_GNU_HASH address):
//   header:  [nbuckets, symoffset, bloom_size, bloom_shift]  (4 x uint32_t)
//   bloom:   bloom[bloom_size]  (pointer-sized Bloom filter words)
//   buckets: buckets[nbuckets]  (uint32_t, first symbol index per bucket)
//   chains:  chains[]  (uint32_t, parallel to symtab starting at symoffset;
//                       upper 31 bits = hash, LSB = 1 marks end of chain)
inline bool gnu_hash_lookup(const DsoInfo* dso, const char* name, Elf64_Sym* sym_out) {
  uint32_t hash = gnu_hash_calc(name);

  // Read header: [nbuckets, symoffset, bloom_size, bloom_shift].
  uint32_t header[4];
  if (!dso_contains_load_range(dso, dso->gnu_hash_addr, sizeof(header))) return false;
  if (!safe_read(header, dso->gnu_hash_addr, sizeof(header))) return false;

  uint32_t nbuckets = header[0];
  uint32_t symoffset = header[1];
  uint32_t bloom_size = header[2];
  uint32_t bloom_shift = header[3];
  if (nbuckets == 0 || bloom_size == 0) return false;
  constexpr uint32_t kMaxReasonable = 1000000;
  if (nbuckets > kMaxReasonable || bloom_size > kMaxReasonable) return false;

  // Compute base addresses for the three sub-tables that follow the header. These correspond to
  // bionic's gnu_bloom_filter_, gnu_bucket_, and gnu_chain_ members
  // (bionic/linker/linker_soinfo.h), which are set once during prelink_image().
  uintptr_t bloom_base, buckets_base, chains_base;
  if (__builtin_add_overflow(dso->gnu_hash_addr, 4 * sizeof(uint32_t), &bloom_base)) return false;
  if (__builtin_add_overflow(bloom_base, (uintptr_t)bloom_size * sizeof(uintptr_t),
                             &buckets_base)) {
    return false;
  }
  if (__builtin_add_overflow(buckets_base, (uintptr_t)nbuckets * sizeof(uint32_t), &chains_base)) {
    return false;
  }

  // --- Bloom filter check ---
  // bionic/linker/linker_soinfo.cpp:soinfo::gnu_lookup:
  //   constexpr uint32_t kBloomMaskBits = sizeof(ElfW(Addr)) * 8;
  //   const uint32_t word_num = (hash / kBloomMaskBits) & gnu_maskwords_;
  //   const ElfW(Addr) bloom_word = gnu_bloom_filter_[word_num];
  //   if ((1 & (bloom_word >> h1) & (bloom_word >> h2)) == 0) return nullptr;
  constexpr uint32_t kBloomMaskBits = sizeof(uintptr_t) * 8;  // 64 on AArch64
  uintptr_t bloom_word;
  if (!safe_read_dso_at(&bloom_word, dso, bloom_base,
                        (uintptr_t)((hash / kBloomMaskBits) % bloom_size))) {
    return false;
  }

  uint32_t h1 = hash % kBloomMaskBits;
  uint32_t h2 = (hash >> bloom_shift) % kBloomMaskBits;
  // test against bloom filter
  if ((1 & (bloom_word >> h1) & (bloom_word >> h2)) == 0) return false;

  // bloom test says "probably yes"... bionic: uint32_t n = gnu_bucket_[hash % gnu_nbucket_];
  uint32_t n;
  if (!safe_read_dso_at(&n, dso, buckets_base, (uintptr_t)(hash % nbuckets))) return false;

  if (n == 0) return false;

  // --- Chain walk ---
  // bionic/linker/linker_soinfo.cpp:soinfo::gnu_lookup:
  //   do {
  //     ElfW(Sym)* s = symtab_ + n;
  //     if (((gnu_chain_[n] ^ hash) >> 1) == 0 &&
  //         strcmp(get_string(s->st_name), symbol_name.get_name()) == 0 &&
  //         is_symbol_global_and_defined(this, s)) {
  //       return symtab_ + n;
  //     }
  //   } while ((gnu_chain_[n++] & 1) == 0);
  size_t name_len = strlen(name);
  constexpr size_t kMaxChainSteps = 4096;
  size_t step = 0;
  uint32_t chain_val = 0;

  do {
    if (n < symoffset || step++ >= kMaxChainSteps) return false;

    // Read chain entry: upper 31 bits = hash, LSB = end-of-chain flag. bionic reads gnu_chain_[n]
    // twice (body + while); we read once.
    if (!safe_read_dso_at(&chain_val, dso, chains_base, (uintptr_t)(n - symoffset))) return false;

    // Compare upper 31 bits of hash (LSB is end-of-chain flag).
    if (((chain_val ^ hash) >> 1) == 0) {
      // Hash matches; read the symbol and compare names. bionic: ElfW(Sym)* s = symtab_ + n;
      Elf64_Sym sym;
      if (!safe_read_dso_at(&sym, dso, dso->symtab_addr, (uintptr_t)n)) return false;

      // Hash matches; check binding and name, then return if everything matches. Keep all checks
      // inside the if-block so the end-of-chain test (chain_val & 1) in the while condition always
      // runs, matching
      // bionic/linker/linker_soinfo.cpp soinfo::gnu_lookup():
      //   if (hash_match && check_symbol_version && strcmp && is_global_defined) return;
      // We skip check_symbol_version (we look up known symbols in known DSOs).
      if (is_symbol_global_and_defined(&sym)) {
        char name_buf[256];
        size_t read_len = (name_len + 1 < sizeof(name_buf)) ? name_len + 1 : sizeof(name_buf);
        uintptr_t name_addr;
        if (__builtin_add_overflow(dso->strtab_addr, (uintptr_t)sym.st_name, &name_addr))
          return false;
        if (!dso_contains_load_range(dso, name_addr, read_len)) return false;
        if (!safe_read(name_buf, name_addr, read_len)) return false;
        name_buf[read_len - 1] = '\0';

        if (strcmp(name_buf, name) == 0) {
          *sym_out = sym;
          return true;
        }
      }
    }
    // bionic: } while ((gnu_chain_[n++] & 1) == 0);
    n++;
  } while ((chain_val & 1) == 0);

  return false;
}

// Look up a symbol by exact name using the DT_HASH (SYSV hash) table. Returns true if found, fills
// sym_out with the matching symbol entry. Follows the same bucket -> chain walk algorithm as
// bionic's dynamic linker
// (bionic/linker/linker_soinfo.cpp:soinfo::elf_lookup).
//
// DT_HASH layout:
//   header:  [nbuckets, nchain]  (2 x uint32_t)
//   buckets: buckets[nbuckets]   (uint32_t)
//   chains:  chains[nchain]      (uint32_t, next symbol index or 0)
inline bool elf_hash_lookup(const DsoInfo* dso, const char* name, Elf64_Sym* sym_out) {
  uint32_t hash = elf_hash_calc(name);

  uint32_t header[2];
  if (!dso_contains_load_range(dso, dso->hash_addr, sizeof(header))) return false;
  if (!safe_read(header, dso->hash_addr, sizeof(header))) return false;

  uint32_t nbuckets = header[0];
  uint32_t nchain = header[1];
  if (nbuckets == 0 || nchain == 0) return false;
  constexpr uint32_t kMaxReasonable = 1000000;
  if (nbuckets > kMaxReasonable || nchain > kMaxReasonable) return false;

  // Compute base addresses for the two sub-tables that follow the header. These correspond to
  // bionic's bucket_ and chain_ members
  // (bionic/linker/linker_soinfo.h), which are set once during prelink_image().
  uintptr_t buckets_base, chains_base;
  if (__builtin_add_overflow(dso->hash_addr, 2 * sizeof(uint32_t), &buckets_base)) return false;
  if (__builtin_add_overflow(buckets_base, (uintptr_t)nbuckets * sizeof(uint32_t), &chains_base)) {
    return false;
  }

  // bionic: uint32_t n = bucket_[hash % nbucket_];
  uint32_t n;
  if (!safe_read_dso_at(&n, dso, buckets_base, (uintptr_t)(hash % nbuckets))) return false;

  size_t name_len = strlen(name);
  constexpr size_t kMaxChainSteps = 4096;

  // bionic/linker/linker_soinfo.cpp:soinfo::elf_lookup:
  //   for (uint32_t n = bucket_[hash % nbucket_]; n != 0; n = chain_[n]) {
  //     ElfW(Sym)* s = symtab_ + n;
  //     if (strcmp(get_string(s->st_name), symbol_name.get_name()) == 0 &&
  //         is_symbol_global_and_defined(this, s)) {
  //       return symtab_ + n;
  //     }
  //   }
  for (size_t step = 0; n != 0 && step < kMaxChainSteps; step++) {
    if (n >= nchain) return false;

    // bionic: ElfW(Sym)* s = symtab_ + n;
    Elf64_Sym sym;
    if (!safe_read_dso_at(&sym, dso, dso->symtab_addr, (uintptr_t)n)) return false;

    // Matches bionic/linker/linker_soinfo.cpp soinfo::elf_lookup():
    //   if (check_symbol_version && strcmp && is_global_defined) return;
    // We skip check_symbol_version (we look up known symbols in known DSOs).
    if (is_symbol_global_and_defined(&sym)) {
      char name_buf[256];
      size_t read_len = (name_len + 1 < sizeof(name_buf)) ? name_len + 1 : sizeof(name_buf);
      uintptr_t name_addr;
      if (__builtin_add_overflow(dso->strtab_addr, (uintptr_t)sym.st_name, &name_addr))
        return false;
      if (!dso_contains_load_range(dso, name_addr, read_len)) return false;
      if (!safe_read(name_buf, name_addr, read_len)) return false;
      name_buf[read_len - 1] = '\0';

      if (strcmp(name_buf, name) == 0) {
        *sym_out = sym;
        return true;
      }
    }

    // Follow chain to next symbol in this bucket. bionic: n = chain_[n]
    if (!safe_read_dso_at(&n, dso, chains_base, (uintptr_t)n)) return false;
  }

  return false;
}

// ---------------------------------------------------------------------------
// PT_DYNAMIC and full DSO ELF parsing.
// ---------------------------------------------------------------------------

// Parse PT_DYNAMIC to extract the pieces needed for exact symbol lookup:
//   1. DT_SYMTAB / DT_STRTAB
//   2. DT_GNU_HASH or DT_HASH
//   3. DT_SONAME for APK-embedded libraries
//
// dyn_addr is the runtime address of the PT_DYNAMIC segment. base is the offset=0 maps base for the
// DSO, and elf_load_bias is the page-aligned minimum PT_LOAD p_vaddr. Dynamic tags store ELF
// virtual addresses, so each d_ptr must be translated back into a runtime address before we can
// safely read it.
//
// This mirrors the data bionic records during
// bionic/linker/linker.cpp soinfo::prelink_image() and uses later in
// bionic/linker/linker_soinfo.cpp soinfo::gnu_lookup() /
// bionic/linker/linker_soinfo.cpp soinfo::elf_lookup(), but here we have to
// reconstruct it directly from already-mapped ELF bytes inside a crash handler.
//
// Every memory access uses safe_read() because this runs in a signal handler where mapped ELF data
// may already be corrupt. See safe_read.h for the full rationale.
inline bool parse_dynamic(uintptr_t dyn_addr, size_t dyn_size, uintptr_t base,
                          uintptr_t elf_load_bias, DsoInfo* out) {
  uintptr_t raw_symtab = 0, raw_strtab = 0, raw_hash = 0, raw_gnu_hash = 0, raw_soname = 0;
  uintptr_t raw_strsz = 0;

  // Cap the dynamic-section walk. A well-formed DSO has at most a few dozen entries. 4096 is
  // generous and prevents an infinite loop if DT_NULL is missing or corrupt.
  constexpr size_t kMaxDynEntries = 4096;
  if (!dso_contains_load_range(out, dyn_addr, dyn_size)) return false;
  size_t dyn_entries = dyn_size / sizeof(Elf64_Dyn);
  if (dyn_entries > kMaxDynEntries) dyn_entries = kMaxDynEntries;
  for (size_t i = 0; i < dyn_entries; i++) {
    Elf64_Dyn dyn;
    uintptr_t entry_addr;
    if (__builtin_add_overflow(dyn_addr, static_cast<uintptr_t>(i) * sizeof(Elf64_Dyn),
                               &entry_addr)) {
      break;
    }
    if (!safe_read(&dyn, entry_addr, sizeof(dyn))) break;
    if (dyn.d_tag == DT_NULL) break;
    switch (dyn.d_tag) {
      case DT_SYMTAB:
        raw_symtab = dyn.d_un.d_ptr;
        break;
      case DT_STRTAB:
        raw_strtab = dyn.d_un.d_ptr;
        break;
      case DT_HASH:
        raw_hash = dyn.d_un.d_ptr;
        break;
      case DT_GNU_HASH:
        raw_gnu_hash = dyn.d_un.d_ptr;
        break;
      case DT_STRSZ:
        raw_strsz = dyn.d_un.d_val;
        break;
      case DT_SONAME:
        raw_soname = dyn.d_un.d_val;
        break;
    }
  }

  // Convert the ELF virtual addresses stored in PT_DYNAMIC into runtime addresses inside this
  // mapped DSO, then prove the minimum structure size fits inside the DSO's PT_LOAD coverage.
  auto translate_dynamic_pointer = [&](uintptr_t raw, uintptr_t* result, size_t min_size) -> bool {
    if (!elf_vaddr_to_runtime_addr(base, elf_load_bias, raw, result)) return false;
    return dso_contains_load_range(out, *result, min_size);
  };

  // DT_STRSZ is mandatory for bounded DT_STRTAB / DT_SONAME validation. This matches how
  // system/unwinding/libunwindstack/ElfInterface.cpp bounds SONAME reads against the dynamic string
  // table instead of trusting an unterminated string to stop before the end of mapped ELF data.
  if (raw_strsz == 0) return false;
  if (raw_symtab && !translate_dynamic_pointer(raw_symtab, &out->symtab_addr, sizeof(Elf64_Sym))) {
    return false;
  }
  if (raw_strtab && !translate_dynamic_pointer(raw_strtab, &out->strtab_addr, raw_strsz)) {
    return false;
  }
  if (raw_hash && !translate_dynamic_pointer(raw_hash, &out->hash_addr, 2 * sizeof(uint32_t))) {
    return false;
  }
  if (raw_gnu_hash &&
      !translate_dynamic_pointer(raw_gnu_hash, &out->gnu_hash_addr, 4 * sizeof(uint32_t))) {
    return false;
  }

  if (!(out->symtab_addr && out->strtab_addr && (out->gnu_hash_addr || out->hash_addr))) {
    return false;
  }

  // Read DT_SONAME from the dynamic string table. This is the library's internal name (e.g.
  // "libfoo.so"), needed to identify APK-embedded DSOs whose path in /proc/self/maps only shows the
  // .apk filename. The DT_STRSZ bound check is deliberate: we treat SONAME as untrusted ELF data
  // and only accept strings that are fully contained within the dynamic string table, following the
  // same model as libunwindstack's SONAME extraction in
  // system/unwinding/libunwindstack/ElfInterface.cpp and APK display-name logic
  // in system/unwinding/libunwindstack/MapInfo.cpp.
  out->soname[0] = '\0';
  if (raw_soname != 0 && raw_strsz != 0 && raw_soname < raw_strsz) {
    uintptr_t soname_addr;
    if (!__builtin_add_overflow(out->strtab_addr, static_cast<uintptr_t>(raw_soname),
                                &soname_addr)) {
      safe_read_cstring(out->soname, sizeof(out->soname), soname_addr, raw_strsz - raw_soname);
    }
  }

  return true;
}

// Read ELF header and program headers from a DSO mapped at base. map_end is the end address of the
// /proc/self/maps entry that supplied base. For normal DSOs, base is the offset=0 entry from
// /proc/self/maps. For APK-embedded DSOs, base is the maps entry whose file offset points to the
// start of the .so within the APK; the ELF header is still at base because the kernel maps that
// file region there (see bionic/linker/linker_phdr.cpp ElfReader::LoadSegments()). Compute the
// PT_LOAD-derived ranges, then parse PT_DYNAMIC for symbol/hash table pointers and DT_SONAME.
// Returns true if the DSO was fully resolved.
//
// Unlike the dynamic linker, which trusts ELF data from disk after validation in
// bionic/linker/linker.cpp soinfo::prelink_image(), this code runs in a signal handler triggered by
// memory corruption from an MTE fault. The ELF structures we read may themselves be corrupt, and a
// crash here would be fatal because it would recurse on the signal stack.
//
// Therefore every memory access goes through safe_read(), which uses process_vm_readv so a bad read
// fails with EFAULT instead of faulting. Pointer arithmetic uses __builtin_add_overflow to catch
// integer overflow, and chain walks are capped to prevent infinite loops on corrupted hash tables.
// This follows the same defensive pattern used by libunwindstack
// (system/unwinding/libunwindstack/Symbols.cpp and Memory.cpp), which also
// guards against malformed ELF data when unwinding, although it unwinds arbitrary stack traces
// rather than only SEGV_MTESERR.
//
// The initial Ehdr + Phdr bootstrap is additionally bounded to the first maps entry that contained
// base. This closes the one place where we do not yet have trusted PT_LOAD-derived bounds: a
// corrupted e_phoff must not be able to send the Phdr read into unrelated readable memory and
// define a fake load layout. libunwindstack gets similar protection from its higher-level ownership
// model: MapInfo + Memory objects already tie an ELF parse to a specific mapped file range (see
// system/unwinding/libunwindstack/MapInfo.cpp and Memory.cpp). Here we are parsing mapped ELF data
// directly inside a signal handler, so we need an explicit bootstrap bound before we can trust any
// PT_LOAD-derived range.
inline bool parse_dso_elf(uintptr_t base, uintptr_t map_end, DsoInfo* out) {
  // High-level flow:
  //   1. Safely bootstrap the ELF header + program headers from the initial map.
  //   2. Derive the DSO's runtime load layout from PT_LOAD.
  //   3. Locate PT_DYNAMIC and translate it into a runtime address.
  //   4. Parse symbol/hash/string-table pointers out of PT_DYNAMIC.
  //
  // Conceptually this is a tiny, signal-handler-safe subset of what the bionic linker does when
  // loading a shared library:
  //   - bionic/linker/linker_phdr.cpp ElfReader::Read() and
  //     bionic/linker/linker_phdr.cpp phdr_table_get_load_size() read program
  //     headers and compute load bias
  //   - bionic/linker/linker.cpp soinfo::prelink_image() records PT_DYNAMIC state
  //   - bionic/linker/linker_soinfo.cpp soinfo::gnu_lookup() and
  //     bionic/linker/linker_soinfo.cpp soinfo::elf_lookup() resolve symbols
  if (map_end <= base) return false;

  // ----- Phase 1: bootstrap from the initial /proc/self/maps entry -----
  // The ELF header itself must fit inside the initial maps entry. We cannot use later
  // PT_LOAD-derived ranges yet because those are computed from the Phdrs we are about to read.
  if (!range_contains(base, map_end, base, sizeof(Elf64_Ehdr))) return false;

  Elf64_Ehdr ehdr;
  if (!safe_read(&ehdr, base, sizeof(ehdr))) return false;
  if (!verify_elf_header(ehdr)) return false;

  // Read all program headers in one shot.
  Elf64_Phdr phdrs[kMaxPhdrs];
  uintptr_t phdr_table_addr;
  if (__builtin_add_overflow(base, static_cast<uintptr_t>(ehdr.e_phoff), &phdr_table_addr)) {
    return false;
  }
  size_t phdr_table_size;
  if (__builtin_mul_overflow(static_cast<size_t>(ehdr.e_phnum), sizeof(Elf64_Phdr),
                             &phdr_table_size)) {
    return false;
  }
  // Bound the Phdr table to the same initial maps entry that supplied the ELF base address. Without
  // this check, a corrupted e_phoff could redirect the Phdr read into arbitrary readable memory
  // before load_start/load_end exist, letting attacker-controlled bytes define a fake
  // PT_LOAD/PT_DYNAMIC layout.
  if (!range_contains(base, map_end, phdr_table_addr, phdr_table_size)) return false;
  if (!safe_read(phdrs, phdr_table_addr, phdr_table_size)) return false;

  // ----- Phase 2: derive the DSO's mapped layout from PT_LOAD -----
  // PT_LOAD segments describe what parts of the ELF file are mapped into memory. PT_DYNAMIC
  // describes where the symbol-lookup metadata lives. This is the same information the linker
  // consumes in
  // bionic/linker/linker_phdr.cpp ElfReader::Read() and
  // bionic/linker/linker_phdr.cpp ElfReader::LoadSegments() when it builds the
  // mapping layout for a DSO.
  uintptr_t min_load_vaddr = UINTPTR_MAX;
  uintptr_t dynamic_vaddr = 0;
  size_t dynamic_size = 0;
  bool has_dynamic = false;
  for (int i = 0; i < ehdr.e_phnum; i++) {
    if (phdrs[i].p_type == PT_LOAD && phdrs[i].p_vaddr < min_load_vaddr) {
      min_load_vaddr = phdrs[i].p_vaddr;
    }
    if (phdrs[i].p_type == PT_DYNAMIC) {
      dynamic_vaddr = phdrs[i].p_vaddr;
      dynamic_size = phdrs[i].p_memsz;
      has_dynamic = true;
    }
  }
  if (min_load_vaddr == UINTPTR_MAX || !has_dynamic) return false;

  // Page-align the minimum PT_LOAD vaddr to match the linker's load_bias computation. The linker
  // (bionic/linker/linker_phdr.cpp phdr_table_get_load_size()) page-aligns
  // min_vaddr before computing
  //   load_bias = mmap_start - page_start(min_vaddr)
  // Our base is that mmap_start, the offset=0 maps entry, so elf_load_bias must also be
  // page-aligned for
  //   runtime = base + (file_vaddr - elf_load_bias)
  // to match.
  //
  // On arm64, PAGE_SIZE is not defined by bionic, so getpagesize() goes through page_size()'s
  //   static const size_t page_size = getauxval(AT_PAGESZ);
  // and first use goes through __cxa_guard_* for that function-local static. Theoretically,
  // __cxa_guard_* is not reentrant. In practice, getauxval() only scans the already-published auxv
  // array, so there is no realistic synchronous MTE-fault source there, and normal dynamically
  // linked processes hit this very early before vendor code runs.
  uintptr_t page_size = getpagesize();
  min_load_vaddr = min_load_vaddr & ~(page_size - 1);

  out->base = base;
  out->elf_load_bias = min_load_vaddr;
  out->load_start = UINTPTR_MAX;
  out->load_end = 0;
  out->code_start = UINTPTR_MAX;
  out->code_end = 0;
  out->exec_start = UINTPTR_MAX;
  out->exec_end = 0;

  // Convert each PT_LOAD segment from ELF virtual-address space into runtime address space, then
  // accumulate:
  //   load_* : total mapped coverage for this DSO
  //   exec_* : executable subset used for PC validation
  //   code_* : coarse PT_LOAD union kept for legacy logs/tests
  //
  // This is roughly the same translation the linker applies while turning ELF segment descriptors
  // into concrete memory ranges in
  // bionic/linker/linker_phdr.cpp ElfReader::LoadSegments().
  for (int i = 0; i < ehdr.e_phnum; i++) {
    if (phdrs[i].p_type != PT_LOAD) continue;
    if (phdrs[i].p_vaddr < min_load_vaddr) continue;
    uintptr_t seg_start;
    if (!elf_vaddr_to_runtime_addr(base, min_load_vaddr, phdrs[i].p_vaddr, &seg_start)) continue;
    uintptr_t seg_end;
    if (__builtin_add_overflow(seg_start, phdrs[i].p_memsz, &seg_end)) continue;
    if (seg_start < out->load_start) out->load_start = seg_start;
    if (seg_end > out->load_end) out->load_end = seg_end;
    if (seg_start < out->code_start) out->code_start = seg_start;
    if (seg_end > out->code_end) out->code_end = seg_end;
    if ((phdrs[i].p_flags & PF_X) != 0) {
      if (seg_start < out->exec_start) out->exec_start = seg_start;
      if (seg_end > out->exec_end) out->exec_end = seg_end;
    }
  }
  if (out->load_start >= out->load_end) return false;
  if (out->exec_start >= out->exec_end) return false;

  // ----- Phase 3: locate PT_DYNAMIC in runtime address space -----
  if (dynamic_vaddr < min_load_vaddr) return false;
  uintptr_t dynamic_runtime_addr;
  if (!elf_vaddr_to_runtime_addr(base, min_load_vaddr, dynamic_vaddr, &dynamic_runtime_addr)) {
    return false;
  }

  // ----- Phase 4: parse DT_* pointers out of PT_DYNAMIC -----
  // The linker records the same DT_* pointers during prelinking in
  // bionic/linker/linker.cpp soinfo::prelink_image(). We rebuild just the
  // pieces later consumed by bionic/linker/linker_soinfo.cpp soinfo::gnu_lookup() /
  // soinfo::elf_lookup() for exact symbol matching.
  bool ok = parse_dynamic(dynamic_runtime_addr, dynamic_size, base, min_load_vaddr, out);
  out->valid = ok;
  return ok;
}

// ---------------------------------------------------------------------------
// High-level: check if addr is inside a named function in a DSO.
// ---------------------------------------------------------------------------

// Check whether `addr` is inside a function with exact mangled name `func_name` in the given DSO.
// Uses hash-based O(1) lookup by exact name, matching how the dynamic linker resolves symbols. See:
// bionic/linker/linker_soinfo.cpp soinfo::gnu_lookup() and soinfo::elf_lookup().
//
// Prefers DT_GNU_HASH when present and falls back to DT_HASH (SYSV). At least one hash table is
// always present: the dynamic linker refuses to load DSOs with neither (bionic/linker/linker.cpp
// soinfo::prelink_image()). The hash style is set at link time via lld's --hash-style flag. On
// arm64, lld defaults to --hash-style=gnu, meaning DT_GNU_HASH only. Bionic applies
// --hash-style=both only for 32-bit targets (arm, x86), so vendor DSOs on arm64 typically have only
// DT_GNU_HASH unless explicitly linked with --hash-style=both.
inline bool func_matches(uintptr_t addr, const DsoInfo* dso, const char* func_name) {
  if (!dso->valid) return false;
  if (dso->exec_start >= dso->exec_end) return false;
  if (addr < dso->exec_start || addr >= dso->exec_end) return false;

  if (!dso->symtab_addr || !dso->strtab_addr) {
    async_safe_format_log(ANDROID_LOG_WARN, "libc",
                          "mte_suppress: func_matches addr=%p, no symtab/strtab",
                          reinterpret_cast<void*>(addr));
    return false;
  }

  // Convert the runtime address to the file virtual address used by st_value. ASLR randomizes the
  // DSO base on each process start, so subtract base to get a stable offset and then add
  // elf_load_bias to match ELF symbol-table addresses.
  //   file_vaddr = (addr - base) + elf_load_bias
  if (addr < dso->base) return false;
  uintptr_t file_vaddr;
  if (__builtin_add_overflow(addr - dso->base, dso->elf_load_bias, &file_vaddr)) return false;

  // Hash-based lookup: O(1) average by exact symbol name. Uses DT_GNU_HASH (preferred) or DT_HASH
  // (SYSV fallback).
  Elf64_Sym sym;
  bool found = false;
  if (dso->gnu_hash_addr) {
    found = gnu_hash_lookup(dso, func_name, &sym);
  } else if (dso->hash_addr) {
    found = elf_hash_lookup(dso, func_name, &sym);
  } else {
    async_safe_format_log(ANDROID_LOG_WARN, "libc",
                          "mte_suppress: func_matches addr=%p, no hash tables",
                          reinterpret_cast<void*>(addr));
    return false;
  }

  if (!found) {
    async_safe_format_log(
        ANDROID_LOG_WARN, "libc",
        "mte_suppress: hash lookup miss for '%s' file_vaddr=%p gnu_hash=%p hash=%p", func_name,
        reinterpret_cast<void*>(file_vaddr), reinterpret_cast<void*>(dso->gnu_hash_addr),
        reinterpret_cast<void*>(dso->hash_addr));
    return false;
  }

  bool type_ok = ELF64_ST_TYPE(sym.st_info) == STT_FUNC && sym.st_shndx != SHN_UNDEF;
  uintptr_t sym_end;
  if (__builtin_add_overflow(sym.st_value, sym.st_size, &sym_end)) return false;
  bool addr_ok = file_vaddr >= sym.st_value && file_vaddr < sym_end;

  async_safe_format_log(
      ANDROID_LOG_WARN, "libc",
      "mte_suppress: hash lookup '%s' [%p+%p) type=%d addr=%d gnu_hash=%p hash=%p", func_name,
      reinterpret_cast<void*>(sym.st_value), reinterpret_cast<void*>(sym.st_size), type_ok, addr_ok,
      reinterpret_cast<void*>(dso->gnu_hash_addr), reinterpret_cast<void*>(dso->hash_addr));

  return type_ok && addr_ok;
}

}  // namespace mte_suppression
