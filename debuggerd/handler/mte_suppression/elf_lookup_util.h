// Pure ELF helper functions for MTE crash suppression. This file keeps arithmetic-only ELF helpers
// separate from the signal-handler and mapped-memory readers so they can be unit-tested on device
// without process_vm_readv dependencies.

#pragma once

#include <elf.h>
#include <stdint.h>
#include <string.h>

namespace mte_suppression {

// A typical DSO has 7-10 program headers (PT_PHDR, PT_LOAD x2-3, PT_DYNAMIC, PT_NOTE, PT_GNU_STACK,
// PT_GNU_RELRO). Cap at 64 to bound stack usage (64 * sizeof(Elf64_Phdr) = 3.5 KiB) while staying
// well above any real-world value.
inline constexpr size_t kMaxPhdrs = 64;

// bionic/linker/linker_relocate.h:is_symbol_global_and_defined.
// Returns true if the symbol has global or weak binding and is defined (not an import).
inline bool is_symbol_global_and_defined(const Elf64_Sym* s) {
  if (ELF64_ST_BIND(s->st_info) == STB_GLOBAL || ELF64_ST_BIND(s->st_info) == STB_WEAK) {
    return s->st_shndx != SHN_UNDEF;
  }
  return false;
}

// Compute the GNU hash of a symbol name using the same scalar algorithm as bionic's dynamic linker
// (bionic/linker/linker_gnu_hash.h:calculate_gnu_hash_simple). The linker also
// has a NEON-optimized variant, but this helper intentionally keeps the simple portable form.
inline uint32_t gnu_hash_calc(const char* name) {
  uint32_t h = 5381;
  const uint8_t* name_bytes = reinterpret_cast<const uint8_t*>(name);
#pragma unroll 8
  while (*name_bytes != 0) {
    h += (h << 5) + *name_bytes++;  // h*33 + c = h + h * 32 + c = h + h << 5 + c
  }
  return h;
}

// Compute the SYSV ELF hash of a symbol name. Standard algorithm from the System V ABI
// specification, same as bionic's linker (bionic/linker/linker_soinfo.h:SymbolName::elf_hash).
inline uint32_t elf_hash_calc(const char* name) {
  const uint8_t* name_bytes = reinterpret_cast<const uint8_t*>(name);
  uint32_t h = 0, g;

  while (*name_bytes) {
    h = (h << 4) + *name_bytes++;
    g = h & 0xf0000000;
    h ^= g;
    h ^= g >> 24;
  }

  return h;
}

// Validate ELF header fields. Matches
// bionic/linker/linker_phdr.cpp ElfReader::VerifyElfHeader(). We hardcode
// Elf64_* types throughout, so reject anything that is not a 64-bit little-endian shared object for
// AArch64.
//
// libunwindstack (Elf.cpp) only checks ELFMAG, EI_CLASS, and e_machine.
inline bool verify_elf_header(const Elf64_Ehdr& ehdr) {
  if (memcmp(ehdr.e_ident, ELFMAG, SELFMAG) != 0) return false;
  if (ehdr.e_ident[EI_CLASS] != ELFCLASS64) return false;
  if (ehdr.e_ident[EI_DATA] != ELFDATA2LSB) return false;
  if (ehdr.e_type != ET_DYN) return false;
  if (ehdr.e_version != EV_CURRENT) return false;
  // This handler is __aarch64__ only (MTE is an ARMv8.5-A feature).
  if (ehdr.e_machine != EM_AARCH64) return false;
  if (ehdr.e_phentsize != sizeof(Elf64_Phdr)) return false;
  if (ehdr.e_phnum == 0 || ehdr.e_phnum > kMaxPhdrs) return false;
  return true;
}

}  // namespace mte_suppression
