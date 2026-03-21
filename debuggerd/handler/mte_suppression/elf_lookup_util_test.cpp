// Unit tests for the pure ELF helper functions in elf_lookup_util.h. These run on aarch64 devices
// because verify_elf_header() checks EM_AARCH64.

#include "elf_lookup_util.h"

#include <gtest/gtest.h>

// Cross-check against bionic's canonical implementation in
// bionic/linker/linker_gnu_hash.h:calculate_gnu_hash_simple.
#include "linker_gnu_hash.h"

using namespace mte_suppression;

// ===== gnu_hash_calc tests =====

TEST(GnuHashCalc, EmptyString) {
  EXPECT_EQ(gnu_hash_calc(""), 5381u);
}

TEST(GnuHashCalc, MatchesBionic) {
  // Cross-check our implementation against bionic's calculate_gnu_hash_simple().
  const char* symbols[] = {
      "printf",
      "main",
      "A",
      "_ZN6vendor8graphics23VendorGraphicBufferMeta4initEPK13native_handle",
      "_ZN11ExynosLayer10printLayerEv",
      "_ZN13ExynosDisplay15printDebugInfosERN7android7String8E",
      "",
  };
  for (const char* sym : symbols) {
    auto [bionic_hash, bionic_len] = calculate_gnu_hash_simple(sym);
    EXPECT_EQ(gnu_hash_calc(sym), bionic_hash) << "mismatch for symbol: " << sym;
  }
}

TEST(GnuHashCalc, SingleChar) {
  // h = 5381 + (5381 << 5) + 'A' = 5381 + 172192 + 65 = 177638
  EXPECT_EQ(gnu_hash_calc("A"), 177638u);
}

TEST(GnuHashCalc, DifferentSymbolsDiffer) {
  EXPECT_NE(gnu_hash_calc("printf"), gnu_hash_calc("main"));
}

// ===== elf_hash_calc tests =====

TEST(ElfHashCalc, EmptyString) {
  EXPECT_EQ(elf_hash_calc(""), 0u);
}

TEST(ElfHashCalc, SingleChar) {
  // h = (0 << 4) + 'A' = 65 g = 65 & 0xf0000000 = 0 h ^= 0; h ^= 0; -> h = 65
  EXPECT_EQ(elf_hash_calc("A"), 65u);
}

TEST(ElfHashCalc, HighBitsMasked) {
  // The SysV hash uses h & 0xf0000000 to clear high bits, so the result should never have the top 4
  // bits set.
  EXPECT_EQ(elf_hash_calc("printf") & 0xf0000000, 0u);
  EXPECT_EQ(elf_hash_calc("_ZN6vendor8graphics23VendorGraphicBufferMeta4initEPK13native_handle") &
                0xf0000000,
            0u);
}

// ===== is_symbol_global_and_defined tests =====

static Elf64_Sym make_sym(unsigned char bind, unsigned char type, uint16_t shndx) {
  Elf64_Sym s = {};
  s.st_info = ELF64_ST_INFO(bind, type);
  s.st_shndx = shndx;
  return s;
}

TEST(IsSymbolGlobalAndDefined, GlobalDefined) {
  Elf64_Sym s = make_sym(STB_GLOBAL, STT_FUNC, 1);
  EXPECT_TRUE(is_symbol_global_and_defined(&s));
}

TEST(IsSymbolGlobalAndDefined, GlobalUndef) {
  Elf64_Sym s = make_sym(STB_GLOBAL, STT_FUNC, SHN_UNDEF);
  EXPECT_FALSE(is_symbol_global_and_defined(&s));
}

TEST(IsSymbolGlobalAndDefined, WeakDefined) {
  Elf64_Sym s = make_sym(STB_WEAK, STT_FUNC, 1);
  EXPECT_TRUE(is_symbol_global_and_defined(&s));
}

TEST(IsSymbolGlobalAndDefined, WeakUndef) {
  Elf64_Sym s = make_sym(STB_WEAK, STT_FUNC, SHN_UNDEF);
  EXPECT_FALSE(is_symbol_global_and_defined(&s));
}

TEST(IsSymbolGlobalAndDefined, LocalDefined) {
  Elf64_Sym s = make_sym(STB_LOCAL, STT_FUNC, 1);
  EXPECT_FALSE(is_symbol_global_and_defined(&s));
}

TEST(IsSymbolGlobalAndDefined, LocalUndef) {
  Elf64_Sym s = make_sym(STB_LOCAL, STT_FUNC, SHN_UNDEF);
  EXPECT_FALSE(is_symbol_global_and_defined(&s));
}

TEST(IsSymbolGlobalAndDefined, GlobalObject) {
  // Non-FUNC type should still return true. The helper checks binding/shndx, not symbol type.
  Elf64_Sym s = make_sym(STB_GLOBAL, STT_OBJECT, 1);
  EXPECT_TRUE(is_symbol_global_and_defined(&s));
}

TEST(IsSymbolGlobalAndDefined, GlobalCommon) {
  // SHN_COMMON is defined (not SHN_UNDEF).
  Elf64_Sym s = make_sym(STB_GLOBAL, STT_OBJECT, SHN_COMMON);
  EXPECT_TRUE(is_symbol_global_and_defined(&s));
}

TEST(IsSymbolGlobalAndDefined, GlobalAbs) {
  Elf64_Sym s = make_sym(STB_GLOBAL, STT_OBJECT, SHN_ABS);
  EXPECT_TRUE(is_symbol_global_and_defined(&s));
}

// ===== verify_elf_header tests =====

// Build a valid AArch64 shared-object ELF header.
static Elf64_Ehdr make_valid_ehdr() {
  Elf64_Ehdr ehdr = {};
  memcpy(ehdr.e_ident, ELFMAG, SELFMAG);
  ehdr.e_ident[EI_CLASS] = ELFCLASS64;
  ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr.e_type = ET_DYN;
  ehdr.e_version = EV_CURRENT;
  ehdr.e_machine = EM_AARCH64;
  ehdr.e_phentsize = sizeof(Elf64_Phdr);
  ehdr.e_phnum = 4;
  return ehdr;
}

TEST(VerifyElfHeader, Valid) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  EXPECT_TRUE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, BadMagic) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_ident[0] = 0x00;
  EXPECT_FALSE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, Class32) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_ident[EI_CLASS] = ELFCLASS32;
  EXPECT_FALSE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, BigEndian) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_ident[EI_DATA] = ELFDATA2MSB;
  EXPECT_FALSE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, TypeExec) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_type = ET_EXEC;
  EXPECT_FALSE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, TypeRel) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_type = ET_REL;
  EXPECT_FALSE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, WrongVersion) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_version = EV_NONE;
  EXPECT_FALSE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, MachineX86) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_machine = EM_X86_64;
  EXPECT_FALSE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, MachineArm32) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_machine = EM_ARM;
  EXPECT_FALSE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, WrongPhentsize) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_phentsize = sizeof(Elf64_Phdr) - 1;
  EXPECT_FALSE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, ZeroPhnum) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_phnum = 0;
  EXPECT_FALSE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, ExcessivePhnum) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_phnum = static_cast<decltype(ehdr.e_phnum)>(kMaxPhdrs + 1);
  EXPECT_FALSE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, MaxPhnum) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_phnum = static_cast<decltype(ehdr.e_phnum)>(kMaxPhdrs);
  EXPECT_TRUE(verify_elf_header(ehdr));
}

TEST(VerifyElfHeader, OnePhnum) {
  Elf64_Ehdr ehdr = make_valid_ehdr();
  ehdr.e_phnum = 1;
  EXPECT_TRUE(verify_elf_header(ehdr));
}
