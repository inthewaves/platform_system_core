// Device tests for safe_read(), parse_dso_elf(), gnu_hash_lookup(), elf_hash_lookup(), and
// func_matches() against real loaded DSOs. Requires an aarch64 device.

#include "dso_lookup_util.h"
#include "maps_util.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <link.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace mte_suppression;

// Load libdso_test_hash_helper.so from the same directory as the test binary. data_libs deploys it
// alongside the test. We dlopen it so it appears in /proc/self/maps for parse_dso_elf() and
// elf_hash_lookup() testing.
static void* g_hash_helper_handle = nullptr;

static std::string get_test_lib_dir() {
  char self[PATH_MAX];
  ssize_t len = readlink("/proc/self/exe", self, sizeof(self) - 1);
  if (len <= 0) return ".";
  self[len] = '\0';
  return dirname(self);
}

static void load_hash_helper() {
  if (g_hash_helper_handle) return;
  std::string path = get_test_lib_dir() + "/libdso_test_hash_helper.so";
  g_hash_helper_handle = dlopen(path.c_str(), RTLD_NOW);
  if (!g_hash_helper_handle) {
    // Fallback: try without path in case LD_LIBRARY_PATH is set.
    g_hash_helper_handle = dlopen("libdso_test_hash_helper.so", RTLD_NOW);
  }
}

static bool copy_file(const std::string& src, const std::string& dst) {
  int src_fd = open(src.c_str(), O_RDONLY | O_CLOEXEC);
  if (src_fd < 0) return false;
  int dst_fd = open(dst.c_str(), O_CREAT | O_WRONLY | O_TRUNC | O_CLOEXEC, 0644);
  if (dst_fd < 0) {
    close(src_fd);
    return false;
  }

  char buf[4096];
  bool ok = true;
  for (;;) {
    ssize_t n = read(src_fd, buf, sizeof(buf));
    if (n == 0) break;
    if (n < 0) {
      ok = false;
      break;
    }
    size_t written = 0;
    while (written < static_cast<size_t>(n)) {
      ssize_t w =
          TEMP_FAILURE_RETRY(write(dst_fd, buf + written, static_cast<size_t>(n) - written));
      if (w <= 0) {
        ok = false;
        break;
      }
      written += static_cast<size_t>(w);
    }
    if (!ok) break;
  }

  close(src_fd);
  close(dst_fd);
  return ok;
}

static void init_synthetic_lookup_dso(DsoInfo* dso, uintptr_t base, size_t size) {
  *dso = {};
  dso->base = base;
  dso->load_start = base;
  dso->load_end = base + size;
  dso->code_start = base;
  dso->code_end = base + size;
}

static Elf64_Sym make_global_func_sym(uint32_t name_offset, uintptr_t value, size_t size) {
  Elf64_Sym sym{};
  sym.st_name = name_offset;
  sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
  sym.st_shndx = 1;
  sym.st_value = value;
  sym.st_size = size;
  return sym;
}

// ===== safe_read tests =====

TEST(SafeRead, ReadStackVariable) {
  uint64_t val = 0xDEADBEEFCAFEBABEULL;
  uint64_t out = 0;
  EXPECT_TRUE(safe_read(&out, reinterpret_cast<uintptr_t>(&val), sizeof(val)));
  EXPECT_EQ(out, 0xDEADBEEFCAFEBABEULL);
}

TEST(SafeRead, ReadUnmappedFails) {
  uint64_t out = 0;
  // Address 0x1000 is almost certainly not mapped.
  EXPECT_FALSE(safe_read(&out, 0x1000, sizeof(out)));
}

TEST(SafeRead, ReadNullFails) {
  uint64_t out = 0;
  EXPECT_FALSE(safe_read(&out, 0, sizeof(out)));
}

TEST(SafeRead, PartialReadFails) {
  // Allocate a page-aligned buffer via mmap(), then unmap the second page. Reading across the
  // boundary should fail.
  size_t page_size = getpagesize();
  void* mem =
      mmap(nullptr, page_size * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED);
  // Unmap the second page.
  munmap(static_cast<char*>(mem) + page_size, page_size);
  // Try to read 16 bytes starting 8 bytes before the page boundary.
  uint8_t buf[16];
  uintptr_t addr = reinterpret_cast<uintptr_t>(mem) + page_size - 8;
  EXPECT_FALSE(safe_read(buf, addr, 16));
  munmap(mem, page_size);
}

// ===== safe_read_at tests =====

TEST(SafeReadAt, ReadArrayElement) {
  uint32_t arr[] = {10, 20, 30, 40};
  uint32_t out = 0;
  EXPECT_TRUE(safe_read_at(&out, reinterpret_cast<uintptr_t>(arr), 2));
  EXPECT_EQ(out, 30u);
}

TEST(SafeReadAt, OverflowIndexFails) {
  uint64_t out = 0;
  // Huge index should trigger mul_overflow or add_overflow.
  EXPECT_FALSE(safe_read_at(&out, 0x7FFFFFFFFFFFF000ULL, 0x7FFFFFFFFFFFF000ULL));
}

// ===== Helper: find DSO mapping from /proc/self/maps =====

static MapsEntry find_dso_mapping(const char* dso_name) {
  MapsEntry result{};
  int fd = open("/proc/self/maps", O_RDONLY | O_CLOEXEC);
  EXPECT_GE(fd, 0) << "open /proc/self/maps: " << strerror(errno);
  if (fd < 0) return result;

  for_each_line_from_fd(fd, [&](const char* line) -> bool {
    MapsEntry entry{};
    if (!parse_maps_line(line, &entry) || entry.offset != 0 || entry.name[0] != '/') return true;

    const char* basename = strrchr(entry.name, '/');
    basename = basename ? basename + 1 : entry.name;

    if (strcmp(basename, dso_name) == 0) {
      result = entry;
      return false;  // Stop.
    }
    return true;
  });
  EXPECT_EQ(close(fd), 0) << "close /proc/self/maps: " << strerror(errno);
  return result;
}

// ===== parse_dso_elf tests =====

TEST(ParseDsoElf, LibcResolves) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u) << "Could not find libc.so in /proc/self/maps";

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));

  // Basic sanity: code range should bracket the base address.
  EXPECT_LE(dso.code_start, mapping.start);
  EXPECT_GT(dso.code_end, mapping.start);
  // Must have symtab, strtab, and at least one hash table.
  EXPECT_NE(dso.symtab_addr, 0u);
  EXPECT_NE(dso.strtab_addr, 0u);
  EXPECT_NE(dso.gnu_hash_addr, 0u);  // bionic libc always has DT_GNU_HASH.
  EXPECT_EQ(dso.base, mapping.start);
  EXPECT_EQ(dso.elf_load_bias, 0u);  // libc.so has min_vaddr == 0.
}

TEST(ParseDsoElf, InvalidBaseFails) {
  DsoInfo dso{};
  // Unmapped address should fail safely.
  EXPECT_FALSE(parse_dso_elf(0x1000, 0x2000, &dso));
}

TEST(ParseDsoElf, LibcSoname) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u) << "Could not find libc.so in /proc/self/maps";

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));

  // parse_dynamic extracts DT_SONAME from the dynamic string table, mirroring
  // ElfInterface::ReadSoname() in libunwindstack (ElfInterface.cpp:434).
  EXPECT_STREQ(dso.soname, "libc.so");
}

TEST(ParseDsoElf, HelperSoname) {
  load_hash_helper();
  ASSERT_NE(g_hash_helper_handle, nullptr) << "Failed to dlopen libdso_test_hash_helper.so";

  MapsEntry mapping = find_dso_mapping("libdso_test_hash_helper.so");
  ASSERT_NE(mapping.start, 0u) << "Could not find libdso_test_hash_helper.so in /proc/self/maps";

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));
  EXPECT_STREQ(dso.soname, "libdso_test_hash_helper.so");
}

TEST(ParseDsoElf, PhdrTableOutsideInitialMapFails) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);

  auto* ehdr = static_cast<Elf64_Ehdr*>(mem);
  memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
  ehdr->e_ident[EI_CLASS] = ELFCLASS64;
  ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr->e_type = ET_DYN;
  ehdr->e_version = EV_CURRENT;
  ehdr->e_machine = EM_AARCH64;
  ehdr->e_phentsize = sizeof(Elf64_Phdr);
  ehdr->e_phnum = 1;
  ehdr->e_phoff = 0x80;

  DsoInfo dso{};
  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  EXPECT_FALSE(parse_dso_elf(base, base + 0x80, &dso));

  munmap(mem, page_size);
}

// Copied and adapted from
// system/unwinding/libunwindstack/tests/ElfInterfaceTest.cpp,
// ElfInterfaceTest.get_load_bias_non_zero_32 and ElfInterfaceTest.get_load_bias_non_zero_64.
// Verifies that parse_dso_elf() handles a non-zero minimum PT_LOAD p_vaddr and translates runtime
// addresses using the aligned non-zero load bias.
TEST(ParseDsoElf, SyntheticNonZeroLoadBias) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  void* mem =
      mmap(nullptr, page_size * 2, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);
  memset(mem, 0, page_size * 2);

  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  auto* ehdr = static_cast<Elf64_Ehdr*>(mem);
  memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
  ehdr->e_ident[EI_CLASS] = ELFCLASS64;
  ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr->e_type = ET_DYN;
  ehdr->e_version = EV_CURRENT;
  ehdr->e_machine = EM_AARCH64;
  ehdr->e_phentsize = sizeof(Elf64_Phdr);
  ehdr->e_phnum = 3;
  ehdr->e_phoff = sizeof(Elf64_Ehdr);

  auto* phdrs = reinterpret_cast<Elf64_Phdr*>(static_cast<char*>(mem) + sizeof(Elf64_Ehdr));
  phdrs[0].p_type = PT_LOAD;
  phdrs[0].p_vaddr = 0x3000;
  phdrs[0].p_memsz = 0x800;
  phdrs[0].p_flags = PF_R;

  phdrs[1].p_type = PT_LOAD;
  phdrs[1].p_vaddr = 0x4000;
  phdrs[1].p_memsz = 0x200;
  phdrs[1].p_flags = PF_R | PF_X;

  phdrs[2].p_type = PT_DYNAMIC;
  phdrs[2].p_vaddr = 0x3180;
  phdrs[2].p_memsz = 6 * sizeof(Elf64_Dyn);

  // Keep PT_DYNAMIC separate from the Phdr table. parse_dso_elf() bootstraps from the program
  // headers first, so this synthetic image must not let the dynamic entries overwrite them.
  auto* dyn = reinterpret_cast<Elf64_Dyn*>(static_cast<char*>(mem) + 0x180);
  dyn[0].d_tag = DT_SYMTAB;
  dyn[0].d_un.d_ptr = 0x3300;
  dyn[1].d_tag = DT_STRTAB;
  dyn[1].d_un.d_ptr = 0x3200;
  dyn[2].d_tag = DT_STRSZ;
  dyn[2].d_un.d_val = 0x40;
  dyn[3].d_tag = DT_GNU_HASH;
  dyn[3].d_un.d_ptr = 0x3400;
  dyn[4].d_tag = DT_SONAME;
  dyn[4].d_un.d_val = 1;
  dyn[5].d_tag = DT_NULL;
  dyn[5].d_un.d_val = 0;

  char* strtab = static_cast<char*>(mem) + 0x200;
  strtab[0] = '\0';
  strcpy(strtab + 1, "libsynthetic.so");

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(base, base + page_size * 2, &dso));
  EXPECT_EQ(dso.elf_load_bias, 0x3000u);
  EXPECT_EQ(dso.load_start, base);
  EXPECT_EQ(dso.load_end, base + 0x1200);
  EXPECT_EQ(dso.exec_start, base + 0x1000);
  EXPECT_EQ(dso.exec_end, base + 0x1200);
  EXPECT_EQ(dso.strtab_addr, base + 0x200);
  EXPECT_EQ(dso.symtab_addr, base + 0x300);
  EXPECT_EQ(dso.gnu_hash_addr, base + 0x400);
  EXPECT_STREQ(dso.soname, "libsynthetic.so");

  munmap(mem, page_size * 2);
}

// Copied and adapted from
// system/unwinding/libunwindstack/tests/MapInfoGetElfTest.cpp,
// MapInfoGetElfTest.file_backed_non_zero_offset_full_file and related non-zero-offset cases.
// Verifies that parse_dso_elf() works when the ELF bytes are mapped from a file at a non-zero file
// offset.
TEST(ParseDsoElf, NonZeroFileOffsetMappingResolves) {
  load_hash_helper();
  ASSERT_NE(g_hash_helper_handle, nullptr) << "Failed to dlopen libdso_test_hash_helper.so";

  std::string src_path = get_test_lib_dir() + "/libdso_test_hash_helper.so";
  char tmp_template[] = "/data/local/tmp/mte_suppression_parse.XXXXXX";
  char* tmp_dir = mkdtemp(tmp_template);
  ASSERT_NE(tmp_dir, nullptr) << strerror(errno);

  std::string payload_path = std::string(tmp_dir) + "/payload.so";
  ASSERT_TRUE(copy_file(src_path, payload_path)) << "Failed to copy helper DSO";

  int payload_fd = open(payload_path.c_str(), O_RDONLY | O_CLOEXEC);
  ASSERT_GE(payload_fd, 0) << strerror(errno);
  off_t payload_size = lseek(payload_fd, 0, SEEK_END);
  ASSERT_GT(payload_size, 0);
  close(payload_fd);

  std::string apk_path = std::string(tmp_dir) + "/embedded.apk";
  int apk_fd = open(apk_path.c_str(), O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644);
  ASSERT_GE(apk_fd, 0) << strerror(errno);

  const size_t page_size = static_cast<size_t>(getpagesize());
  std::vector<char> zeroes(page_size, 0);
  ASSERT_EQ(static_cast<ssize_t>(page_size),
            TEMP_FAILURE_RETRY(write(apk_fd, zeroes.data(), zeroes.size())));

  payload_fd = open(payload_path.c_str(), O_RDONLY | O_CLOEXEC);
  ASSERT_GE(payload_fd, 0) << strerror(errno);
  char buf[4096];
  for (;;) {
    ssize_t n = read(payload_fd, buf, sizeof(buf));
    ASSERT_GE(n, 0) << strerror(errno);
    if (n == 0) break;
    size_t written = 0;
    while (written < static_cast<size_t>(n)) {
      ssize_t w =
          TEMP_FAILURE_RETRY(write(apk_fd, buf + written, static_cast<size_t>(n) - written));
      ASSERT_GT(w, 0) << strerror(errno);
      written += static_cast<size_t>(w);
    }
  }
  close(payload_fd);

  void* mapping = mmap(nullptr, static_cast<size_t>(payload_size), PROT_READ, MAP_PRIVATE, apk_fd,
                       static_cast<off_t>(page_size));
  close(apk_fd);
  ASSERT_NE(mapping, MAP_FAILED) << strerror(errno);

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(
      reinterpret_cast<uintptr_t>(mapping),
      reinterpret_cast<uintptr_t>(mapping) + static_cast<size_t>(payload_size), &dso));
  EXPECT_STREQ(dso.soname, "libdso_test_hash_helper.so");
  EXPECT_NE(dso.gnu_hash_addr, 0u);
  EXPECT_NE(dso.symtab_addr, 0u);
  EXPECT_NE(dso.strtab_addr, 0u);

  munmap(mapping, static_cast<size_t>(payload_size));
  unlink(payload_path.c_str());
  unlink(apk_path.c_str());
  rmdir(tmp_dir);
}

TEST(ParseDynamic, SonameOutsideStrtabIsRejected) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);

  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  auto* dyn = static_cast<Elf64_Dyn*>(mem);
  strcpy(reinterpret_cast<char*>(base + 0x100), "libfake.so");

  dyn[0].d_tag = DT_SYMTAB;
  dyn[0].d_un.d_ptr = 0x200;
  dyn[1].d_tag = DT_STRTAB;
  dyn[1].d_un.d_ptr = 0x100;
  dyn[2].d_tag = DT_STRSZ;
  dyn[2].d_un.d_val = 4;
  dyn[3].d_tag = DT_GNU_HASH;
  dyn[3].d_un.d_ptr = 0x300;
  dyn[4].d_tag = DT_SONAME;
  dyn[4].d_un.d_val = 8;
  dyn[5].d_tag = DT_NULL;
  dyn[5].d_un.d_val = 0;

  DsoInfo dso{};
  dso.load_start = base;
  dso.load_end = base + page_size;
  ASSERT_TRUE(parse_dynamic(base, 6 * sizeof(Elf64_Dyn), base, 0, &dso));
  EXPECT_EQ(dso.symtab_addr, base + 0x200);
  EXPECT_EQ(dso.strtab_addr, base + 0x100);
  EXPECT_EQ(dso.gnu_hash_addr, base + 0x300);
  EXPECT_STREQ(dso.soname, "");

  munmap(mem, page_size);
}

// Copied and adapted from
// system/unwinding/libunwindstack/tests/ElfInterfaceTest.cpp,
// ElfInterfaceTest.soname_after_dt_null_64. Verifies that parse_dynamic() stops at DT_NULL and
// ignores any later DT_SONAME entry.
TEST(ParseDynamic, SonameAfterDtNullIsIgnored) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);

  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  auto* dyn = static_cast<Elf64_Dyn*>(mem);
  strcpy(reinterpret_cast<char*>(base + 0x100), "libfake.so");

  dyn[0].d_tag = DT_SYMTAB;
  dyn[0].d_un.d_ptr = 0x200;
  dyn[1].d_tag = DT_STRTAB;
  dyn[1].d_un.d_ptr = 0x100;
  dyn[2].d_tag = DT_STRSZ;
  dyn[2].d_un.d_val = 0x20;
  dyn[3].d_tag = DT_GNU_HASH;
  dyn[3].d_un.d_ptr = 0x300;
  dyn[4].d_tag = DT_NULL;
  dyn[4].d_un.d_val = 0;
  dyn[5].d_tag = DT_SONAME;
  dyn[5].d_un.d_val = 1;
  dyn[6].d_tag = DT_NULL;
  dyn[6].d_un.d_val = 0;

  DsoInfo dso{};
  dso.load_start = base;
  dso.load_end = base + page_size;
  ASSERT_TRUE(parse_dynamic(base, 7 * sizeof(Elf64_Dyn), base, 0, &dso));
  EXPECT_EQ(dso.symtab_addr, base + 0x200);
  EXPECT_EQ(dso.strtab_addr, base + 0x100);
  EXPECT_EQ(dso.gnu_hash_addr, base + 0x300);
  EXPECT_STREQ(dso.soname, "");

  munmap(mem, page_size);
}

TEST(ParseDynamic, UnterminatedSonameIsRejected) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);

  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  auto* dyn = static_cast<Elf64_Dyn*>(mem);
  memcpy(reinterpret_cast<void*>(base + 0x100), "xabcdef", 7);

  dyn[0].d_tag = DT_SYMTAB;
  dyn[0].d_un.d_ptr = 0x200;
  dyn[1].d_tag = DT_STRTAB;
  dyn[1].d_un.d_ptr = 0x100;
  dyn[2].d_tag = DT_STRSZ;
  dyn[2].d_un.d_val = 7;
  dyn[3].d_tag = DT_GNU_HASH;
  dyn[3].d_un.d_ptr = 0x300;
  dyn[4].d_tag = DT_SONAME;
  dyn[4].d_un.d_val = 1;
  dyn[5].d_tag = DT_NULL;
  dyn[5].d_un.d_val = 0;

  DsoInfo dso{};
  dso.load_start = base;
  dso.load_end = base + page_size;
  ASSERT_TRUE(parse_dynamic(base, 6 * sizeof(Elf64_Dyn), base, 0, &dso));
  EXPECT_STREQ(dso.soname, "");

  munmap(mem, page_size);
}

TEST(ParseDynamic, StrtabOutsideLoadRangeIsRejected) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);

  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  auto* dyn = static_cast<Elf64_Dyn*>(mem);

  dyn[0].d_tag = DT_SYMTAB;
  dyn[0].d_un.d_ptr = 0x80;
  dyn[1].d_tag = DT_STRTAB;
  dyn[1].d_un.d_ptr = 0x180;
  dyn[2].d_tag = DT_STRSZ;
  dyn[2].d_un.d_val = 0x40;
  dyn[3].d_tag = DT_GNU_HASH;
  dyn[3].d_un.d_ptr = 0x100;
  dyn[4].d_tag = DT_NULL;
  dyn[4].d_un.d_val = 0;

  DsoInfo dso{};
  dso.load_start = base;
  dso.load_end = base + 0x1A0;
  EXPECT_FALSE(parse_dynamic(base, 5 * sizeof(Elf64_Dyn), base, 0, &dso));

  munmap(mem, page_size);
}

TEST(ParseDsoElf, CodeRangeBracketsKnownSymbol) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u);

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));

  // atoi is a regular STT_FUNC in libc.so (not an IFUNC like strlen/memcpy).
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  ASSERT_NE(atoi_addr, nullptr);
  uintptr_t atoi_rt = reinterpret_cast<uintptr_t>(atoi_addr);
  EXPECT_GE(atoi_rt, dso.code_start);
  EXPECT_LT(atoi_rt, dso.code_end);
}

// ===== gnu_hash_lookup tests =====

TEST(GnuHashLookup, FindAtoiInLibc) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u);

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));
  ASSERT_NE(dso.gnu_hash_addr, 0u);

  // Use atoi, a regular STT_FUNC, not an IFUNC like strlen/memcpy on aarch64.
  Elf64_Sym sym{};
  ASSERT_TRUE(gnu_hash_lookup(&dso, "atoi", &sym));

  EXPECT_EQ(ELF64_ST_TYPE(sym.st_info), (unsigned)STT_FUNC);
  EXPECT_NE(sym.st_shndx, (unsigned)SHN_UNDEF);
  EXPECT_GT(sym.st_size, 0u);

  // Cross-check: dlsym() resolves IFUNCs to the selected target, but for regular functions it
  // returns base + (st_value - elf_load_bias).
  void* dlsym_addr = dlsym(RTLD_DEFAULT, "atoi");
  ASSERT_NE(dlsym_addr, nullptr);
  uintptr_t dlsym_rt = reinterpret_cast<uintptr_t>(dlsym_addr);
  uintptr_t sym_rt = mapping.start + sym.st_value - dso.elf_load_bias;
  EXPECT_EQ(dlsym_rt, sym_rt);
}

TEST(GnuHashLookup, NonexistentSymbolFails) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u);

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));

  Elf64_Sym sym{};
  EXPECT_FALSE(gnu_hash_lookup(&dso, "__this_symbol_does_not_exist_at_all__", &sym));
}

TEST(GnuHashLookup, MultipleSymbols) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u);

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));

  // Look up several known libc symbols.
  const char* symbols[] = {"strlen", "memcpy", "open", "close", "write"};
  for (const char* name : symbols) {
    Elf64_Sym sym{};
    EXPECT_TRUE(gnu_hash_lookup(&dso, name, &sym)) << "Failed to find symbol: " << name;
    EXPECT_GT(sym.st_size, 0u) << "Zero size for symbol: " << name;
  }
}

TEST(GnuHashLookup, BucketCollisionFindsLaterSymbol) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);
  memset(mem, 0, page_size);

  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  DsoInfo dso{};
  init_synthetic_lookup_dso(&dso, base, page_size);
  dso.symtab_addr = base + 0x100;
  dso.strtab_addr = base + 0x200;
  dso.gnu_hash_addr = base + 0x300;

  auto* symtab = reinterpret_cast<Elf64_Sym*>(static_cast<char*>(mem) + 0x100);
  char* strtab = static_cast<char*>(mem) + 0x200;
  uint32_t header[4] = {1, 1, 1, 0};
  memcpy(static_cast<char*>(mem) + 0x300, header, sizeof(header));

  // Force both symbols into the same bucket by using nbuckets == 1. The first chain entry names a
  // different symbol; the lookup must keep walking until it reaches the later matching symbol.
  strtab[0] = '\0';
  strcpy(strtab + 1, "first");
  const uint32_t target_name_off = 1 + strlen("first") + 1;
  strcpy(strtab + target_name_off, "target");
  symtab[1] = make_global_func_sym(1, 0x1000, 0x20);
  symtab[2] = make_global_func_sym(target_name_off, 0x1100, 0x20);

  auto* bloom = reinterpret_cast<uintptr_t*>(static_cast<char*>(mem) + 0x300 + sizeof(header));
  bloom[0] = ~uintptr_t{0};
  auto* buckets = reinterpret_cast<uint32_t*>(bloom + 1);
  buckets[0] = 1;
  auto* chains = buckets + 1;
  chains[0] = gnu_hash_calc("first") & ~1u;
  chains[1] = gnu_hash_calc("target") | 1u;

  Elf64_Sym sym{};
  ASSERT_TRUE(gnu_hash_lookup(&dso, "target", &sym));
  EXPECT_EQ(sym.st_name, target_name_off);
  EXPECT_EQ(sym.st_value, 0x1100u);

  munmap(mem, page_size);
}

TEST(GnuHashLookup, ChainStepCapStopsMalformedLongChain) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  constexpr size_t kChainEntries = 4096;
  const size_t mapping_size = page_size * 5;
  void* mem =
      mmap(nullptr, mapping_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);
  memset(mem, 0, mapping_size);

  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  DsoInfo dso{};
  init_synthetic_lookup_dso(&dso, base, mapping_size);
  dso.gnu_hash_addr = base + 0x100;

  uint32_t header[4] = {1, 1, 1, 0};
  memcpy(static_cast<char*>(mem) + 0x100, header, sizeof(header));

  auto* bloom = reinterpret_cast<uintptr_t*>(static_cast<char*>(mem) + 0x100 + sizeof(header));
  bloom[0] = ~uintptr_t{0};
  auto* buckets = reinterpret_cast<uint32_t*>(bloom + 1);
  buckets[0] = 1;
  auto* chains = buckets + 1;

  // Model a corrupted GNU hash table whose chain never sets the end-of-chain bit. The lookup must
  // return false after kMaxChainSteps instead of walking unbounded memory.
  for (size_t i = 0; i < kChainEntries; i++) chains[i] = 0;

  Elf64_Sym sym{};
  EXPECT_FALSE(gnu_hash_lookup(&dso, "missing", &sym));

  munmap(mem, mapping_size);
}

// ===== elf_hash_lookup tests =====
// These use libdso_test_hash_helper.so, which is built with --hash-style=both, guaranteeing DT_HASH
// is present. On arm64, the platform default is --hash-style=gnu, meaning DT_GNU_HASH only, so most
// system DSOs lack DT_HASH.

class ElfHashLookup : public ::testing::Test {
 protected:
  void SetUp() override {
    load_hash_helper();
    ASSERT_NE(g_hash_helper_handle, nullptr) << "Failed to dlopen libdso_test_hash_helper.so";
    mapping_ = find_dso_mapping("libdso_test_hash_helper.so");
    ASSERT_NE(mapping_.start, 0u) << "Could not find libdso_test_hash_helper.so in /proc/self/maps";
    ASSERT_TRUE(parse_dso_elf(mapping_.start, mapping_.end, &dso_));
    ASSERT_NE(dso_.hash_addr, 0u) << "libdso_test_hash_helper.so should have DT_HASH";
  }

  MapsEntry mapping_{};
  DsoInfo dso_{};
};

TEST_F(ElfHashLookup, FindSymbolInTestDso) {
  Elf64_Sym sym{};
  ASSERT_TRUE(elf_hash_lookup(&dso_, "dso_test_add", &sym));

  EXPECT_EQ(ELF64_ST_TYPE(sym.st_info), (unsigned)STT_FUNC);
  EXPECT_NE(sym.st_shndx, (unsigned)SHN_UNDEF);
  EXPECT_GT(sym.st_size, 0u);
}

TEST_F(ElfHashLookup, CrossCheckWithGnuHash) {
  ASSERT_NE(dso_.gnu_hash_addr, 0u);

  // Cross-check: both hash tables must resolve the same symbol identically.
  const char* symbols[] = {"dso_test_add", "dso_test_mul", "dso_test_identity"};
  for (const char* name : symbols) {
    Elf64_Sym elf_sym{};
    ASSERT_TRUE(elf_hash_lookup(&dso_, name, &elf_sym)) << "elf_hash_lookup failed for: " << name;

    Elf64_Sym gnu_sym{};
    ASSERT_TRUE(gnu_hash_lookup(&dso_, name, &gnu_sym)) << "gnu_hash_lookup failed for: " << name;

    EXPECT_EQ(elf_sym.st_value, gnu_sym.st_value) << "st_value mismatch for: " << name;
    EXPECT_EQ(elf_sym.st_size, gnu_sym.st_size) << "st_size mismatch for: " << name;
  }
}

TEST_F(ElfHashLookup, NonexistentSymbolFails) {
  Elf64_Sym sym{};
  EXPECT_FALSE(elf_hash_lookup(&dso_, "__this_symbol_does_not_exist_at_all__", &sym));
}

TEST_F(ElfHashLookup, MultipleSymbols) {
  const char* symbols[] = {"dso_test_add", "dso_test_mul", "dso_test_identity"};
  for (const char* name : symbols) {
    Elf64_Sym sym{};
    EXPECT_TRUE(elf_hash_lookup(&dso_, name, &sym)) << "Failed to find symbol: " << name;
    EXPECT_GT(sym.st_size, 0u) << "Zero size for symbol: " << name;
  }
}

TEST(ElfHashLookupSynthetic, BucketCollisionFindsLaterSymbol) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);
  memset(mem, 0, page_size);

  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  DsoInfo dso{};
  init_synthetic_lookup_dso(&dso, base, page_size);
  dso.symtab_addr = base + 0x100;
  dso.strtab_addr = base + 0x200;
  dso.hash_addr = base + 0x300;

  auto* symtab = reinterpret_cast<Elf64_Sym*>(static_cast<char*>(mem) + 0x100);
  char* strtab = static_cast<char*>(mem) + 0x200;
  auto* header = reinterpret_cast<uint32_t*>(static_cast<char*>(mem) + 0x300);
  header[0] = 1;  // nbuckets
  header[1] = 3;  // nchain

  // Like the GNU hash test above, use a single bucket so lookup must follow the chain to the later
  // symbol instead of returning after the first non-matching entry in the bucket.
  strtab[0] = '\0';
  strcpy(strtab + 1, "first");
  const uint32_t target_name_off = 1 + strlen("first") + 1;
  strcpy(strtab + target_name_off, "target");
  symtab[1] = make_global_func_sym(1, 0x1000, 0x20);
  symtab[2] = make_global_func_sym(target_name_off, 0x1100, 0x20);

  auto* buckets = header + 2;
  auto* chains = buckets + 1;
  buckets[0] = 1;
  chains[0] = 0;
  chains[1] = 2;
  chains[2] = 0;

  Elf64_Sym sym{};
  ASSERT_TRUE(elf_hash_lookup(&dso, "target", &sym));
  EXPECT_EQ(sym.st_name, target_name_off);
  EXPECT_EQ(sym.st_value, 0x1100u);

  munmap(mem, page_size);
}

TEST(ElfHashLookupSynthetic, ChainStepCapStopsCycle) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  void* mem = mmap(nullptr, page_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
  ASSERT_NE(mem, MAP_FAILED) << strerror(errno);
  memset(mem, 0, page_size);

  uintptr_t base = reinterpret_cast<uintptr_t>(mem);
  DsoInfo dso{};
  init_synthetic_lookup_dso(&dso, base, page_size);
  dso.symtab_addr = base + 0x100;
  dso.strtab_addr = base + 0x200;
  dso.hash_addr = base + 0x300;

  auto* symtab = reinterpret_cast<Elf64_Sym*>(static_cast<char*>(mem) + 0x100);
  char* strtab = static_cast<char*>(mem) + 0x200;
  auto* header = reinterpret_cast<uint32_t*>(static_cast<char*>(mem) + 0x300);
  header[0] = 1;  // nbuckets
  header[1] = 2;  // nchain

  strtab[0] = '\0';
  strcpy(strtab + 1, "present");
  symtab[1] = make_global_func_sym(1, 0x1000, 0x20);

  auto* buckets = header + 2;
  auto* chains = buckets + 1;

  // Model a corrupted SYSV hash chain that loops back to the same symbol forever. The lookup must
  // stop at kMaxChainSteps instead of spinning indefinitely on chain[1] == 1.
  buckets[0] = 1;
  chains[0] = 0;
  chains[1] = 1;

  Elf64_Sym sym{};
  EXPECT_FALSE(elf_hash_lookup(&dso, "missing", &sym));

  munmap(mem, page_size);
}

// ===== func_matches tests =====

TEST(FuncMatches, AtoiMatchesByAddress) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u);

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));
  dso.valid = true;

  // Use atoi, a regular STT_FUNC, not an IFUNC.
  void* addr = dlsym(RTLD_DEFAULT, "atoi");
  ASSERT_NE(addr, nullptr);

  EXPECT_TRUE(func_matches(reinterpret_cast<uintptr_t>(addr), &dso, "atoi"));
}

TEST(FuncMatches, WrongNameFails) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u);

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));
  dso.valid = true;

  // Use atoi's address but look up "close". Should fail.
  void* addr = dlsym(RTLD_DEFAULT, "atoi");
  ASSERT_NE(addr, nullptr);

  EXPECT_FALSE(func_matches(reinterpret_cast<uintptr_t>(addr), &dso, "close"));
}

TEST(FuncMatches, OnePastEndFails) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u);

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));
  dso.valid = true;

  // Look up atoi to get its size, then test one-past-end.
  Elf64_Sym sym{};
  ASSERT_TRUE(gnu_hash_lookup(&dso, "atoi", &sym));
  ASSERT_GT(sym.st_size, 0u);

  uintptr_t sym_rt = mapping.start + sym.st_value - dso.elf_load_bias;
  uintptr_t one_past_end = sym_rt + sym.st_size;
  EXPECT_FALSE(func_matches(one_past_end, &dso, "atoi"));
}

TEST(FuncMatches, AddrBeforeBaseFails) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u);

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));
  dso.valid = true;

  // Address before the DSO base should fail.
  EXPECT_FALSE(func_matches(mapping.start - 1, &dso, "atoi"));
}

TEST(FuncMatches, InvalidDsoFails) {
  DsoInfo dso{};
  dso.valid = false;
  EXPECT_FALSE(func_matches(0x12345, &dso, "atoi"));
}

TEST(FuncMatches, MiddleOfFunctionMatches) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u);

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));
  dso.valid = true;

  // Use atoi, a regular STT_FUNC with nonzero size, and test an address in the middle.
  Elf64_Sym sym{};
  ASSERT_TRUE(gnu_hash_lookup(&dso, "atoi", &sym));
  ASSERT_GT(sym.st_size, 4u);

  uintptr_t sym_rt = mapping.start + sym.st_value - dso.elf_load_bias;
  EXPECT_TRUE(func_matches(sym_rt + 4, &dso, "atoi"));
}

// ===== Integration: hash lookup cross-check against dlsym =====

TEST(Integration, GnuHashMatchesDlsym) {
  MapsEntry mapping = find_dso_mapping("libc.so");
  ASSERT_NE(mapping.start, 0u);

  DsoInfo dso{};
  ASSERT_TRUE(parse_dso_elf(mapping.start, mapping.end, &dso));

  // Use non-IFUNC symbols. String and memory functions such as strlen() and memcpy() are IFUNCs on
  // aarch64, so dlsym() resolves to the selected implementation rather than st_value.
  const char* symbols[] = {"atoi", "open", "close", "write", "getpid"};
  for (const char* name : symbols) {
    void* dlsym_addr = dlsym(RTLD_DEFAULT, name);
    if (!dlsym_addr) continue;  // Symbol may not be exported.

    Elf64_Sym sym{};
    ASSERT_TRUE(gnu_hash_lookup(&dso, name, &sym)) << "gnu_hash_lookup failed for: " << name;

    uintptr_t sym_rt = mapping.start + sym.st_value - dso.elf_load_bias;
    EXPECT_EQ(reinterpret_cast<uintptr_t>(dlsym_addr), sym_rt) << "Address mismatch for: " << name;
  }
}
