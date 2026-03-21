// Device tests for the backtrace-driven DSO-resolution helpers in maps_dso_search.h. These run
// against real DSOs loaded into /proc/self/maps and therefore require an aarch64 device.

#include "maps_dso_search.h"

#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libgen.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <gtest/gtest.h>

#include <string>
#include <vector>

using namespace mte_suppression;

static_assert(kMaxDsos >= 2,
              "maps_dso_search_test exercises successful cross-DSO resolution and needs at least "
              "two DSO slots");

// Load libdso_test_hash_helper.so from the same directory as the test binary.
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

static Elf64_Sym make_global_func_sym(uint32_t name_offset, uintptr_t value, size_t size) {
  Elf64_Sym sym{};
  sym.st_name = name_offset;
  sym.st_info = ELF64_ST_INFO(STB_GLOBAL, STT_FUNC);
  sym.st_shndx = 1;
  sym.st_value = value;
  sym.st_size = size;
  return sym;
}

static std::vector<char> make_synthetic_elf_payload_without_soname() {
  const size_t page_size = static_cast<size_t>(getpagesize());
  std::vector<char> payload(page_size * 2, '\0');

  auto* ehdr = reinterpret_cast<Elf64_Ehdr*>(payload.data());
  memcpy(ehdr->e_ident, ELFMAG, SELFMAG);
  ehdr->e_ident[EI_CLASS] = ELFCLASS64;
  ehdr->e_ident[EI_DATA] = ELFDATA2LSB;
  ehdr->e_type = ET_DYN;
  ehdr->e_version = EV_CURRENT;
  ehdr->e_machine = EM_AARCH64;
  ehdr->e_phentsize = sizeof(Elf64_Phdr);
  ehdr->e_phnum = 3;
  ehdr->e_phoff = sizeof(Elf64_Ehdr);

  auto* phdrs = reinterpret_cast<Elf64_Phdr*>(payload.data() + sizeof(Elf64_Ehdr));
  phdrs[0].p_type = PT_LOAD;
  phdrs[0].p_vaddr = 0x0;
  phdrs[0].p_memsz = 0x800;
  phdrs[0].p_flags = PF_R;

  phdrs[1].p_type = PT_LOAD;
  phdrs[1].p_vaddr = 0x1000;
  phdrs[1].p_memsz = 0x200;
  phdrs[1].p_flags = PF_R | PF_X;

  phdrs[2].p_type = PT_DYNAMIC;
  phdrs[2].p_vaddr = 0x180;
  phdrs[2].p_memsz = 5 * sizeof(Elf64_Dyn);

  auto* dyn = reinterpret_cast<Elf64_Dyn*>(payload.data() + 0x180);
  dyn[0].d_tag = DT_SYMTAB;
  dyn[0].d_un.d_ptr = 0x300;
  dyn[1].d_tag = DT_STRTAB;
  dyn[1].d_un.d_ptr = 0x200;
  dyn[2].d_tag = DT_STRSZ;
  dyn[2].d_un.d_val = 0x40;
  dyn[3].d_tag = DT_GNU_HASH;
  dyn[3].d_un.d_ptr = 0x400;
  dyn[4].d_tag = DT_NULL;
  dyn[4].d_un.d_val = 0;

  char* strtab = payload.data() + 0x200;
  strtab[0] = '\0';
  strcpy(strtab + 1, "target");

  auto* symtab = reinterpret_cast<Elf64_Sym*>(payload.data() + 0x300);
  symtab[1] = make_global_func_sym(1, 0x1000, 0x20);

  uint32_t header[4] = {1, 1, 1, 0};
  memcpy(payload.data() + 0x400, header, sizeof(header));
  auto* bloom = reinterpret_cast<uintptr_t*>(payload.data() + 0x400 + sizeof(header));
  bloom[0] = ~uintptr_t{0};
  auto* buckets = reinterpret_cast<uint32_t*>(bloom + 1);
  buckets[0] = 1;
  auto* chains = buckets + 1;
  chains[0] = gnu_hash_calc("target") | 1u;

  return payload;
}

static int count_unique_pattern_dsos(const SuppressionPattern& pat) {
  const char* seen[kMaxFrames] = {};
  int count = 0;
  for (int frame_idx = 0; frame_idx < static_cast<int>(pat.frames.size()); frame_idx++) {
    const char* dso_name = pat.frames[frame_idx].dso_name;
    bool already_seen = false;
    for (int seen_idx = 0; seen_idx < count; seen_idx++) {
      if (strcmp(seen[seen_idx], dso_name) == 0) {
        already_seen = true;
        break;
      }
    }
    if (!already_seen) {
      seen[count++] = dso_name;
    }
  }
  return count;
}

static void resolve_pattern_or_fail(const SuppressionPattern& pat, const uintptr_t* backtrace,
                                    int bt_depth, int* frame_dso_map, DsoSearchCtx* ctx) {
  bool bt_in_exec_map[kMaxFrames + 2] = {};
  ASSERT_EQ(collect_executable_frames_and_find_pattern_dsos_for_backtrace(
                pat, backtrace, bt_depth, bt_in_exec_map, frame_dso_map, ctx),
            count_unique_pattern_dsos(pat));
}

TEST(CollectExecutableFramesAndFindPatternDsosForBacktrace, DistinguishesCodeFromStack) {
  load_hash_helper();
  ASSERT_NE(g_hash_helper_handle, nullptr) << "Failed to dlopen libdso_test_hash_helper.so";

  void* add_addr = dlsym(g_hash_helper_handle, "dso_test_add");
  ASSERT_NE(add_addr, nullptr);
  uint8_t stack_var = 0;
  uintptr_t backtrace[2] = {
      reinterpret_cast<uintptr_t>(add_addr),
      reinterpret_cast<uintptr_t>(&stack_var),
  };
  ASSERT_NE(backtrace[0], 0u);

  constexpr FramePattern kFrames[] = {{"libdso_test_hash_helper.so", "dso_test_add"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("code_vs_stack", 10, kFrames[0]);
  SuppressionPattern pat = kPatternDef.view();
  int frame_dso_map[kMaxFrames] = {};
  DsoSearchCtx ctx = {};
  bool bt_in_exec_map[2] = {};
  ASSERT_EQ(collect_executable_frames_and_find_pattern_dsos_for_backtrace(
                pat, backtrace, 2, bt_in_exec_map, frame_dso_map, &ctx),
            1);
  EXPECT_TRUE(bt_in_exec_map[0]);
  EXPECT_FALSE(bt_in_exec_map[1]);
  EXPECT_EQ(ctx.found, 1);
  EXPECT_TRUE(ctx.infos[0].valid);
}

TEST(CollectExecutableFramesAndFindPatternDsosForBacktrace, SingleDso) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  ASSERT_NE(atoi_addr, nullptr);

  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr)};
  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("single_dso", 10, kFrames[0]);
  SuppressionPattern pat = kPatternDef.view();
  int frame_dso_map[kMaxFrames] = {};
  DsoSearchCtx ctx = {};

  resolve_pattern_or_fail(pat, backtrace, 1, frame_dso_map, &ctx);

  EXPECT_EQ(ctx.found, 1);
  EXPECT_TRUE(ctx.infos[0].valid);
  EXPECT_EQ(frame_dso_map[0], 0);
  EXPECT_STREQ(ctx.infos[0].soname, "libc.so");
}

TEST(CollectExecutableFramesAndFindPatternDsosForBacktrace, DedupSameDso) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  void* open_addr = dlsym(RTLD_DEFAULT, "open");
  ASSERT_NE(atoi_addr, nullptr);
  ASSERT_NE(open_addr, nullptr);

  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr),
                           reinterpret_cast<uintptr_t>(open_addr)};
  constexpr FramePattern kFrames[] = {{"libc.so", "atoi"}, {"libc.so", "open"}};
  constexpr auto kPatternDef =
      MakeSuppressionPatternDef("dedup_same_dso", 10, kFrames[0], kFrames[1]);
  SuppressionPattern pat = kPatternDef.view();
  int frame_dso_map[kMaxFrames] = {};
  DsoSearchCtx ctx = {};

  resolve_pattern_or_fail(pat, backtrace, 2, frame_dso_map, &ctx);

  EXPECT_EQ(ctx.found, 1);
  EXPECT_EQ(frame_dso_map[0], 0);
  EXPECT_EQ(frame_dso_map[1], 0);
}

TEST(CollectExecutableFramesAndFindPatternDsosForBacktrace, TwoDifferentDsos) {
  load_hash_helper();
  ASSERT_NE(g_hash_helper_handle, nullptr) << "Failed to dlopen libdso_test_hash_helper.so";

  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  void* add_addr = dlsym(g_hash_helper_handle, "dso_test_add");
  ASSERT_NE(atoi_addr, nullptr);
  ASSERT_NE(add_addr, nullptr);

  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr),
                           reinterpret_cast<uintptr_t>(add_addr)};
  constexpr FramePattern kFrames[] = {
      {"libc.so", "atoi"},
      {"libdso_test_hash_helper.so", "dso_test_add"},
  };
  constexpr auto kPatternDef =
      MakeSuppressionPatternDef("two_different_dsos", 10, kFrames[0], kFrames[1]);
  SuppressionPattern pat = kPatternDef.view();
  int frame_dso_map[kMaxFrames] = {};
  DsoSearchCtx ctx = {};

  resolve_pattern_or_fail(pat, backtrace, 2, frame_dso_map, &ctx);

  EXPECT_EQ(ctx.found, 2);
  EXPECT_EQ(frame_dso_map[0], 0);
  EXPECT_EQ(frame_dso_map[1], 1);
  EXPECT_NE(ctx.infos[0].base, ctx.infos[1].base);
}

TEST(CollectExecutableFramesAndFindPatternDsosForBacktrace, CrossDsoDedupMapping) {
  load_hash_helper();
  ASSERT_NE(g_hash_helper_handle, nullptr) << "Failed to dlopen libdso_test_hash_helper.so";

  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  void* add_addr = dlsym(g_hash_helper_handle, "dso_test_add");
  void* open_addr = dlsym(RTLD_DEFAULT, "open");
  ASSERT_NE(atoi_addr, nullptr);
  ASSERT_NE(add_addr, nullptr);
  ASSERT_NE(open_addr, nullptr);

  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr),
                           reinterpret_cast<uintptr_t>(add_addr),
                           reinterpret_cast<uintptr_t>(open_addr)};
  constexpr FramePattern kFrames[] = {
      {"libc.so", "atoi"},
      {"libdso_test_hash_helper.so", "dso_test_add"},
      {"libc.so", "open"},
  };
  constexpr auto kPatternDef =
      MakeSuppressionPatternDef("cross_dso_dedup", 10, kFrames[0], kFrames[1], kFrames[2]);
  SuppressionPattern pat = kPatternDef.view();
  int frame_dso_map[kMaxFrames] = {};
  DsoSearchCtx ctx = {};

  resolve_pattern_or_fail(pat, backtrace, 3, frame_dso_map, &ctx);

  EXPECT_EQ(ctx.found, 2);
  EXPECT_EQ(frame_dso_map[0], 0);
  EXPECT_EQ(frame_dso_map[1], 1);
  EXPECT_EQ(frame_dso_map[2], 0);
}

TEST(CollectExecutableFramesAndFindPatternDsosForBacktrace, NonexistentDsoPartialFind) {
  void* atoi_addr = dlsym(RTLD_DEFAULT, "atoi");
  ASSERT_NE(atoi_addr, nullptr);

  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(atoi_addr)};
  bool bt_in_exec_map[1] = {};

  constexpr FramePattern kFrames[] = {
      {"libc.so", "atoi"},
      {"libthis_does_not_exist_at_all.so", "fake"},
  };
  constexpr auto kPatternDef =
      MakeSuppressionPatternDef("nonexistent_partial_find", 10, kFrames[0], kFrames[1]);
  SuppressionPattern pat = kPatternDef.view();
  int frame_dso_map[kMaxFrames] = {};
  DsoSearchCtx ctx = {};

  ASSERT_EQ(collect_executable_frames_and_find_pattern_dsos_for_backtrace(
                pat, backtrace, 1, bt_in_exec_map, frame_dso_map, &ctx),
            2);
  EXPECT_TRUE(bt_in_exec_map[0]);
  EXPECT_EQ(ctx.found, 1);
  EXPECT_TRUE(ctx.infos[0].valid);
  EXPECT_FALSE(ctx.infos[1].valid);
}

TEST(CollectExecutableFramesAndFindPatternDsosForBacktrace,
     IgnoresDuplicateBasenameWithoutMatchingFrame) {
  load_hash_helper();
  ASSERT_NE(g_hash_helper_handle, nullptr) << "Failed to dlopen libdso_test_hash_helper.so";

  std::string src_path = get_test_lib_dir() + "/libdso_test_hash_helper.so";
  char tmp_template[] = "/data/local/tmp/mte_suppression_dup.XXXXXX";
  char* tmp_dir = mkdtemp(tmp_template);
  ASSERT_NE(tmp_dir, nullptr) << strerror(errno);

  std::string dup_path = std::string(tmp_dir) + "/libdso_test_hash_helper.so";
  ASSERT_TRUE(copy_file(src_path, dup_path)) << "Failed to copy helper DSO";

  int dup_fd = open(dup_path.c_str(), O_RDONLY | O_CLOEXEC);
  ASSERT_GE(dup_fd, 0) << strerror(errno);
  off_t dup_size = lseek(dup_fd, 0, SEEK_END);
  ASSERT_GT(dup_size, 0);
  void* dup_mapping =
      mmap(nullptr, static_cast<size_t>(dup_size), PROT_READ, MAP_PRIVATE, dup_fd, 0);
  close(dup_fd);
  ASSERT_NE(dup_mapping, MAP_FAILED) << strerror(errno);

  void* add_addr = dlsym(g_hash_helper_handle, "dso_test_add");
  ASSERT_NE(add_addr, nullptr);
  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(add_addr)};
  bool bt_in_exec_map[1] = {};

  constexpr FramePattern kFrames[] = {{"libdso_test_hash_helper.so", "dso_test_add"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("test_duplicate_basename", 10, kFrames[0]);
  SuppressionPattern pat = kPatternDef.view();
  int frame_dso_map[kMaxFrames] = {};
  DsoSearchCtx ctx = {};
  ASSERT_EQ(collect_executable_frames_and_find_pattern_dsos_for_backtrace(
                pat, backtrace, 1, bt_in_exec_map, frame_dso_map, &ctx),
            1);
  ASSERT_TRUE(bt_in_exec_map[0]);
  EXPECT_EQ(ctx.found, 1);
  EXPECT_FALSE(ctx.ambiguous[0]);

  Dl_info info = {};
  ASSERT_NE(dladdr(add_addr, &info), 0);
  EXPECT_EQ(ctx.infos[0].base, reinterpret_cast<uintptr_t>(info.dli_fbase));

  munmap(dup_mapping, static_cast<size_t>(dup_size));
  unlink(dup_path.c_str());
  rmdir(tmp_dir);
}

TEST(BuildPatternDsoSlots, TooManyUniqueDsosFails) {
  // This limit is enforced before any /proc/self/maps scan happens. Use fake DSO names on purpose:
  // the test is only about documenting that one pattern cannot reference more than kMaxDsos unique
  // DSOs in the current fixed-size signal-handler scratch model. Build exactly kMaxDsos + 1 unique
  // names so the test stays valid if the production limit changes later.
  std::vector<std::string> dso_names(kMaxDsos + 1);
  std::vector<std::string> func_names(kMaxDsos + 1);
  std::vector<FramePattern> frames(kMaxDsos + 1);
  for (size_t i = 0; i < frames.size(); i++) {
    dso_names[i] = "lib" + std::to_string(i) + ".so";
    func_names[i] = "f" + std::to_string(i);
    frames[i] = FramePattern{dso_names[i].c_str(), func_names[i].c_str()};
  }
  SuppressionPattern pat = {
      .name = "too_many_unique_dsos",
      .frames = frames,
      .reenable_timer_ms = 10,
  };

  std::vector<int> frame_dso_map(frames.size());
  DsoSearchCtx ctx = {};
  EXPECT_EQ(build_pattern_dso_slots(pat, frame_dso_map.data(), &ctx), -1);
}

TEST(CollectExecutableFramesAndFindPatternDsosForBacktrace, ApkEmbeddedDsoWithoutSonameIsIgnored) {
  const size_t page_size = static_cast<size_t>(getpagesize());
  std::vector<char> payload = make_synthetic_elf_payload_without_soname();

  char tmp_template[] = "/data/local/tmp/mte_suppression_apk.XXXXXX";
  char* tmp_dir = mkdtemp(tmp_template);
  ASSERT_NE(tmp_dir, nullptr) << strerror(errno);

  std::string apk_path = std::string(tmp_dir) + "/embedded.apk";
  int fd = open(apk_path.c_str(), O_CREAT | O_RDWR | O_TRUNC | O_CLOEXEC, 0644);
  ASSERT_GE(fd, 0) << strerror(errno);

  std::vector<char> pad(page_size, '\0');
  ASSERT_EQ(static_cast<ssize_t>(pad.size()),
            TEMP_FAILURE_RETRY(write(fd, pad.data(), pad.size())));
  ASSERT_EQ(static_cast<ssize_t>(payload.size()),
            TEMP_FAILURE_RETRY(write(fd, payload.data(), payload.size())));

  void* mapping = mmap(nullptr, payload.size(), PROT_READ | PROT_EXEC, MAP_PRIVATE, fd,
                       static_cast<off_t>(page_size));
  close(fd);
  ASSERT_NE(mapping, MAP_FAILED) << strerror(errno);

  // Point the synthetic backtrace into the executable PT_LOAD range and name the exact symbol that
  // exists in the synthetic ELF. If APK matching ever starts falling back to the .apk path or
  // stops requiring DT_SONAME, this test would begin resolving the DSO instead of leaving it
  // unresolved.
  uintptr_t backtrace[] = {reinterpret_cast<uintptr_t>(mapping) + 0x1000};
  bool bt_in_exec_map[1] = {};
  constexpr FramePattern kFrames[] = {{"libsynthetic_missing_soname.so", "target"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("apk_without_soname", 10, kFrames[0]);
  SuppressionPattern pat = kPatternDef.view();
  int frame_dso_map[1] = {};
  DsoSearchCtx ctx = {};

  ASSERT_EQ(collect_executable_frames_and_find_pattern_dsos_for_backtrace(
                pat, backtrace, 1, bt_in_exec_map, frame_dso_map, &ctx),
            1);
  EXPECT_TRUE(bt_in_exec_map[0]);
  EXPECT_EQ(frame_dso_map[0], 0);
  EXPECT_EQ(ctx.found, 0);
  EXPECT_FALSE(ctx.infos[0].valid);

  munmap(mapping, payload.size());
  unlink(apk_path.c_str());
  rmdir(tmp_dir);
}

TEST(CollectExecutableFramesAndFindPatternDsosForBacktrace, TooManyCandidatesFailsClosed) {
  std::string src_path = get_test_lib_dir() + "/libdso_test_hash_helper.so";
  char tmp_template[] = "/data/local/tmp/mte_suppression_candidates.XXXXXX";
  char* tmp_dir = mkdtemp(tmp_template);
  ASSERT_NE(tmp_dir, nullptr) << strerror(errno);

  constexpr const char* kBasename = "libcandidate_cap_helper.so";
  std::vector<void*> mappings;
  std::vector<size_t> mapping_sizes;
  std::vector<std::string> file_paths;
  std::vector<std::string> dir_paths;

  // Create more than kMaxPatternDsoCandidates mappings with the same basename. The production code
  // collects these basename matches before it disambiguates them against the current backtrace, so
  // this drives the fixed-size candidate cap directly.
  for (int i = 0; i < kMaxPatternDsoCandidates + 1; i++) {
    std::string dir = std::string(tmp_dir) + "/" + std::to_string(i);
    ASSERT_EQ(mkdir(dir.c_str(), 0700), 0) << strerror(errno);

    std::string path = dir + "/" + kBasename;
    ASSERT_TRUE(copy_file(src_path, path)) << "Failed to copy helper DSO to " << path;

    int fd = open(path.c_str(), O_RDONLY | O_CLOEXEC);
    ASSERT_GE(fd, 0) << strerror(errno);
    off_t size = lseek(fd, 0, SEEK_END);
    ASSERT_GT(size, 0);

    void* mapping = mmap(nullptr, static_cast<size_t>(size), PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    ASSERT_NE(mapping, MAP_FAILED) << strerror(errno);

    mappings.push_back(mapping);
    mapping_sizes.push_back(static_cast<size_t>(size));
    file_paths.push_back(path);
    dir_paths.push_back(dir);
  }

  constexpr FramePattern kFrames[] = {{kBasename, "dso_test_add"}};
  constexpr auto kPatternDef = MakeSuppressionPatternDef("candidate_cap", 10, kFrames[0]);
  SuppressionPattern pat = kPatternDef.view();
  uintptr_t backtrace[] = {0};
  bool bt_in_exec_map[1] = {};
  int frame_dso_map[1] = {};
  DsoSearchCtx ctx = {};

  EXPECT_EQ(collect_executable_frames_and_find_pattern_dsos_for_backtrace(
                pat, backtrace, 1, bt_in_exec_map, frame_dso_map, &ctx),
            -1);

  for (size_t i = 0; i < mappings.size(); i++) munmap(mappings[i], mapping_sizes[i]);
  for (const auto& path : file_paths) unlink(path.c_str());
  for (const auto& dir : dir_paths) rmdir(dir.c_str());
  rmdir(tmp_dir);
}
