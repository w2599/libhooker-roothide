// 用真实符号解析与单个 Mach 接口桩验证共享缓存查询的入口筛选。
#include <assert.h>
#include <mach/mach.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

static unsigned taskInfoCalls;
static bool denyIndexAllocation;
static unsigned allocations;

// 模拟索引分配失败，符号映射及原始表仍然可用。
static void *testCalloc(size_t count, size_t size) {
    allocations++;
    return denyIndexAllocation ? NULL : calloc(count, size);
}

// 阻止访问宿主缓存，使初始化次数和后续测试符号表完全可控。
static kern_return_t LHTestTaskInfo(task_name_t task, task_flavor_t flavor,
        task_info_t info, mach_msg_type_number_t *count) {
    (void)task; (void)flavor; (void)info; (void)count;
    taskInfoCalls++;
    return KERN_FAILURE;
}

#define task_info LHTestTaskInfo
#define calloc testCalloc
#include "../libhooker/dyld/dyldSyms-modern.c"
#undef calloc
#undef task_info

// 构造磁盘缓存，使用生产映射与查询入口；每种布局在独立进程中运行。
static void testDiskTable(bool wide, bool shuffled, bool benchmark) {
    enum { images = 4096 };
    struct {
        struct dyld_cache_header header;
        struct mach_header_64 image[images + 1];
    } *fixture = calloc(1, sizeof(*fixture));
    assert(fixture);
    cacheHeader = &fixture->header;
    size_t width = wide ? sizeof(struct dyld_cache_local_symbols_entry_64) : sizeof(struct dyld_cache_local_symbols_entry);
    size_t entriesOffset = sizeof(struct dyld_cache_local_symbols_info) + 1; // 刻意不对齐。
    size_t nlistOffset = entriesOffset + (images + 1) * width;
    size_t stringsOffset = nlistOffset + 2 * sizeof(struct nlist_64);
    const char strings[] = "\0_cached";
    size_t bytes = stringsOffset + sizeof(strings);
    uint8_t *data = calloc(1, bytes);
    assert(data);
    struct dyld_cache_local_symbols_info info = {
        .entriesOffset = entriesOffset, .entriesCount = images + 1, .nlistOffset = nlistOffset,
        .nlistCount = 2, .stringsOffset = stringsOffset, .stringsSize = sizeof(strings),
    };
    memcpy(data, &info, sizeof(info));
    for (unsigned i = 0; i <= images; i++) {
        // 表尾重复最后一个偏移；两个条目给出不同结果，必须使用文件中靠前的一项。
        unsigned position = i == images ? i - 1 : i;
        unsigned which = shuffled ? (position * 4051u) % images : position;
        uint64_t offset = (uintptr_t)&fixture->image[which] - (uintptr_t)cacheHeader;
        struct dyld_cache_local_symbols_entry_64 modern = {offset, i == images, 1};
        struct dyld_cache_local_symbols_entry legacy = {(uint32_t)offset, i == images, 1};
        memcpy(data + entriesOffset + i * width, wide ? (void *)&modern : (void *)&legacy, width);
    }
    for (unsigned i = 0; i <= images; i++)
        fixture->image[i] = (struct mach_header_64){.magic = MH_MAGIC_64, .flags = MH_DYLIB_IN_CACHE};
    struct nlist_64 symbols[2] = {
        {.n_un.n_strx = 1, .n_type = N_SECT, .n_value = 0x1000},
        {.n_un.n_strx = 1, .n_type = N_SECT, .n_value = 0x2000},
    };
    memcpy(data + nlistOffset, symbols, sizeof(symbols));
    memcpy(data + stringsOffset, strings, sizeof(strings));
    struct dyld_cache_header header = {
        .mappingOffset = wide ? sizeof(header) : offsetof(struct dyld_cache_header, uuid) + sizeof(header.uuid),
        .localSymbolsOffset = (uint64_t)getpagesize(), .localSymbolsSize = bytes,
    };
    memcpy(header.magic, "dyld_v1 ", 8);
    char path[] = "worker/host-tests/symbol-cache-XXXXXX";
    int fd = mkstemp(path);
    assert(fd >= 0 && write(fd, &header, sizeof(header)) == sizeof(header));
    assert(lseek(fd, header.localSymbolsOffset, SEEK_SET) == (off_t)header.localSymbolsOffset);
    assert(write(fd, data, bytes) == (ssize_t)bytes && close(fd) == 0);
    uint64_t start = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
    assert(LHMapLocalSymbols(path, false));
    uint64_t setup = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) - start;
    if (!benchmark) assert(allocations == (unsigned)shuffled);
    assert(unlink(path) == 0);
    const char *name = "_cached";
    unsigned rounds = benchmark ? 64 : 1;
    start = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
    for (unsigned pass = 0; pass < rounds; pass++) {
        for (unsigned i = 0; i < images; i++) {
            void *result = NULL;
            LHSearchCache(&fixture->image[(i * 97u) % images], 0, &name, &result, 1);
            assert(result == (void *)0x1000);
        }
    }
    uint64_t hits = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) - start;
    start = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW);
    const char *absent = "_absent";
    for (unsigned pass = 0; pass < rounds; pass++) {
        for (unsigned i = 0; i < images; i++) {
            void *result = NULL;
            LHSearchCache(&fixture->image[i], 0, &absent, &result, 1);
            assert(!result);
        }
    }
    uint64_t misses = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) - start;
    void *result = NULL;
    LHSearchCache(&fixture->image[images], 0, &name, &result, 1);
    assert(!result);
    if (benchmark) printf("%u lookups per group, setup %.3f ms, hits %.3f ms, absent symbol %.3f ms\n",
        rounds * images, setup / 1e6, hits / 1e6, misses / 1e6);
    free(data);
    free(fixture);
}

// 普通镜像不初始化缓存；共享缓存仍初始化一次并按原有表格式解析符号。
int main(int argc, char **argv) {
    struct {
        struct dyld_cache_header cache;
        struct mach_header_64 image;
    } fixture = {.image = {.magic = MH_MAGIC_64}};
    const char *name = "_cached";
    void *result = NULL;
    LHSearchCache(&fixture.image, 0, &name, &result, 1);
    assert(!result && taskInfoCalls == 0 && !cacheHeader && !localSymbols);

    fixture.image.flags = MH_DYLIB_IN_CACHE;
    LHSearchCache(&fixture.image, 0, &name, &result, 1);
    assert(!result && taskInfoCalls == 1);

    if (argc >= 3) {
        denyIndexAllocation = argc == 4 && !strcmp(argv[3], "--no-index-memory");
        testDiskTable(!strcmp(argv[1], "wide"), !strcmp(argv[2], "shuffled"),
            argc == 4 && !strcmp(argv[3], "--bench"));
        return 0;
    }

    struct {
        struct dyld_cache_local_symbols_entry_64 entry;
        struct nlist_64 symbol;
        char strings[9];
    } table = {
        .entry = {.dylibOffset = offsetof(typeof(fixture), image), .nlistCount = 1},
        .symbol = {.n_un.n_strx = 1, .n_type = N_SECT, .n_value = 0x1000},
        .strings = "\0_cached",
    };
    cacheHeader = &fixture.cache;
    localSymbols = (const void *)&table;
    localInfo = (struct dyld_cache_local_symbols_info){
        .nlistOffset = offsetof(typeof(table), symbol), .nlistCount = 1,
        .stringsOffset = offsetof(typeof(table), strings), .stringsSize = sizeof(table.strings),
        .entriesOffset = offsetof(typeof(table), entry), .entriesCount = 1,
    };
    wideEntries = true;
    LHSearchCache(&fixture.image, 0x2000, &name, &result, 1);
    assert(result == (void *)0x3000 && taskInfoCalls == 1);

    fixture.image.flags = 0;
    result = NULL;
    LHSearchCache(&fixture.image, 0x2000, &name, &result, 1);
    assert(!result && taskInfoCalls == 1);
    puts("symbol-cache: cache filtering and lookup passed");
    return 0;
}
