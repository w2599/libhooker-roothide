// iOS 16+ 的镜像与符号解析，不解码 dyld 私有句柄。
#include "dyldSyms.h"
#include "macho-symbols.h"
#include "funcMacros.h"
#include "dyld_cache_format.h"
#include <dispatch/dispatch.h>
#include <dlfcn.h>
#include <fcntl.h>
#include <limits.h>
#include <mach/mach.h>
#include <mach-o/dyld.h>
#include <mach-o/dyld_images.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <ptrauth.h>
#include <stdatomic.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

static const struct dyld_cache_header *cacheHeader;
static const uint8_t *localSymbols;
static struct dyld_cache_local_symbols_info localInfo;
static bool wideEntries;
static bool entriesOrdered;
static uint32_t *entryOrder;

typedef const void *(*LHDlopenHeaderLookup)(void *);
typedef void (*LHDyldLockAction)(void);
struct LHDyldOpenLock { LHDyldLockAction lock, unlock; };

// 旧 dyld 的 NOLOAD 增引用与 dlclose 减引用使用不同锁，补上同一递归 API 锁。
static struct LHDyldOpenLock LHGetDyldOpenLock(void) {
    // 这两个 SPI 只拿/放 dlopen 的递归锁，不执行 fork 或重置锁状态。
    LHDyldLockAction lock = dlsym(RTLD_DEFAULT, "_dyld_dlopen_atfork_prepare");
    LHDyldLockAction unlock = dlsym(RTLD_DEFAULT, "_dyld_dlopen_atfork_parent");
    if (!lock || !unlock) return (struct LHDyldOpenLock){0};
    return (struct LHDyldOpenLock){lock, unlock};
}

// 从已验证的映射读取条目，兼容未对齐的两种磁盘布局。
static struct dyld_cache_local_symbols_entry_64 LHCacheEntry(uint32_t index) {
    const uint8_t *entries = localSymbols + localInfo.entriesOffset;
    if (wideEntries) {
        struct dyld_cache_local_symbols_entry_64 entry;
        memcpy(&entry, entries + (size_t)index * sizeof(entry), sizeof(entry));
        return entry;
    }
    struct dyld_cache_local_symbols_entry entry;
    memcpy(&entry, entries + (size_t)index * sizeof(entry), sizeof(entry));
    return (struct dyld_cache_local_symbols_entry_64){entry.dylibOffset, entry.nlistStartIndex, entry.nlistCount};
}

// 排序时以原序号打破平局，保留顺序扫描对重复偏移的首次匹配。
static int LHCompareCacheEntries(const void *left, const void *right) {
    uint32_t a = *(const uint32_t *)left, b = *(const uint32_t *)right;
    uint64_t x = LHCacheEntry(a).dylibOffset, y = LHCacheEntry(b).dylibOffset;
    if (x != y) return x < y ? -1 : 1;
    return (a > b) - (a < b);
}

// 在映射初始化期间建立只读查找顺序；有序表直接使用映射，分配失败保留顺序查询。
static void LHIndexCacheEntries(void) {
    uint64_t previous = 0;
    for (uint32_t i = 0; i < localInfo.entriesCount; i++) {
        uint64_t offset = LHCacheEntry(i).dylibOffset;
        if (offset < previous) {
            entryOrder = calloc(localInfo.entriesCount, sizeof(*entryOrder));
            if (!entryOrder) return;
            for (uint32_t j = 0; j < localInfo.entriesCount; j++) entryOrder[j] = j;
            qsort(entryOrder, localInfo.entriesCount, sizeof(*entryOrder), LHCompareCacheEntries);
            break;
        }
        previous = offset;
    }
    entriesOrdered = true;
}

// 返回第一个匹配的条目；未命中时返回条目总数。
static uint32_t LHFindCacheEntry(uint64_t imageOffset) {
    uint32_t end = localInfo.entriesCount;
    if (!entriesOrdered) {
        for (uint32_t i = 0; i < end; i++)
            if (LHCacheEntry(i).dylibOffset == imageOffset) return i;
        return end;
    }
    uint32_t first = 0, last = end;
    while (first < last) {
        uint32_t mid = first + (last - first) / 2;
        uint32_t index = entryOrder ? entryOrder[mid] : mid;
        if (LHCacheEntry(index).dylibOffset < imageOffset) first = mid + 1;
        else last = mid;
    }
    if (first == end) return end;
    uint32_t index = entryOrder ? entryOrder[first] : first;
    return LHCacheEntry(index).dylibOffset == imageOffset ? index : end;
}

// 读取磁盘共享缓存的符号区并核对运行中缓存的 UUID。
static bool LHMapLocalSymbols(const char *path, bool separate) {
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0) return false;
    struct stat st;
    // 只读各代共有的固定前缀，旧缓存无需包含当前结构体的全部尾部字段。
    struct dyld_cache_header header = {0};
    const size_t prefixSize = offsetof(struct dyld_cache_header, uuid) + sizeof(header.uuid);
    bool valid = fstat(fd, &st) == 0 && st.st_size >= 0 &&
        pread(fd, &header, prefixSize, 0) == prefixSize &&
        !memcmp(header.magic, "dyld_v1 ", 8) &&
        header.mappingOffset >= prefixSize && header.mappingOffset <= (uint64_t)st.st_size &&
        header.localSymbolsOffset >= header.mappingOffset &&
        !memcmp(header.uuid, separate ? cacheHeader->symbolFileUUID : cacheHeader->uuid, 16) &&
        LHRange(header.localSymbolsOffset, header.localSymbolsSize, 1, st.st_size) &&
        header.localSymbolsSize >= sizeof(localInfo);
    if (!valid) { close(fd); return false; }
    size_t mask = getpagesize() - 1;
    off_t offset = header.localSymbolsOffset & ~mask;
    size_t delta = header.localSymbolsOffset - offset;
    if (header.localSymbolsSize > SIZE_MAX - delta) { close(fd); return false; }
    size_t length = delta + header.localSymbolsSize;
    void *map = mmap(NULL, length, PROT_READ, MAP_PRIVATE, fd, offset);
    close(fd);
    if (map == MAP_FAILED) return false;
    const uint8_t *data = (const uint8_t *)map + delta;
    struct dyld_cache_local_symbols_info info;
    memcpy(&info, data, sizeof(info));
    // 与 dyld 一致按文件头版本判定条目宽度，内嵌符号区同样可能使用 64 位偏移。
    bool wide = header.mappingOffset >= offsetof(struct dyld_cache_header, symbolFileUUID);
    size_t entrySize = wide ? sizeof(struct dyld_cache_local_symbols_entry_64) :
                             sizeof(struct dyld_cache_local_symbols_entry);
    valid = LHRange(info.nlistOffset, info.nlistCount, sizeof(struct nlist_64), header.localSymbolsSize) &&
        LHRange(info.stringsOffset, info.stringsSize, 1, header.localSymbolsSize) &&
        LHRange(info.entriesOffset, info.entriesCount, entrySize, header.localSymbolsSize);
    if (!valid) { munmap(map, length); return false; }
    localSymbols = data;
    localInfo = info;
    wideEntries = wide;
    LHIndexCacheEntries();
    return true;
}

// 尝试主缓存或独立 .symbols 文件。
static bool LHTryCachePath(const char *base, bool separate) {
    if (!base) return false;
    char path[PATH_MAX];
    int length = snprintf(path, sizeof(path), "%s%s", base, separate ? ".symbols" : "");
    return length > 0 && length < sizeof(path) && LHMapLocalSymbols(path, separate);
}

// 延迟映射符号区；缺失符号文件时仍可查询导出符号。
static void LHLoadLocalSymbols(void) {
    static dispatch_once_t once;
    static atomic_bool initialized;
    if (atomic_load_explicit(&initialized, memory_order_acquire)) return;
    // dyld 查询放在 once 外，避免另一线程的镜像构造函数反向等待该 once。
    const char *(*cachePath)(void) = dlsym(RTLD_DEFAULT, "dyld_shared_cache_file_path");
    const char *basePath = cachePath ? cachePath() : NULL;
    dispatch_once(&once, ^{
        struct task_dyld_info taskInfo;
        mach_msg_type_number_t count = TASK_DYLD_INFO_COUNT;
        if (task_info(mach_task_self(), TASK_DYLD_INFO, (task_info_t)&taskInfo, &count) != KERN_SUCCESS) return;
        const struct dyld_all_image_infos *infos = (const void *)taskInfo.all_image_info_addr;
        cacheHeader = (const void *)infos->sharedCacheBaseAddress;
        if (!cacheHeader || memcmp(cacheHeader->magic, "dyld_v1 ", 8)) { cacheHeader = NULL; return; }
        uint8_t zeroUUID[16] = {0};
        bool separate = cacheHeader->mappingOffset >= offsetof(struct dyld_cache_header, symbolFileUUID) + 16 &&
            memcmp(cacheHeader->symbolFileUUID, zeroUUID, 16);
        if (LHTryCachePath(basePath, separate)) return;
        char arch[9] = {0};
        memcpy(arch, cacheHeader->magic + 8, 8);
        const char *architecture = arch;
        while (*architecture == ' ') architecture++;
        const char *directories[] = {
            "/System/Cryptexes/OS/System/Library/Caches/com.apple.dyld/",
            "/System/Library/Caches/com.apple.dyld/",
        };
        for (unsigned i = 0; i < sizeof(directories) / sizeof(*directories); i++) {
            char base[PATH_MAX];
            snprintf(base, sizeof(base), "%sdyld_shared_cache_%s", directories[i], architecture);
            if (LHTryCachePath(base, separate)) return;
        }
    });
    atomic_store_explicit(&initialized, true, memory_order_release);
}

// 查找共享缓存中被剥离的本地符号。
static void LHSearchCache(const void *image, uintptr_t slide, const char **names, void **results, size_t count) {
    // 普通镜像没有共享缓存符号，避免为缺失查询初始化并遍历缓存。
    if (!(((const struct mach_header_64 *)image)->flags & MH_DYLIB_IN_CACHE)) return;
    LHLoadLocalSymbols();
    if (!localSymbols || !cacheHeader || (uintptr_t)image < (uintptr_t)cacheHeader) return;
    uint64_t imageOffset = (uintptr_t)image - (uintptr_t)cacheHeader;
    uint32_t index = LHFindCacheEntry(imageOffset);
    if (index == localInfo.entriesCount) return;
    struct dyld_cache_local_symbols_entry_64 entry = LHCacheEntry(index);
    if (!LHRange(entry.nlistStartIndex, entry.nlistCount, 1, localInfo.nlistCount)) return;
    const uint8_t *symbols = localSymbols + localInfo.nlistOffset + (size_t)entry.nlistStartIndex * sizeof(struct nlist_64);
    LHSearchTable(image, slide, (const void *)symbols, entry.nlistCount,
        (const char *)localSymbols + localInfo.stringsOffset, localInfo.stringsSize, names, results, count);
}

// 取得拥有引用的句柄后读取镜像；FIRST 排除没有显式重导出的普通依赖。
static struct libhooker_image *LHOpenImageWithFlags(const char *path, int flags) {
    if (!path) return NULL;
    struct LHDyldOpenLock openLock = {0};
    if (flags & RTLD_NOLOAD) openLock = LHGetDyldOpenLock();
    if (openLock.lock) openLock.lock();
    void *handle = dlopen(path, RTLD_LAZY | RTLD_LOCAL | RTLD_FIRST | flags);
    if (openLock.lock) openLock.unlock();
    if (!handle) return NULL;
    LHDlopenHeaderLookup getHeader = dlsym(RTLD_DEFAULT, "_dyld_get_dlopen_image_header");
    const void *header = getHeader ? getHeader(handle) : NULL;
    uintptr_t slide = LHImageSlide(header);
    if (slide == UINTPTR_MAX) { dlclose(handle); return NULL; }
    struct libhooker_image *image = malloc(sizeof(*image));
    if (!image) { dlclose(handle); return NULL; }
    *image = (struct libhooker_image){
        .imageHeader = header, .slide = slide, .dyldHandle = handle,
    };
    return image;
}

// 打开指定镜像，供公开接口持有其加载生命周期。
LIBHOOKER_EXPORT struct libhooker_image *LHOpenImage(const char *path) {
    return LHOpenImageWithFlags(path, 0);
}

// 只取得已经加载的镜像引用，不因兼容符号查找额外加载插件。
struct libhooker_image *LHOpenLoadedImage(const char *path) {
    return LHOpenImageWithFlags(path, RTLD_NOLOAD);
}

// 释放通过 LHOpenImage 获取的引用。
LIBHOOKER_EXPORT void LHCloseImage(struct libhooker_image *image) {
    if (!image) return;
    if (image->dyldHandle) dlclose(image->dyldHandle);
    free(image);
}

// 用 dyld 的地址归属查询排除来自普通依赖或重导出的候选。
static bool LHSymbolBelongsToImage(const struct libhooker_image *image, void *symbol) {
    if (!symbol) return false;
    const void *address = ptrauth_strip(symbol, ptrauth_key_function_pointer);
    Dl_info info = {0};
    return dladdr(address, &info) && info.dli_fbase == image->imageHeader;
}

// 本镜像符号优先；显式重导出仅作回退，普通依赖不参与指定镜像查找。
LIBHOOKER_EXPORT bool LHFindSymbols(struct libhooker_image *image, const char **names, void **results, size_t count) {
    if (!count) return true;
    if (!results || !names || count > SIZE_MAX / sizeof(void *)) return false;
    memset(results, 0, count * sizeof(void *));
    if (!image || !image->imageHeader || image->slide == UINTPTR_MAX) return false;
    if (image->dyldHandle) {
        for (size_t i = 0; i < count; i++) {
            if (!names[i]) continue;
            void *symbol = dlsym(image->dyldHandle, names[i][0] == '_' ? names[i] + 1 : names[i]);
            if (LHSymbolBelongsToImage(image, symbol)) results[i] = symbol;
        }
    }
    bool found = LHAllSymbolsFound(results, count);
    if (!found) {
        LHSearchImage(image->imageHeader, image->slide, names, results, count);
        found = LHAllSymbolsFound(results, count);
    }
    if (!found) {
        LHSearchCache(image->imageHeader, image->slide, names, results, count);
        if (image->dyldHandle) {
            for (size_t i = 0; i < count; i++) {
                if (!results[i] && names[i])
                    results[i] = dlsym(image->dyldHandle, names[i][0] == '_' ? names[i] + 1 : names[i]);
            }
        }
        found = LHAllSymbolsFound(results, count);
    }
    return found;
}
