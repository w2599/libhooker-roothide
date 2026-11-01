// roothide 内存后端；沿用 libhooker 的 API，不依赖 ElleKit 引擎。
#include "funcMacros.h"
#include "writeMem.h"
#include "shadowMem.h"
#include "threadSafety.h"
#include "legacy-memory.h"
#include <dlfcn.h>
#include <errno.h>
#include <ptrauth.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdatomic.h>
#include <string.h>
#include <sys/mman.h>

typedef kern_return_t (*LHProtect)(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
typedef kern_return_t (*LHPatch)(void *, const void *, size_t);
struct LHMemoryBackend { LHProtect protect; LHPatch patch; };

// 仅缓存进程期接口的成功地址；解析不持本地锁，允许加载构造重入及缺失重试。
static struct LHMemoryBackend LHInitializeMemory(void) {
    static _Atomic(LHProtect) cachedProtect;
    static _Atomic(LHPatch) cachedPatch;
    static atomic_bool cachedLegacy;
    if (atomic_load_explicit(&cachedLegacy, memory_order_acquire)) {
        return (struct LHMemoryBackend){LHLegacyProtect, LHLegacyPatch};
    }
    LHProtect protect = atomic_load_explicit(&cachedProtect, memory_order_relaxed);
    if (!protect) {
        protect = (LHProtect)dlsym(RTLD_DEFAULT, "substrate_vm_protect");
        if (protect) atomic_store_explicit(&cachedProtect, protect, memory_order_relaxed);
    }
    LHPatch patch = atomic_load_explicit(&cachedPatch, memory_order_relaxed);
    if (!patch) {
        patch = (LHPatch)dlsym(RTLD_DEFAULT, "substrate_hook_memory");
        if (patch) atomic_store_explicit(&cachedPatch, patch, memory_order_relaxed);
    }
    // 旧版没有这两个导出；完整使用本地后端，避免混用不完整的服务接口。
    if (!protect && !patch && LHPrepareLegacyMemory()) {
        atomic_store_explicit(&cachedLegacy, true, memory_order_release);
        return (struct LHMemoryBackend){LHLegacyProtect, LHLegacyPatch};
    }
    return (struct LHMemoryBackend){protect, patch};
}

// 递归进入共享缓存的子映射，避免把外层只读权限误当成代码页权限。
static bool LHGetProtection(uintptr_t page, vm_prot_t *protection) {
    natural_t depth = 0;
    for (;;) {
        mach_vm_address_t address = page;
        mach_vm_size_t size = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t kr = mach_vm_region_recurse(mach_task_self(), &address, &size,
            &depth, (vm_region_recurse_info_t)&info, &count);
        if (kr != KERN_SUCCESS || address > page || page - address >= size) return false;
        if (info.is_submap) { depth++; continue; }
        *protection = info.protection;
        return true;
    }
}

// 向影子事务提供当前页权限，不暴露为公开 Hook 接口。
bool LHGetMemoryProtection(uintptr_t page, uint32_t *protection) {
    if (!page || (page & PAGE_MASK) || !protection) return false;
    vm_prot_t current;
    if (!LHGetProtection(page, &current)) return false;
    *protection = (uint32_t)current;
    return true;
}

// 有界读取目标内容，内核未复制完整范围时拒绝使用快照。
static bool LHReadMemory(uintptr_t address, void *data, size_t size) {
    mach_vm_size_t copied = 0;
    return mach_vm_read_overwrite(mach_task_self(), address, size,
        (mach_vm_address_t)data, &copied) == KERN_SUCCESS && copied == size;
}

// 每次提交都在暂停线程前准备依赖，不能在暂停期间触发首次动态解析。
bool LHPrepareMemory(void) {
    struct LHMemoryBackend backend = LHInitializeMemory();
    vm_prot_t protection;
    uintptr_t address = (uintptr_t)ptrauth_strip(&LHPrepareMemory, ptrauth_key_function_pointer);
    sys_icache_invalidate((void *)address, 0);
    if (!backend.patch || !backend.protect ||
        !LHGetProtection(address & ~PAGE_MASK, &protection)) return false;
    uint8_t byte, copiedByte;
    if (!LHReadMemory(address, &byte, sizeof(byte))) return false;
    // 间接调用阻止编译器消去预热；回滚比较使用内联逐字节读取，不进入 libc。
    void *(*volatile copyMemory)(void *, const void *, size_t) = memcpy;
    copyMemory(&copiedByte, &byte, sizeof(byte));
    return true;
}

// 调整匿名 trampoline 页权限；已签名代码的修改交给 bootstrap。
static bool LHProtectMemory(void *data, size_t size, vm_prot_t protection) {
    struct LHMemoryBackend backend = LHInitializeMemory();
    LHProtect protect = backend.protect ?: mach_vm_protect;
    return protect(mach_task_self(), (mach_vm_address_t)data, size, false, protection) == KERN_SUCCESS;
}

// 将 trampoline 页切换为可写。
bool LHMarkMemoryWriteable(void *data) {
    return data && LHProtectMemory((void *)((uintptr_t)data & ~PAGE_MASK), PAGE_SIZE,
                                  VM_PROT_READ | VM_PROT_WRITE);
}

// 刷新指令缓存后将 trampoline 页切换为可执行。
bool LHMarkMemoryExecutable(void *data) {
    if (!data) return false;
    void *page = (void *)((uintptr_t)data & ~PAGE_MASK);
    sys_icache_invalidate(page, PAGE_SIZE);
    return LHProtectMemory(page, PAGE_SIZE, VM_PROT_READ | VM_PROT_EXECUTE);
}

// 创建任意大小的可执行缓冲区，失败时不留下半初始化的输出指针。
LIBHOOKER_EXPORT bool LHExecMemory(void **page, void *data, size_t size) {
    if (!page) return false;
    *page = NULL;
    if (!data || !size || size > SIZE_MAX - PAGE_MASK) return false;
    size_t allocation = (size + PAGE_MASK) & ~PAGE_MASK;
    void *buffer = mmap(NULL, allocation, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (buffer == MAP_FAILED) return false;
    memcpy(buffer, data, size);
    sys_icache_invalidate(buffer, size);
    if (!LHProtectMemory(buffer, allocation, VM_PROT_READ | VM_PROT_EXECUTE)) {
        munmap(buffer, allocation);
        return false;
    }
    *page = buffer;
    return true;
}

// 仅提交明确修改的连续字节，避免把提交线程自己的栈和同页状态恢复为旧快照。
static void LHCopyDirtyRanges(uint8_t *destination, const uint8_t *data, const uint8_t *mask, size_t size) {
    size_t offset = 0;
    while (offset < size) {
        if (!mask[offset / 8]) { offset = (offset + 8) & ~(size_t)7; continue; }
        if (!(mask[offset / 8] & (1u << (offset & 7)))) { offset++; continue; }
        size_t start = offset++;
        while (offset < size && (mask[offset / 8] & (1u << (offset & 7)))) {
            if (!(offset & 7) && mask[offset / 8] == 0xff) offset += 8;
            else offset++;
        }
        memcpy(destination + start, data + start, offset - start);
    }
}

// 恢复快照记录的权限，并根据实际结果判断，避免后端错误码掩盖已完成的修改。
static bool LHRestoreProtection(struct LHMemoryBackend backend, uintptr_t page, size_t size, vm_prot_t protection) {
    vm_prot_t current;
    if (LHGetProtection(page, &current) && current == protection) return true;
    backend.protect(mach_task_self(), page, size, false, protection);
    return LHGetProtection(page, &current) && current == protection;
}

// 按快照权限提交；拒绝权限漂移，底层失败后仍尝试恢复原权限。
bool LHCommitMemoryRanges(uintptr_t page, const void *data, size_t size, const uint8_t *mask, uint32_t protection) {
    if (!page || !data || !mask || (page & PAGE_MASK) || size != PAGE_SIZE) return false;
    struct LHMemoryBackend backend = LHInitializeMemory();
    if (!backend.patch || !backend.protect) {
        errno = ENOTSUP;
        return false;
    }
    vm_prot_t current;
    if (!LHGetProtection(page, &current) || current != (vm_prot_t)protection) return false;
    // 普通可写数据页无需临时切换成代码页；直接提交可避免不必要的 COW/RX 变更。
    if ((protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == VM_PROT_WRITE) {
        LHCopyDirtyRanges((void *)page, data, mask, size);
        return true;
    }
    kern_return_t kr = backend.patch((void *)page, data, size);
    bool restoredProtection = LHRestoreProtection(backend, page, size, (vm_prot_t)protection);
    sys_icache_invalidate((void *)page, size);
    return kr == KERN_SUCCESS && restoredProtection;
}

// 比较回滚结果；普通可写页只检查脏字节，避免提交线程栈变化造成误判。
static bool LHRestoredBytesMatch(const uint8_t *expected, const uint8_t *actual,
        const uint8_t *mask, size_t size, bool writableData) {
    const volatile uint8_t *expectedBytes = expected, *actualBytes = actual;
    for (size_t offset = 0; offset < size; offset++) {
        if (writableData && !(mask[offset / 8] & (1u << (offset & 7)))) continue;
        if (expectedBytes[offset] != actualBytes[offset]) return false;
    }
    return true;
}

// 用实时非目标字节和事务原始脏字节回滚，双页 scratch 由暂停线程前的调用方准备。
bool LHRestoreMemoryRanges(uintptr_t page, const void *original, size_t size,
        const uint8_t *mask, uint32_t protection, void *scratch) {
    if (!page || !original || !mask || !scratch || (page & PAGE_MASK) || size != PAGE_SIZE) return false;
    struct LHMemoryBackend backend = LHInitializeMemory();
    if (!backend.patch || !backend.protect) {
        errno = ENOTSUP;
        return false;
    }
    // 提交可能已经改变权限；恢复读取能力后再合并，不能使用旧的整页快照覆盖实时状态。
    if (!LHRestoreProtection(backend, page, size, (vm_prot_t)protection)) return false;
    uint8_t *expected = scratch, *actual = expected + size;
    if (!LHReadMemory(page, expected, size)) return false;
    LHCopyDirtyRanges(expected, original, mask, size);
    bool writableData = (protection & (VM_PROT_WRITE | VM_PROT_EXECUTE)) == VM_PROT_WRITE;
    if (writableData) LHCopyDirtyRanges((void *)page, expected, mask, size);
    else {
        // 错误返回也可能已完成全部或部分写入，始终恢复权限并以回读结果为准。
        backend.patch((void *)page, expected, size);
        bool restoredProtection = LHRestoreProtection(backend, page, size, (vm_prot_t)protection);
        sys_icache_invalidate((void *)page, size);
        if (!restoredProtection) return false;
    }
    if (!LHReadMemory(page, actual, size) || !LHRestoredBytesMatch(expected, actual, mask, size, writableData)) return false;
    vm_prot_t current;
    return LHGetProtection(page, &current) && current == (vm_prot_t)protection;
}
