// 用接口桩验证真实 roothide 后端的脏范围、权限与回滚校验，不修改宿主代码页。
#include <dlfcn.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../libhooker/mem/shadowMem.h"

static unsigned checks;
static unsigned availableExports = 3, resolutions, legacyPreparations;
static bool legacyAvailable = true;
#define REQUIRE(condition) do { \
    ++checks; \
    if (!(condition)) { \
        fprintf(stderr, "memory-backend failure at %s:%d: %s\n", __FILE__, __LINE__, #condition); \
        abort(); \
    } \
} while (0)

static uint8_t *memory, *original, *replacement, *mask, *scratch;
struct PatchAction { size_t bytes; kern_return_t result; };
static struct {
    vm_prot_t protection;
    unsigned patches, protects, reads, invalidations;
    struct PatchAction actions[4];
    unsigned actionCount;
    unsigned failedProtectionCall;
    bool failedProtectionChanges;
    unsigned failedReadCall, shortReadCall, corruptReadCall;
    bool mutateCleanOnVerification;
    bool driftAfterVerification;
} mock;

// 初始化测试页、原字节、替换数据和独立生成的脏字节位图。
static void resetFixture(vm_prot_t protection) {
    memset(&mock, 0, sizeof(mock));
    mock.protection = protection;
    memset(memory, 0x35, PAGE_SIZE);
    memcpy(original, memory, PAGE_SIZE);
    memset(replacement, 0x91, PAGE_SIZE);
    memset(mask, 0, PAGE_SIZE / 8);
    memset(scratch, 0, PAGE_SIZE * 2);
}

// 逐字节声明目标范围，不复用生产代码的位图合并算法。
static void dirtyRange(size_t start, size_t length) {
    REQUIRE(start <= PAGE_SIZE && length <= PAGE_SIZE - start);
    for (size_t index = start; index < start + length; index++) mask[index / 8] |= 1u << (index % 8);
}

// 模拟 bootstrap 整页提交，支持未写、半写或全写后仍返回失败。
static kern_return_t mockPatch(void *destination, const void *source, size_t size) {
    REQUIRE(destination == memory && size == PAGE_SIZE);
    struct PatchAction action = {size, KERN_SUCCESS};
    if (mock.patches < mock.actionCount) action = mock.actions[mock.patches];
    mock.patches++;
    REQUIRE(action.bytes <= size);
    memcpy(destination, source, action.bytes);
    mock.protection = VM_PROT_READ | VM_PROT_EXECUTE;
    return action.result;
}

// 权限修改桩既可失败且不生效，也可已经生效但返回错误。
static kern_return_t mockProtect(vm_map_t task, mach_vm_address_t address, mach_vm_size_t size,
        boolean_t maximum, vm_prot_t protection) {
    REQUIRE(task == mach_task_self() && address == (uintptr_t)memory && size == PAGE_SIZE && !maximum);
    mock.protects++;
    bool fail = mock.protects == mock.failedProtectionCall;
    if (!fail || mock.failedProtectionChanges) mock.protection = protection;
    return fail ? KERN_FAILURE : KERN_SUCCESS;
}

// 仅向被测源码提供两个 bootstrap 接口，不覆盖宿主进程的动态解析器。
static void *mockDlsym(void *handle, const char *name) {
    REQUIRE(handle == RTLD_DEFAULT);
    resolutions++;
    if (!strcmp(name, "substrate_hook_memory")) return (availableExports & 1) ? (void *)mockPatch : NULL;
    if (!strcmp(name, "substrate_vm_protect")) return (availableExports & 2) ? (void *)mockProtect : NULL;
    REQUIRE(false);
    return NULL;
}

// 返回独立维护的当前权限，读取权限不会触发真实的 Mach 变更。
static kern_return_t mockRegion(vm_map_t task, mach_vm_address_t *address, mach_vm_size_t *size,
        natural_t *depth, vm_region_recurse_info_t info, mach_msg_type_number_t *count) {
    REQUIRE(task == mach_task_self() && *depth == 0 && *count == VM_REGION_SUBMAP_INFO_COUNT_64);
    vm_region_submap_info_64_t output = (vm_region_submap_info_64_t)info;
    memset(output, 0, sizeof(*output));
    *size = PAGE_SIZE;
    output->protection = *address == (uintptr_t)memory ? mock.protection : VM_PROT_READ | VM_PROT_EXECUTE;
    return KERN_SUCCESS;
}

// 模拟回读失败、短读和错误字节；普通数据页的非目标字节可在校验期间继续变化。
static kern_return_t mockRead(vm_map_read_t task, mach_vm_address_t address, mach_vm_size_t size,
        mach_vm_address_t destination, mach_vm_size_t *copied) {
    REQUIRE(task == mach_task_self());
    mock.reads++;
    *copied = 0;
    if (mock.reads == mock.failedReadCall) return KERN_FAILURE;
    if (address == (uintptr_t)memory && mock.reads == 2 && mock.mutateCleanOnVerification) memory[0] ^= 0x11;
    *copied = mock.reads == mock.shortReadCall ? size - 1 : size;
    memcpy((void *)destination, (const void *)address, *copied);
    if (mock.reads == mock.corruptReadCall && *copied > 9) ((uint8_t *)destination)[9] ^= 0xff;
    if (mock.reads == 2 && mock.driftAfterVerification) mock.protection = VM_PROT_READ | VM_PROT_EXECUTE;
    return KERN_SUCCESS;
}

// 指令缓存维护只记录调用，不对宿主执行页做任何操作。
static void mockInvalidate(void *address, size_t size) { (void)address; (void)size; mock.invalidations++; }

// 旧版后端的设备行为另做真机验证；此处只验证完整选择与初始化缓存。
static bool mockPrepareLegacy(void) { legacyPreparations++; return legacyAvailable; }

#define LHPrepareLegacyMemory mockPrepareLegacy
#define LHLegacyProtect mockProtect
#define LHLegacyPatch mockPatch
#define dlsym mockDlsym
#define mach_vm_region_recurse mockRegion
#define mach_vm_protect mockProtect
#define mach_vm_read_overwrite mockRead
#define sys_icache_invalidate mockInvalidate
#include "../libhooker/mem/writeMem-roothide.c"
#undef dlsym
#undef mach_vm_region_recurse
#undef mach_vm_protect
#undef mach_vm_read_overwrite
#undef sys_icache_invalidate
#undef LHPrepareLegacyMemory
#undef LHLegacyProtect
#undef LHLegacyPatch

// 普通 RW 页只改脏字节，邻接字节及权限保持原值，不调用 bootstrap 整页补丁。
static void testDirtyRanges(void) {
    for (size_t offset = 0; offset < 8; offset++) {
        for (size_t length = 1; length <= 17; length++) {
            resetFixture(VM_PROT_READ | VM_PROT_WRITE);
            dirtyRange(32 + offset, length);
            dirtyRange(PAGE_SIZE - length, length);
            REQUIRE(LHCommitMemoryRanges((uintptr_t)memory, replacement, PAGE_SIZE, mask, mock.protection));
            for (size_t index = 0; index < PAGE_SIZE; index++) {
                bool dirty = (index >= 32 + offset && index < 32 + offset + length) || index >= PAGE_SIZE - length;
                REQUIRE(memory[index] == (dirty ? 0x91 : 0x35));
            }
            REQUIRE(!mock.patches && !mock.protects && mock.protection == (VM_PROT_READ | VM_PROT_WRITE));
        }
    }
}

// 代码、只读及 RWX 页提交后必须恢复快照权限；提交前权限漂移直接拒绝。
static void testCommitProtection(void) {
    const vm_prot_t protections[] = {VM_PROT_READ, VM_PROT_READ | VM_PROT_EXECUTE,
        VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE};
    for (unsigned index = 0; index < sizeof(protections) / sizeof(*protections); index++) {
        resetFixture(protections[index]);
        dirtyRange(8, 8);
        REQUIRE(LHCommitMemoryRanges((uintptr_t)memory, replacement, PAGE_SIZE, mask, protections[index]));
        REQUIRE(mock.patches == 1 && mock.protection == protections[index] && mock.invalidations == 1);
    }
    resetFixture(VM_PROT_READ);
    REQUIRE(!LHCommitMemoryRanges((uintptr_t)memory, replacement, PAGE_SIZE, mask, VM_PROT_READ | VM_PROT_EXECUTE));
    REQUIRE(!mock.patches && !mock.protects);
    resetFixture(VM_PROT_READ);
    mock.failedProtectionCall = 1;
    REQUIRE(!LHCommitMemoryRanges((uintptr_t)memory, replacement, PAGE_SIZE, mask, VM_PROT_READ));
    REQUIRE(mock.patches == 1 && mock.protection == (VM_PROT_READ | VM_PROT_EXECUTE));
}

// 提交返回错误也必须尽力恢复原权限，再由上层决定是否回滚字节。
static void testPartialCommit(void) {
    const size_t amounts[] = {0, PAGE_SIZE / 2, PAGE_SIZE};
    for (unsigned index = 0; index < 3; index++) {
        resetFixture(VM_PROT_READ);
        dirtyRange(0, PAGE_SIZE);
        mock.actions[0] = (struct PatchAction){amounts[index], KERN_FAILURE};
        mock.actionCount = 1;
        REQUIRE(!LHCommitMemoryRanges((uintptr_t)memory, replacement, PAGE_SIZE, mask, VM_PROT_READ));
        REQUIRE(mock.protection == VM_PROT_READ);
        REQUIRE(LHRestoreMemoryRanges((uintptr_t)memory, original, PAGE_SIZE, mask, VM_PROT_READ, scratch));
        REQUIRE(!memcmp(memory, original, PAGE_SIZE) && mock.protection == VM_PROT_READ);
    }
}

// 恢复只采用原始脏字节，不能覆盖本次提交后产生的非目标变化。
static void testRestorePreservesLiveBytes(void) {
    const vm_prot_t protections[] = {VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_EXECUTE};
    for (unsigned index = 0; index < 2; index++) {
        resetFixture(protections[index]);
        dirtyRange(8, 8);
        memset(memory + 8, 0x91, 8);
        memory[0] = 0xa7;
        mock.mutateCleanOnVerification = index == 0;
        REQUIRE(LHRestoreMemoryRanges((uintptr_t)memory, original, PAGE_SIZE, mask, protections[index], scratch));
        REQUIRE(memory[0] == (index == 0 ? (0xa7 ^ 0x11) : 0xa7));
        REQUIRE(!memcmp(memory + 8, original + 8, 8));
        REQUIRE(mock.protection == protections[index]);
    }
}

// 错误码不能代替最终字节与权限校验，完整恢复后报错仍可确认恢复成功。
static void testRestoreReportedErrors(void) {
    resetFixture(VM_PROT_READ);
    dirtyRange(0, PAGE_SIZE);
    memset(memory, 0x91, PAGE_SIZE);
    mock.actions[0] = (struct PatchAction){PAGE_SIZE, KERN_FAILURE};
    mock.actionCount = 1;
    mock.failedProtectionCall = 1;
    mock.failedProtectionChanges = true;
    REQUIRE(LHRestoreMemoryRanges((uintptr_t)memory, original, PAGE_SIZE, mask, VM_PROT_READ, scratch));
    REQUIRE(!memcmp(memory, original, PAGE_SIZE) && mock.protection == VM_PROT_READ);
}

// 恢复部分写、权限失败、短读、回读失败、内容不符和最终权限漂移都不能报告成功。
static void testRestoreFailures(void) {
    for (unsigned failure = 0; failure < 7; failure++) {
        resetFixture(VM_PROT_READ);
        dirtyRange(0, PAGE_SIZE);
        memset(memory, 0x91, PAGE_SIZE);
        if (failure == 0) { mock.actions[0] = (struct PatchAction){PAGE_SIZE / 2, KERN_FAILURE}; mock.actionCount = 1; }
        if (failure == 1) mock.failedProtectionCall = 1;
        if (failure == 2) mock.failedReadCall = 1;
        if (failure == 3) mock.failedReadCall = 2;
        if (failure == 4) mock.shortReadCall = 2;
        if (failure == 5) mock.corruptReadCall = 2;
        if (failure == 6) mock.driftAfterVerification = true;
        REQUIRE(!LHRestoreMemoryRanges((uintptr_t)memory, original, PAGE_SIZE, mask, VM_PROT_READ, scratch));
    }
}

// 使用真实页大小及普通堆内存运行后端回归，所有权限操作均经过桩。
int main(int argc, char **argv) {
    REQUIRE(!posix_memalign((void **)&memory, PAGE_SIZE, PAGE_SIZE));
    original = malloc(PAGE_SIZE); replacement = malloc(PAGE_SIZE);
    mask = malloc(PAGE_SIZE / 8); scratch = malloc(PAGE_SIZE * 2);
    REQUIRE(original && replacement && mask && scratch);
    if (argc > 1) {
        availableExports = !strcmp(argv[1], "partial-patch") ? 1 : !strcmp(argv[1], "partial-protect") ? 2 : 0;
        legacyAvailable = strcmp(argv[1], "unavailable") != 0;
        if (availableExports || !legacyAvailable) {
            resetFixture(VM_PROT_READ | VM_PROT_EXECUTE);
            dirtyRange(8, 8);
            REQUIRE(!LHCommitMemoryRanges((uintptr_t)memory, replacement, PAGE_SIZE, mask, mock.protection));
            REQUIRE(!mock.patches && !memcmp(memory, original, PAGE_SIZE));
            REQUIRE(legacyPreparations == (availableExports ? 0 : 1));
            // 尚未成功选择后端时允许稍后出现的完整接口恢复工作。
            availableExports = 3;
        }
    }
    testDirtyRanges();
    testCommitProtection();
    testPartialCommit();
    testRestorePreservesLiveBytes();
    testRestoreReportedErrors();
    testRestoreFailures();
    REQUIRE(legacyPreparations == (availableExports ? (legacyAvailable ? 0 : 1) : 1));
    if (!availableExports) REQUIRE(resolutions == 2);
    free(memory); free(original); free(replacement); free(mask); free(scratch);
    printf("PASS memory backend dirty ranges, protection and verified rollback: %u checks\n", checks);
    return 0;
}
