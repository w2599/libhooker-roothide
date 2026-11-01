// 独立进程中的真实 bootstrap 回滚回归，仅改写本程序自有函数与匿名页。
#include "libhooker.h"
#include "../libhooker/mem/writeMem.h"
#include <dlfcn.h>
#include "../libhooker/mem/legacy-memory.h"
#include <errno.h>
#include <libkern/OSCacheControl.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <ptrauth.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>

#define LH_TEST_PAGES 3

typedef kern_return_t (*LHTestPatchBackend)(void *, const void *, size_t);
typedef kern_return_t (*LHTestProtectBackend)(vm_map_t, mach_vm_address_t, mach_vm_size_t, boolean_t, vm_prot_t);
typedef int (*LHTestFunction)(int);

struct LHTestCase {
    const char *name;
    unsigned failAt;
    bool writeBeforeFailure;
    bool changeProtection;
    bool failRollback;
    bool duplicateOutput;
    bool headerChain;
    bool failOutputRestore;
    bool functionBranches;
    bool legacySelfPage;
};

static const struct LHTestCase cases[] = {
    {"batch-success", 0, false, false, false, false, false, false},
    {"fail-first", 1, false, false, false, false, false, false},
    {"fail-middle", 2, false, false, false, false, false, false},
    {"fail-last", 3, false, false, false, false, false, false},
    {"fail-after-write", 2, true, false, false, false, false, false},
    {"fail-after-write-protection", 2, true, true, false, false, false, false},
    {"rollback-failure", 2, true, false, true, false, false, false},
    {"duplicate-success", 0, false, false, false, true, false, false},
    {"duplicate-rollback", 2, true, false, false, true, false, false},
    {"header-chain-rollback", 2, true, false, false, false, true, false},
    {"header-chain-pointer-failure", 2, true, false, false, false, true, true},
    {"header-relay-publish-failure", 1, true, false, false, false, true, false},
    {"function-branches", .functionBranches = true},
    {"legacy-self-page", .legacySelfPage = true}
};

static LHTestPatchBackend realPatch;
static LHTestProtectBackend realProtect;
static const struct LHTestCase *selected;
static uint8_t *functionPages;
static size_t pageSize;
static bool armed, forwardFailed, injectedWriteSucceeded, injectedProtectionSucceeded;
static unsigned forwardCalls, rollbackCalls, checks, failures;
static const char *firstFailure;
static uintptr_t headerPage, headerTargetPage, headerTarget;
static void **headerOutputs;
static bool outputProtectionInjected;
static void *headerOutputSentinel;
static bool headerOutputsUnpublishedAtFailure;
static unsigned nearAllocationsRejected;

// 用两条固定指令构造真实 Mach-O 短函数，不依赖编译器是否插入 PAC 前缀。
extern int LHTestHeaderTarget(int value);
__asm__(".text\n.p2align 2\n.globl _LHTestHeaderTarget\n"
    "_LHTestHeaderTarget:\nadd w0, w0, #31\nret\n");

// 明确初始化双 IP，验证原调用不会提前覆盖后续指令需要的寄存器。
extern int LHTestCallWithIP(LHTestFunction function, int value);
__asm__(".text\n.p2align 2\n.globl _LHTestCallWithIP\n_LHTestCallWithIP:\n"
    "stp x29, x30, [sp, #-16]!\nmov x29, sp\nmov x9, x0\nmov w0, w1\n"
    "mov x16, #11\nmov x17, #31\n"
#if __arm64e__
    "blraaz x9\n"
#else
    "blr x9\n"
#endif
    "ldp x29, x30, [sp], #16\nret\n");

// 只匹配专门注册的完整匿名函数页，不向宿主或系统镜像注入故障。
static bool isRegisteredPage(const void *address, size_t size) {
    uintptr_t value = (uintptr_t)address, first = (uintptr_t)functionPages;
    if (selected->headerChain)
        return size == pageSize && (value == headerPage || value == headerTargetPage);
    return functionPages && size == pageSize && value >= first &&
        value - first < pageSize * LH_TEST_PAGES && (value - first) % pageSize == 0;
}

// 仅在已注册页上模拟未写失败、已写失败和回滚失败，暂停区不分配或输出。
static kern_return_t testPatch(void *destination, const void *source, size_t size) {
    if (!armed || !isRegisteredPage(destination, size)) return realPatch(destination, source, size);
    if (forwardFailed) {
        rollbackCalls++;
        if (selected->failRollback) return KERN_FAILURE;
        kern_return_t result = realPatch(destination, source, size);
        if (result == KERN_SUCCESS && selected->failOutputRestore &&
                (uintptr_t)destination == headerTargetPage && !outputProtectionInjected) {
            outputProtectionInjected = realProtect(mach_task_self(), (mach_vm_address_t)headerOutputs,
                pageSize, false, VM_PROT_READ) == KERN_SUCCESS;
        }
        return result;
    }
    forwardCalls++;
    if (!selected->failAt || forwardCalls != selected->failAt) return realPatch(destination, source, size);
    forwardFailed = true;
    if (selected->headerChain)
        headerOutputsUnpublishedAtFailure = headerOutputs[0] == headerOutputSentinel &&
            headerOutputs[1] == headerOutputSentinel;
    if (selected->writeBeforeFailure) {
        kern_return_t result = realPatch(destination, source, size);
        injectedWriteSucceeded = result == KERN_SUCCESS;
        if (result != KERN_SUCCESS) return result;
    }
    if (selected->changeProtection) {
        kern_return_t result = realProtect(mach_task_self(), (mach_vm_address_t)destination,
            size, false, VM_PROT_READ);
        injectedProtectionSucceeded = result == KERN_SUCCESS;
        if (result != KERN_SUCCESS) return result;
    }
    return KERN_FAILURE;
}

// 权限变更始终透传真实 bootstrap，避免桩结果代替设备行为。
static kern_return_t testProtect(vm_map_t task, mach_vm_address_t address, mach_vm_size_t size,
        boolean_t maximum, vm_prot_t protection) {
    return realProtect(task, address, size, maximum, protection);
}

// 仅后端目标文件重命名 dlsym，其他生产模块和本程序仍使用真实动态解析器。
void *LHTestDlsym(void *handle, const char *name) {
    if (!strcmp(name, "substrate_hook_memory")) return realPatch ? (void *)testPatch : NULL;
    if (!strcmp(name, "substrate_vm_protect")) return realProtect ? (void *)testProtect : NULL;
    return dlsym(handle, name);
}

// 仅阻止本程序短函数的近页申请，强制生产实现验证并使用真实 Mach-O 头部中继。
kern_return_t LHTestMachVMMap(vm_map_t task, mach_vm_address_t *address, mach_vm_size_t size,
        mach_vm_offset_t mask, int flags, mem_entry_name_port_t object, memory_object_offset_t offset,
        boolean_t copy, vm_prot_t current, vm_prot_t maximum, vm_inherit_t inheritance) {
    uintptr_t expected = headerTarget > 0x7ff0000 ? headerTarget - 0x7ff0000 : pageSize;
    if (pageSize) expected = (expected + pageSize - 1) & ~(pageSize - 1);
    if (armed && selected->headerChain && task == mach_task_self() && address &&
            *address == expected && size == pageSize && object == MACH_PORT_NULL && flags == VM_FLAGS_ANYWHERE) {
        nearAllocationsRejected++;
        return KERN_NO_SPACE;
    }
    return mach_vm_map(task, address, size, mask, flags, object, offset, copy, current, maximum, inheritance);
}

// 替换函数只改变返回值，不依赖尚未确认的 original 槽位。
__attribute__((noinline)) static int replacement(int value) { return value + 1000; }

// 用可调用且明确不同的原值检查 oldptr 是否真正恢复。
__attribute__((noinline)) static int sentinel(int value) { return value - 2000; }

// 给匿名函数入口添加当前架构需要的函数指针认证。
static LHTestFunction functionAt(size_t index) {
    void *address = functionPages + index * pageSize;
    return (LHTestFunction)ptrauth_sign_unauthenticated(address, ptrauth_key_function_pointer, 0);
}

// 在事务外收集断言，失败后继续输出完整统计而不丢失设备证据。
static void require(bool condition, const char *description) {
    checks++;
    if (condition) return;
    failures++;
    if (!firstFailure) firstFailure = description;
}

// 创建三页简单函数并在故障开关关闭时预热真实补丁和权限后端。
static uint8_t *preparePages(void) {
    pageSize = (size_t)vm_page_size;
    functionPages = mmap(NULL, pageSize * LH_TEST_PAGES, PROT_READ | PROT_WRITE,
        MAP_PRIVATE | MAP_ANON, -1, 0);
    if (functionPages == MAP_FAILED) { functionPages = NULL; return NULL; }
    memset(functionPages, 0x5a, pageSize * LH_TEST_PAGES);
    for (size_t index = 0; index < LH_TEST_PAGES; index++) {
        uint32_t *code = (uint32_t *)(functionPages + index * pageSize);
        code[0] = 0x11000000 | ((uint32_t)(11 + index) << 10); // add w0, w0, #11+#index
        code[1] = 0xd503201f; // nop
        code[2] = 0xd503201f; // nop
        code[3] = 0xd65f03c0; // ret
    }
    uint8_t *baseline = malloc(pageSize * LH_TEST_PAGES);
    if (!baseline) return NULL;
    memcpy(baseline, functionPages, pageSize * LH_TEST_PAGES);
    for (size_t index = 0; index < LH_TEST_PAGES; index++) {
        void *page = functionPages + index * pageSize;
        if (realProtect(mach_task_self(), (mach_vm_address_t)page, pageSize, false,
                VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS ||
                realPatch(page, baseline + index * pageSize, pageSize) != KERN_SUCCESS ||
                realProtect(mach_task_self(), (mach_vm_address_t)page, pageSize, false,
                    VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) {
            free(baseline);
            return NULL;
        }
        sys_icache_invalidate(page, pageSize);
    }
    return baseline;
}

// 使用真实头部中继重复 Hook 自身短函数，验证 original 依赖在输出槽恢复前不会被撤销。
static int runHeaderCase(void) {
    pageSize = (size_t)vm_page_size;
    headerTarget = (uintptr_t)ptrauth_strip((void *)LHTestHeaderTarget, ptrauth_key_function_pointer);
    headerTargetPage = headerTarget & ~(pageSize - 1);
    Dl_info info = {0};
    if (!dladdr((void *)headerTarget, &info) || !info.dli_fbase) return 2;
    headerPage = (uintptr_t)info.dli_fbase;
    if ((headerPage & (pageSize - 1)) || headerPage >= headerTargetPage) {
        fprintf(stderr, "header fixture requires separate header and target pages\n");
        return 2;
    }
    uint8_t *baseline = malloc(pageSize * 2);
    headerOutputs = mmap(NULL, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    uintptr_t hint = (headerTarget + 0x20000000) & ~(pageSize - 1);
    uint8_t *replacements = mmap((void *)hint, pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (!baseline || headerOutputs == MAP_FAILED || replacements == MAP_FAILED) return 2;
    uintptr_t distance = (uintptr_t)replacements >= headerTarget ? (uintptr_t)replacements - headerTarget :
        headerTarget - (uintptr_t)replacements;
    if (distance <= 0x8000000) { fprintf(stderr, "header replacements are not outside B range\n"); return 2; }
    memcpy(baseline, (void *)headerPage, pageSize);
    memcpy(baseline + pageSize, (void *)headerTargetPage, pageSize);
    headerOutputSentinel = (void *)sentinel;
    for (size_t index = 0; index < 2; index++) {
        uint32_t *code = (uint32_t *)(replacements + index * 32);
        code[0] = 0x11000000 | ((uint32_t)(1000 + index * 1000) << 10);
        code[1] = 0xd65f03c0;
        headerOutputs[index] = (void *)sentinel;
    }
    if (realProtect(mach_task_self(), (mach_vm_address_t)replacements, pageSize, false,
            VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) return 2;
    sys_icache_invalidate(replacements, pageSize);
    // 在暂停前预热真实整页修改，并确保本程序代码和头部保持原始内容。
    for (size_t index = 0; index < 2; index++) {
        uintptr_t page = index ? headerTargetPage : headerPage;
        if (realPatch((void *)page, baseline + index * pageSize, pageSize) != KERN_SUCCESS ||
                realProtect(mach_task_self(), page, pageSize, false,
                    VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) return 2;
        sys_icache_invalidate((void *)page, pageSize);
    }
    struct LHFunctionHook hooks[2];
    for (size_t index = 0; index < 2; index++) {
        void *entry = ptrauth_sign_unauthenticated(replacements + index * 32, ptrauth_key_function_pointer, 0);
        require(((LHTestFunction)entry)(7) == 1007 + (int)index * 1000, "header replacement baseline");
        hooks[index] = (struct LHFunctionHook){(void *)LHTestHeaderTarget, entry, &headerOutputs[index], NULL};
    }
    require(LHTestHeaderTarget(7) == 38, "short function baseline");
    errno = 0;
    armed = true;
    int installed = LHHookFunctions(hooks, 2);
    int hookError = errno;
    armed = false;
    require(installed == 0 && hookError == (selected->failOutputRestore ? LIBHOOKER_ERR_ROLLBACK : LIBHOOKER_ERR_VM),
        "header chain error classification");
    require(nearAllocationsRejected == 2, "both hooks forced through header relay");
    require(forwardCalls == selected->failAt && forwardFailed && injectedWriteSucceeded, "requested header transaction fault reached");
    require(headerOutputsUnpublishedAtFailure == (selected->failAt == 1), "output publication follows successful relay preparation");
    require(rollbackCalls == (selected->failOutputRestore ? 1u : selected->failAt), "header rollback phase order");
    require(LHTestHeaderTarget(7) == 38, "short function restored before output slots");
    require(memcmp((void *)headerTargetPage, baseline + pageSize, pageSize) == 0, "short target page fully restored");
    bool headerRestored = memcmp((void *)headerPage, baseline, pageSize) == 0;
    require(headerRestored != selected->failOutputRestore, "header relay retained until output slots restored");
    if (selected->failOutputRestore) {
        require(outputProtectionInjected, "output protection fault actually reached");
        require(headerOutputs[0] && headerOutputs[0] != (void *)sentinel, "first original retained");
        require(headerOutputs[1] && headerOutputs[1] != (void *)sentinel, "second original retained");
        if (headerOutputs[0] && headerOutputs[0] != (void *)sentinel)
            require(((LHTestFunction)headerOutputs[0])(7) == 38, "first original callable after partial rollback");
        if (headerOutputs[1] && headerOutputs[1] != (void *)sentinel)
            require(((LHTestFunction)headerOutputs[1])(7) == 1007, "second original still reaches first header relay");
    } else {
        require(headerOutputs[0] == (void *)sentinel && headerOutputs[1] == (void *)sentinel,
            "both output slots restored before clearing relays");
    }
    uint32_t headerProtection = 0, targetProtection = 0;
    require(LHGetMemoryProtection(headerPage, &headerProtection) && headerProtection == (VM_PROT_READ | VM_PROT_EXECUTE),
        "header RX permission restored");
    require(LHGetMemoryProtection(headerTargetPage, &targetProtection) && targetProtection == (VM_PROT_READ | VM_PROT_EXECUTE),
        "target RX permission restored");
    printf("{\"case\":\"%s\",\"status\":\"%s\",\"checks\":%u,\"failures\":%u,"
        "\"installed\":%d,\"errno\":%d,\"forwardCalls\":%u,\"rollbackCalls\":%u,"
        "\"nearAllocationsRejected\":%u,\"headerRestored\":%s,\"outputProtectionInjected\":%s,"
        "\"outputsUnpublishedAtFailure\":%s,\"detail\":\"%s\"}\n",
        selected->name, failures ? "fail" : "pass", checks, failures, installed, hookError, forwardCalls,
        rollbackCalls, nearAllocationsRejected, headerRestored ? "true" : "false",
        outputProtectionInjected ? "true" : "false", headerOutputsUnpublishedAtFailure ? "true" : "false",
        firstFailure ? firstFailure : "all checks passed");
    free(baseline);
    return failures ? 1 : 0;
}

// 只提交四个实际页，保留其余地址空间以精确覆盖 B 的正负范围及不可读页尾。
static int runFunctionBranches(void) {
    pageSize = (size_t)vm_page_size;
    size_t reserveSize = 0x10000000 + pageSize * 3;
    uint8_t *reserve = mmap(NULL, reserveSize, PROT_NONE, MAP_PRIVATE | MAP_ANON, -1, 0);
    if (reserve == MAP_FAILED) return 2;
    uint8_t *center = reserve + 0x8000000 + pageSize;
    uint8_t *pages[] = {reserve + pageSize, center, reserve + 0x10000000, reserve + 0x10000000 + pageSize};
    for (size_t i = 0; i < 4; i++) {
        if (realProtect(mach_task_self(), (mach_vm_address_t)pages[i], pageSize, false,
                VM_PROT_READ | VM_PROT_WRITE) != KERN_SUCCESS) return 2;
        memset(pages[i], 0x5a, pageSize);
    }
    const intptr_t distances[] = {0x7fffffc, 0x8000000, -0x8000000, -0x8000004};
    const uint32_t ordinary[] = {0x11002c00, 0xd503201f, 0xd503201f, 0xd65f03c0};
    const uint32_t bothIP[] = {0x8b110210, 0x11000600, 0xd65f03c0}; // add x16,x16,x17; add w0,w16,#1; ret
    const uint32_t conditional[] = {0x34000040, 0x11002c00, 0xd65f03c0}; // cbz w0,+8; add w0,w0,#11; ret
    uint8_t *targets[8], *replacements[8];
    uint32_t baseline[8][4];
    void *originals[8] = {0};
    for (size_t i = 0; i < 8; i++) {
        targets[i] = i == 7 ? center + pageSize - 4 : center + i * 32;
        replacements[i] = i < 4 ? targets[i] + distances[i] : center + 1024;
        size_t length = i == 7 ? 4 : sizeof(ordinary);
        memcpy(targets[i], i == 7 ? &ordinary[3] : ordinary, length);
        if (i == 5) memcpy(targets[i], bothIP, sizeof(bothIP));
        if (i == 6) memcpy(targets[i], conditional, sizeof(conditional));
        memcpy(baseline[i], targets[i], length);
        uint32_t replacementCode[] = {0x110fa000, 0xd65f03c0}; // add w0,w0,#1000; ret
        memcpy(replacements[i], replacementCode, sizeof(replacementCode));
    }
    uint32_t secondCode[] = {0x111f4000, 0xd65f03c0}; // add w0,w0,#2000; ret
    memcpy(center + 1056, secondCode, sizeof(secondCode));
    for (size_t i = 0; i < 4; i++) {
        if (realProtect(mach_task_self(), (mach_vm_address_t)pages[i], pageSize, false,
                VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) return 2;
        sys_icache_invalidate(pages[i], pageSize);
    }
    for (size_t i = 0; i < 8; i++) {
        LHTestFunction target = (LHTestFunction)ptrauth_sign_unauthenticated(targets[i], ptrauth_key_function_pointer, 0);
        void *replacementEntry = ptrauth_sign_unauthenticated(replacements[i], ptrauth_key_function_pointer, 0);
        int expected = i == 5 ? 43 : i == 7 ? 7 : 18;
        require(LHTestCallWithIP(target, 7) == expected, "branch fixture baseline");
        struct LHFunctionHook hook = {(void *)target, replacementEntry, &originals[i], NULL};
        errno = 0;
        int installed = LHHookFunctions(&hook, 1);
        require(installed == 1 && errno == 0 && originals[i], "branch fixture Hook succeeds");
        if (installed != 1 || !originals[i]) continue;
        require(LHTestCallWithIP(target, 7) == 1007, "branch replacement callable");
        require(LHTestCallWithIP((LHTestFunction)originals[i], 7) == expected, "branch original callable");
        bool near = i != 1 && i != 3;
        if (near) {
            uintptr_t displacement = (uintptr_t)replacements[i] - (uintptr_t)targets[i];
            require(*(uint32_t *)targets[i] == (0x14000000 | ((displacement / 4) & 0x3ffffff)),
                "near branch exact encoding including range endpoints");
            if (i != 7) require(!memcmp(targets[i] + 4, (uint8_t *)baseline[i] + 4, 12),
                "near branch leaves all bytes after first instruction unchanged");
        } else {
            require((*(uint32_t *)targets[i] & 0x9f000000) == 0x90000000,
                "just-outside branch range retains ADRP path");
            require(!memcmp(targets[i] + 12, &baseline[i][3], 4), "far patch retains fourth instruction");
        }
        if (i == 4 || i == 5) {
            void *originalCode = ptrauth_strip(originals[i], ptrauth_key_function_pointer);
            require(!memcmp(originalCode, baseline[i], 12), "near original retains all three relocated instructions");
        }
        if (i == 6) require(((LHTestFunction)originals[i])(0) == 0,
            "conditional original branch still reaches relocated third instruction");
    }
    LHTestFunction target = (LHTestFunction)ptrauth_sign_unauthenticated(targets[4], ptrauth_key_function_pointer, 0);
    void *secondOriginal = NULL;
    struct LHFunctionHook repeat = {(void *)target,
        ptrauth_sign_unauthenticated(center + 1056, ptrauth_key_function_pointer, 0), &secondOriginal, NULL};
    require(LHHookFunctions(&repeat, 1) == 1 && secondOriginal, "repeat near Hook succeeds");
    if (secondOriginal && originals[4]) {
        require(target(7) == 2007 && ((LHTestFunction)secondOriginal)(7) == 1007,
            "repeat near Hook retains previous replacement");
        require(((LHTestFunction)originals[4])(7) == 18, "repeat near Hook retains first original");
    }
    printf("{\"case\":\"%s\",\"status\":\"%s\",\"checks\":%u,\"failures\":%u,\"detail\":\"%s\"}\n",
        selected->name, failures ? "fail" : "pass", checks, failures, firstFailure ? firstFailure : "all checks passed");
    return failures ? 1 : 0;
}

// 原样重写补丁器自身及权限函数所在页，验证移除执行权期间始终在独立页取指。
static int runLegacySelfPage(void) {
    pageSize = vm_page_size;
    require(LHPrepareLegacyMemory(), "legacy writer prepared");
    if (failures) return 1;
    void *functions[] = {(void *)&LHLegacyPatch, (void *)&LHLegacyProtect};
    uint8_t *snapshot = malloc(pageSize);
    if (!snapshot) return 2;
    for (unsigned index = 0; index < 2; index++) {
        uintptr_t page = (uintptr_t)ptrauth_strip(functions[index], ptrauth_key_function_pointer) & ~(pageSize - 1);
        uint32_t before = 0, after = 0;
        require(LHGetMemoryProtection(page, &before), "self page readable");
        memcpy(snapshot, (void *)page, pageSize);
        require(LHLegacyPatch((void *)page, snapshot, pageSize) == KERN_SUCCESS, "self page rewritten");
        sys_icache_invalidate((void *)page, pageSize);
        require(!memcmp(snapshot, (void *)page, pageSize), "self page bytes preserved");
        require(LHGetMemoryProtection(page, &after) && before == after, "self page permission preserved");
    }
    free(snapshot);
    printf("{\"case\":\"%s\",\"status\":\"%s\",\"checks\":%u,\"failures\":%u}\n",
        selected->name, failures ? "fail" : "pass", checks, failures);
    return failures ? 1 : 0;
}

// 运行单个独立案例，真实调用所有目标和需要保留的原函数跳板。
static int runCase(void) {
    if (selected->legacySelfPage) return runLegacySelfPage();
    realPatch = (LHTestPatchBackend)dlsym(RTLD_DEFAULT, "substrate_hook_memory");
    realProtect = (LHTestProtectBackend)dlsym(RTLD_DEFAULT, "substrate_vm_protect");
    // 旧版环境用真实本地后端执行相同故障矩阵，不用接口桩替代设备写入。
    if (!realPatch && !realProtect && LHPrepareLegacyMemory()) {
        realPatch = LHLegacyPatch;
        realProtect = LHLegacyProtect;
    }
    if (!realPatch || !realProtect) {
        printf("{\"case\":\"%s\",\"status\":\"error\",\"detail\":\"bootstrap interfaces unavailable\"}\n", selected->name);
        return 2;
    }
    if (selected->functionBranches) return runFunctionBranches();
    if (selected->headerChain) return runHeaderCase();
    uint8_t *baseline = preparePages();
    if (!baseline) {
        printf("{\"case\":\"%s\",\"status\":\"error\",\"detail\":\"anonymous RX fixture preparation failed\"}\n", selected->name);
        return 2;
    }
    void *outputs[LH_TEST_PAGES] = {(void *)sentinel, (void *)sentinel, (void *)sentinel};
    struct LHFunctionHook hooks[LH_TEST_PAGES];
    for (size_t index = 0; index < LH_TEST_PAGES; index++) {
        require(functionAt(index)(7) == 18 + (int)index, "baseline function result");
        hooks[index] = (struct LHFunctionHook){(void *)functionAt(index), (void *)replacement,
            &outputs[selected->duplicateOutput ? 0 : index], NULL};
    }
    errno = 0;
    armed = true;
    int installed = LHHookFunctions(hooks, LH_TEST_PAGES);
    int hookError = errno;
    armed = false;
    bool expectedSuccess = selected->failAt == 0;
    bool expectedRollbackFailure = selected->failRollback;
    require(installed == (expectedSuccess ? LH_TEST_PAGES : 0), "Hook return count");
    require(hookError == (expectedSuccess ? 0 : expectedRollbackFailure ? LIBHOOKER_ERR_ROLLBACK : LIBHOOKER_ERR_VM),
        "Hook error classification");
    require(forwardCalls == (expectedSuccess ? LH_TEST_PAGES : selected->failAt), "forward fault position");
    require(forwardFailed == !expectedSuccess, "fault injection reached");
    require(rollbackCalls == (expectedSuccess ? 0 : expectedRollbackFailure ? 1 : selected->failAt),
        "rollback visits failing page and stops on failure");
    if (selected->writeBeforeFailure) require(injectedWriteSucceeded, "real write completed before injected error");
    if (selected->changeProtection) require(injectedProtectionSucceeded, "real protection changed before injected error");
    bool allBytesOriginal = true, allPermissionsRestored = true, allOutputsRestored = true;
    for (size_t index = 0; index < LH_TEST_PAGES; index++) {
        bool changed = expectedSuccess || (expectedRollbackFailure && index < selected->failAt);
        require(functionAt(index)(7) == (changed ? 1007 : 18 + (int)index), "target callable after transaction");
        bool bytesOriginal = memcmp(functionPages + index * pageSize, baseline + index * pageSize, pageSize) == 0;
        allBytesOriginal &= bytesOriginal;
        require(bytesOriginal != changed, "target page byte state");
        uint32_t protection = 0;
        bool permissionRestored = LHGetMemoryProtection((uintptr_t)(functionPages + index * pageSize), &protection) &&
            protection == (VM_PROT_READ | VM_PROT_EXECUTE);
        allPermissionsRestored &= permissionRestored;
        require(permissionRestored, "target RX permission restored");
        allOutputsRestored &= outputs[index] == (void *)sentinel;
    }
    if (!expectedSuccess && !expectedRollbackFailure) {
        require(allBytesOriginal, "complete rollback restored all pages");
        require(allOutputsRestored, "complete rollback restored all oldptr values");
        require(((LHTestFunction)outputs[0])(7) == -1993, "restored oldptr remains callable");
    } else {
        size_t count = selected->duplicateOutput ? 1 : LH_TEST_PAGES;
        for (size_t index = 0; index < count; index++) {
            size_t originalIndex = selected->duplicateOutput ? LH_TEST_PAGES - 1 : index;
            require(outputs[index] != (void *)sentinel && outputs[index] != NULL, "original trampoline published");
            if (outputs[index] && outputs[index] != (void *)sentinel)
                require(((LHTestFunction)outputs[index])(7) == 18 + (int)originalIndex, "retained original trampoline callable");
        }
    }
#if __arm64e__
    const char *architecture = "arm64e";
#else
    const char *architecture = "arm64";
#endif
    printf("{\"case\":\"%s\",\"architecture\":\"%s\",\"status\":\"%s\",\"checks\":%u,"
        "\"failures\":%u,\"installed\":%d,\"errno\":%d,\"forwardCalls\":%u,\"rollbackCalls\":%u,"
        "\"bytesOriginal\":%s,\"permissionsRestored\":%s,\"oldptrRestored\":%s,\"detail\":\"%s\"}\n",
        selected->name, architecture, failures ? "fail" : "pass", checks, failures, installed, hookError,
        forwardCalls, rollbackCalls, allBytesOriginal ? "true" : "false", allPermissionsRestored ? "true" : "false",
        allOutputsRestored ? "true" : "false", firstFailure ? firstFailure : "all checks passed");
    free(baseline);
    // 由进程退出统一回收保留跳板和函数映射，尤其不破坏回滚失败后的依赖关系。
    return failures ? 1 : 0;
}

// 每次只运行一个案例，确保故障状态和永久保留资源不会污染下一次验证。
int main(int argc, char **argv) {
    if (argc == 2 && !strcmp(argv[1], "--list")) {
        for (size_t index = 0; index < sizeof(cases) / sizeof(*cases); index++) puts(cases[index].name);
        return 0;
    }
    if (argc == 3 && !strcmp(argv[1], "--case")) {
        for (size_t index = 0; index < sizeof(cases) / sizeof(*cases); index++) {
            if (!strcmp(argv[2], cases[index].name)) { selected = &cases[index]; return runCase(); }
        }
    }
    fprintf(stderr, "usage: %s --list | --case NAME\n", argv[0]);
    return 2;
}
