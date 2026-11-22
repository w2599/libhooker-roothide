//
//  funcHook.c
//  libhooker
//
//  Created by CoolStar on 2/24/20.
//  Copyright © 2020 CoolStar. All rights reserved.
//

// 保留上游独立跳板及通用重定位，按距离与函数长度选择入口。
#include "funcHook.h"
#include "funcMacros.h"
#include "../as-aarch64/as-aarch64.h"
#include "../disas-aarch64/disas-aarch64.h"
#include "../mem/writeMem.h"
#include "../mem/shadowMem.h"
#include "../mem/hook-transaction.h"
#ifdef LH_ROOTHIDE
#include "entry-window.h"
#include "../mem/header-relay.h"
#include <mach/mach.h>
#include <mach/mach_vm.h>
#endif
#include <errno.h>
#include <ptrauth.h>
#include <string.h>
#include <sys/mman.h>

// 识别不再顺序执行下一条指令的出口。
static bool LHEndsBlock(uint32_t opcode, const struct disasm_reg_t *registry) {
    return registry[0].is_op(opcode) || is_bExit(opcode) ||
        (opcode & 0xfffffc1f) == 0xd61f0000 ||
        (opcode & 0xfffff81f) == 0xd61f081f ||
        (opcode & 0xfffff800) == 0xd71f0800;
}

// 前缀内调用可把返回地址保存到深层栈中，不能用多指令入口覆盖它。
static bool LHIsCall(uint32_t opcode) {
    return (opcode & 0xfc000000) == 0x94000000 ||
        (opcode & 0xfffffc1f) == 0xd63f0000 ||
        (opcode & 0xfffff81f) == 0xd63f081f ||
        (opcode & 0xfffff800) == 0xd73f0800;
}

// 避免回跳覆盖前缀刚生成的 IP 值；自定义寄存器仍由调用方选择。
static uint8_t LHRelocationRegister(const uint32_t *instructions, size_t count, uint8_t requested) {
    if (requested != 16 && requested != 17) return requested;
    uint32_t used = 0;
    for (size_t i = 0; i < count; i++) {
        uint32_t opcode = instructions[i];
        // 这些指令的隐式操作数不能从常规寄存器字段推断。
        if ((opcode & ~0xc0U) == 0xd503211f ||
                (opcode & 0xbfa07c00U) == 0x08207c00U ||
                (opcode & 0xffffbc00U) == 0xf83f9000U ||
                (opcode & 0xffe0ec00U) == 0xf820a000U || LHIsCall(opcode)) return 31;
        if ((opcode & 0x7c000000) == 0x14000000 || LHIsConditionCodeBranch(opcode)) continue;
        if ((opcode & 0x1f000000) == 0x10000000 || (opcode & 0x3b000000) == 0x18000000 ||
                (opcode & 0x1f800000) == 0x12800000 ||
                (opcode & 0x7e000000) == 0x34000000 || (opcode & 0x7e000000) == 0x36000000) {
            used |= 1U << (opcode & 31);
        } else {
            used |= (1U << (opcode & 31)) | (1U << ((opcode >> 5) & 31)) |
                (1U << ((opcode >> 10) & 31)) | (1U << ((opcode >> 16) & 31));
        }
    }
    if (!(used & (1U << requested))) return requested;
    uint8_t alternate = requested == 16 ? 17 : 16;
    return used & (1U << alternate) ? 31 : alternate;
}

#ifdef LH_ROOTHIDE
// 隐式 IP 或私有调用入口必须保留全部寄存器，只为这类兼容情况创建独立近页。
static int LHBuildSensitiveOriginal(uintptr_t target, uint32_t opcode, struct LHHookResources *resources) {
    // 此兼容路径只重编码 B/BL，其余 PC 相对指令必须交给通用重定位器。
    if ((opcode & 0x1f000000) == 0x10000000 || (opcode & 0x3b000000) == 0x18000000 ||
            (LHIsBranch(opcode) && (opcode & 0x7c000000) != 0x14000000)) return LIBHOOKER_ERR_BAD_INSN_AT_START;
    uintptr_t lower = target > 0x7fffffc ? target - 0x7fffffc : PAGE_SIZE;
    uintptr_t upper = target < UINTPTR_MAX - 0x8000000 ? target + 0x8000000 : UINTPTR_MAX;
    uintptr_t destination = 0;
    bool branch = (opcode & 0x7c000000) == 0x14000000;
    if (branch) {
        int64_t displacement = opcode & 0x3ffffff;
        if (displacement & 0x2000000) displacement -= 0x4000000;
        destination = target + displacement * 4;
        uintptr_t start = destination > 0x7fffffc ? destination - 0x7fffffc : PAGE_SIZE;
        uintptr_t end = destination < UINTPTR_MAX - 0x8000000 ? destination + 0x8000000 : UINTPTR_MAX;
        if (start > lower) lower = start;
        if (end < upper) upper = end;
    }
    mach_vm_address_t address = (lower + PAGE_MASK) & ~PAGE_MASK;
    if (address > upper || mach_vm_map(mach_task_self(), &address, PAGE_SIZE, 0, VM_FLAGS_ANYWHERE,
            MACH_PORT_NULL, 0, false, VM_PROT_READ | VM_PROT_WRITE,
            VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE, VM_INHERIT_NONE) != KERN_SUCCESS) return LIBHOOKER_ERR_VM;
    if (address > upper) { mach_vm_deallocate(mach_task_self(), address, PAGE_SIZE); return LIBHOOKER_ERR_VM; }
    uint32_t *code = (void *)address;
    code[0] = branch ? (opcode & 0xfc000000) | (((destination - address) / 4) & 0x3ffffff) : opcode;
    code[1] = 0x14000000 | (((target - address) / 4) & 0x3ffffff);
    if (!LHMarkMemoryExecutable(code)) { mach_vm_deallocate(mach_task_self(), address, PAGE_SIZE); return LIBHOOKER_ERR_VM; }
    resources->trampoline = code;
    resources->original = ptrauth_sign_unauthenticated(code, ptrauth_key_function_pointer, 0);
    return LIBHOOKER_OK;
}
#endif

// 按上游分配式接口逐条重定位，内部跳转使用实际输出长度计算位置。
static int LHBuildOriginal(uintptr_t target, const uint32_t *instructions, size_t count,
        uint8_t requested, struct LHHookResources *resources) {
    struct disasm_reg_t *registry;
    int registryCount;
    LHGetDisasmRegistry(&registry, &registryCount);
    uint8_t reg = LHRelocationRegister(instructions, count, requested);
    if (reg >= 31) {
        bool needsScratch = !LHEndsBlock(instructions[count - 1], registry);
        for (size_t i = 0; i < count; i++) needsScratch |= LHIsBranch(instructions[i]) || LHIsCall(instructions[i]);
        if (!needsScratch) reg = requested;
#ifdef LH_ROOTHIDE
        else if (count == 1) return LHBuildSensitiveOriginal(target, instructions[0], resources);
#endif
        else return LIBHOOKER_ERR_BAD_INSN_AT_START;
    }
    uint32_t *pieces[4] = {0};
    size_t sizes[4] = {0}, offsets[4] = {0};
    uint64_t destinations[3] = {0};
    const struct disasm_reg_t *handlers[3] = {0};
    size_t total = 0;
    int result = LIBHOOKER_ERR_BAD_INSN_AT_START;
    void *buffer = NULL;
    for (size_t i = 0; i < count; i++) {
        uint32_t opcode = instructions[i];
        // 零寄存器不能暂存 literal load 或 ADR 的目标地址。
        if (((opcode & 0x3b00001f) == 0x1800001f && (opcode >> 30) != 3) ||
                (opcode & 0x1f00001f) == 0x1000001f) goto done;
        for (int j = 0; j < registryCount; j++) {
            if (registry[j].is_op(opcode)) { handlers[i] = &registry[j]; break; }
        }
        if (!handlers[i] || !handlers[i]->tramp_size || !handlers[i]->handle_op) goto done;
        pieces[i] = handlers[i]->handle_op(target + i * 4, opcode, reg, &destinations[i]);
        if (!pieces[i]) { result = LIBHOOKER_ERR_VM; goto done; }
        sizes[i] = handlers[i]->tramp_size;
        offsets[i] = total;
        total += sizes[i];
        // 拒绝读取将被改写的指令字节，包括从入口前方跨入的 literal。
        if ((opcode & 0x3b000000) == 0x18000000 && (opcode >> 30) != 3) {
            size_t width = (opcode >> 30) == 1 ? 8 : 4;
            if (destinations[i] <= target ? target - destinations[i] < width :
                    destinations[i] - target < count * 4) goto done;
        }
    }
    if (!LHEndsBlock(instructions[count - 1], registry)) {
        pieces[count] = assemble_jmp(target + count * 4, false, reg);
        if (!pieces[count]) { result = LIBHOOKER_ERR_VM; goto done; }
        sizes[count] = JMPSIZ * 4;
        offsets[count] = total;
        total += sizes[count];
    }
    buffer = malloc(total);
    if (!buffer) { result = LIBHOOKER_ERR_VM; goto done; }
    for (size_t i = 0; i <= count; i++)
        if (sizes[i]) memcpy((uint8_t *)buffer + offsets[i], pieces[i], sizes[i]);
    if (!LHExecMemory(&resources->trampoline, buffer, total)) { result = LIBHOOKER_ERR_VM; goto done; }
    // 已知实际跳板地址后重写内部目标；整个原调用发布前完成权限恢复。
    bool writable = false;
    for (size_t i = 0; i < count; i++) {
        if (!LHIsBranch(instructions[i]) || destinations[i] < target || destinations[i] - target >= count * 4) continue;
        if ((destinations[i] - target) & 3 || !handlers[i]->rehandle_op) goto done;
        size_t destinationIndex = (destinations[i] - target) / 4;
        uint32_t *rewritten = handlers[i]->rehandle_op(instructions[i], reg,
            (uintptr_t)resources->trampoline + offsets[destinationIndex]);
        if (!rewritten) { result = LIBHOOKER_ERR_VM; goto done; }
        if (!writable && !LHMarkMemoryWriteable(resources->trampoline)) {
            free(rewritten); result = LIBHOOKER_ERR_VM; goto done;
        }
        writable = true;
        memcpy((uint8_t *)resources->trampoline + offsets[i], rewritten, sizes[i]);
        free(rewritten);
    }
    if (writable && !LHMarkMemoryExecutable(resources->trampoline)) { result = LIBHOOKER_ERR_VM; goto done; }
    resources->original = ptrauth_sign_unauthenticated(resources->trampoline, ptrauth_key_function_pointer, 0);
    result = LIBHOOKER_OK;
done:
    for (size_t i = 0; i < 4; i++) free(pieces[i]);
    free(buffer);
    return result;
}

// 精确检查 ADRP 的正负四 GiB 范围。
static bool LHCanAddressPage(uintptr_t source, uintptr_t destination) {
    source &= ~(uintptr_t)0xfff;
    destination &= ~(uintptr_t)0xfff;
    return destination >= source ? destination - source < 0x100000000ULL : source - destination <= 0x100000000ULL;
}

#ifdef LH_ROOTHIDE
// 精确检查单条 B 指令的正负 128 MiB 范围。
static bool LHCanBranch(uintptr_t source, uintptr_t destination) {
    return destination >= source ? destination - source <= 0x7fffffcULL : source - destination <= 0x8000000ULL;
}

// 只检查当前事务已取得的入口页，跨页或超出指令预算的分支不使用三条覆盖。
static bool LHCanCoverEntry(uintptr_t target) {
    uint32_t words[LH_ENTRY_SCAN_WORDS];
    size_t offset = target & PAGE_MASK;
    size_t count = (PAGE_SIZE - offset) / sizeof(*words);
    if (count > LH_ENTRY_SCAN_WORDS) count = LH_ENTRY_SCAN_WORDS;
    return count >= 3 && LHCopyMemPage(words, target & ~PAGE_MASK, offset, count * sizeof(*words)) &&
        LHCanCoverThreeInstructions(words, count);
}

// 短函数需要时单独申请近页，不与其他 Hook 共享页或复用槽位。
static bool LHCreateShortRelay(uintptr_t target, const uint32_t *jump, void **relay) {
    uintptr_t lower = target > 0x7ff0000 ? target - 0x7ff0000 : PAGE_SIZE;
    mach_vm_address_t address = (lower + PAGE_MASK) & ~PAGE_MASK;
    if (mach_vm_map(mach_task_self(), &address, PAGE_SIZE, 0, VM_FLAGS_ANYWHERE, MACH_PORT_NULL, 0, false,
            VM_PROT_READ | VM_PROT_WRITE, VM_PROT_READ | VM_PROT_WRITE | VM_PROT_EXECUTE, VM_INHERIT_NONE) != KERN_SUCCESS) return false;
    if (LHCanBranch(target, address)) {
        memcpy((void *)address, jump, JMPSIZ * 4);
        if (LHMarkMemoryExecutable((void *)address)) { *relay = (void *)address; return true; }
    }
    mach_vm_deallocate(mach_task_self(), address, PAGE_SIZE);
    return false;
}
#endif

// 近距离入口优先单条直跳；远距离沿用三条指令及独立中继。
int LHHookFunction(void *symbol, void *hook, void **old, uint8_t reg) {
    if (!symbol || !hook) return LIBHOOKER_ERR_NO_SYMBOL;
    uintptr_t target = (uintptr_t)ptrauth_strip(symbol, ptrauth_key_function_pointer);
    uintptr_t replacement = (uintptr_t)ptrauth_strip(hook, ptrauth_key_function_pointer);
    if ((target | replacement) & 3 || reg >= 31 || target == replacement) return LIBHOOKER_ERR_BAD_INSN_AT_START;
    struct disasm_reg_t *registry;
    int registryCount;
    LHGetDisasmRegistry(&registry, &registryCount);
    uint32_t original[3], patch[3];
    size_t count = 3;
    // 逐条读取，在出口停止，避免短函数位于页尾时越过未知映射。
    for (size_t i = 0; i < 3; i++) {
        uintptr_t address = target + i * sizeof(uint32_t);
        // 已对齐的单条指令不会跨页，直接读取快照即可省去临时堆分配。
        if (!address || sizeof(uint32_t) > UINTPTR_MAX - address ||
                !LHCopyMemPage(&original[i], address & ~PAGE_MASK, address & PAGE_MASK,
                    sizeof(original[i]))) return LIBHOOKER_ERR_VM;
#ifdef LH_ROOTHIDE
        if (LHIsCall(original[i]) || LHIsTrapInstruction(original[i])) { count = 1; break; }
#endif
        if (LHEndsBlock(original[i], registry)) { if (i < 2) count = 1; break; }
    }
#ifdef LH_ROOTHIDE
    // 未终止的前缀若没有可借用的 IP，缩小覆盖范围以保留后续寄存器语义。
    if (count == 3 && LHRelocationRegister(original, count, reg) >= 31 && !LHEndsBlock(original[2], registry)) count = 1;
#endif
#ifndef LH_ROOTHIDE
    if (count == 1) return LIBHOOKER_ERR_SHORT_FUNC;
#endif
    struct LHHookResources *resources = calloc(1, sizeof(*resources));
    if (!resources) return LIBHOOKER_ERR_VM;
    resources->oldptr = old;
    resources->target = target;
    int result = LIBHOOKER_ERR_VM;
    uint32_t jump[JMPSIZ];
#ifdef LH_ROOTHIDE
    struct LHHeaderRelay *headerRelay = NULL;
    uintptr_t headerAddress = 0;
    bool headerStaged = false;
#endif
    // 先准备原函数，错误指令不会被中继分配失败掩盖。
    if (old) {
        result = LHBuildOriginal(target, original, count, reg, resources);
        if (result != LIBHOOKER_OK) goto done;
    }
#ifdef LH_ROOTHIDE
    // 保留原调用的完整重定位前缀，仅缩小入口改写，避免提前回跳破坏 IP 寄存器。
    if (count > 1 && (LHCanBranch(target, replacement) || !LHCanCoverEntry(target))) count = 1;
#endif
    resources->patchSize = count * sizeof(uint32_t);
    result = LIBHOOKER_ERR_VM;
#ifdef LH_ROOTHIDE
    if (count == 1) {
        uintptr_t destination = replacement;
        if (!LHCanBranch(target, replacement)) {
            if (!assemble_jmp_into(jump, replacement, false, reg)) goto done;
            if (LHCreateShortRelay(target, jump, &resources->relay)) destination = (uintptr_t)resources->relay;
            else {
                headerRelay = LHPrepareHeaderRelay(target, JMPSIZ * 4, &headerAddress);
                if (!headerRelay) goto done;
                destination = headerAddress;
            }
        }
        patch[0] = 0x14000000 | (((destination - target) / 4) & 0x3ffffff);
    } else
#endif
    {
        uintptr_t destination = replacement;
        bool useMovk = false;
        if (!LHCanAddressPage(target, replacement)) {
            if (!assemble_jmp_into(jump, replacement, false, reg) ||
                    !LHExecMemory(&resources->relay, jump, JMPSIZ * 4)) goto done;
            destination = (uintptr_t)resources->relay;
            if (!LHCanAddressPage(target, destination)) {
                // 中继按页对齐，用 MOVK 修正高 16 位，保留上游三指令入口。
                if ((target >> 48) != (destination >> 48) || (destination & 0xfff)) goto done;
                useMovk = true;
                destination = (target & ~0xffffffffULL) | (destination & 0xffffffffULL);
            }
        }
        patch[0] = assemble_adrp(target, reg, destination & ~(uintptr_t)0xfff);
        patch[1] = useMovk ? assemble_mov(1, MOVK_OP, 32, reg, ((uintptr_t)resources->relay >> 32) & 0xffff) :
            assemble_add(reg, reg, destination & 0xfff);
        patch[2] = assemble_br(BR_OP, reg, 0, PAC_NONE);
    }
#ifdef LH_ROOTHIDE
    if (headerRelay) {
        if (!LHPrepareShadowPage(target & ~PAGE_MASK) || !LHPrepareShadowPage(headerAddress & ~PAGE_MASK) ||
                !LHWriteMemoryInternal((void *)headerAddress, jump, JMPSIZ * 4)) goto done;
        headerStaged = true;
    }
#endif
    if (!LHWriteMemoryInternal((void *)target, patch, count * 4)) goto done;
#ifdef LH_ROOTHIDE
    LHQueueHookResources(resources);
#else
    if (old) *old = resources->original;
    free(resources);
#endif
    resources = NULL;
    result = LIBHOOKER_OK;
done:
    if (resources) {
        if (resources->trampoline) munmap(resources->trampoline, PAGE_SIZE);
        if (resources->relay) munmap(resources->relay, PAGE_SIZE);
        free(resources);
    }
#ifdef LH_ROOTHIDE
    if (headerRelay && !headerStaged) LHCancelHeaderRelay(headerRelay);
#endif
    return result;
}

// 整批 Hook 共用影子事务锁，失败向调用方返回真实状态。
LIBHOOKER_EXPORT int LHHookFunctions(const struct LHFunctionHook *hooks, int count) {
    if (!hooks || count < 0) { errno = LIBHOOKER_ERR_NO_SYMBOL; return 0; }
    LHLockMemory();
    int success = 0;
    errno = 0;
    for (int i = 0; i < count; i++) {
#if __APPLE__
        int reg = 16;
#else
        int reg = 18;
#endif
        if (hooks[i].options) {
#if TARGET_OS_IOS && __LP64__
            if ((uintptr_t)hooks[i].options & LHOptionsSetJumpReg) {
                const struct LHFunctionHookOld *legacy = (const void *)&hooks[i];
                reg = legacy->jmp_reg;
            } else
#endif
            if (hooks[i].options->options & LHOptionsSetJumpReg) reg = hooks[i].options->jmp_reg;
        }
        int result = reg < 0 || reg >= 31 ? LIBHOOKER_ERR_BAD_INSN_AT_START :
            LHHookFunction(hooks[i].function, hooks[i].replacement, hooks[i].oldptr, reg);
        if (result == LIBHOOKER_OK) success++; else errno = result;
    }
    if (!LHCommitShadowPages()) success = 0;
    int commitError = errno;
    LHUnlockMemory();
    errno = commitError;
    return success;
}
