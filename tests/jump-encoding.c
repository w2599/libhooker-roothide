// 检查真实跳转编码、条件重定位及分配次数，不执行生成的机器码。
#include <assert.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../libhooker/func/entry-window.h"

static unsigned allocations;
static size_t allocationSize;
static bool failAllocation;

// 统计生产编码器的堆分配，并可模拟唯一一次分配失败。
static void *countedMalloc(size_t size) {
    allocations++;
    allocationSize = size;
    return failAllocation ? NULL : malloc(size);
}

#define malloc countedMalloc
#include "../libhooker/as-aarch64/as-aarch64.c"
#include "../libhooker/disas-aarch64/disas-aarch64.c"
#undef malloc

// 使用固定指令模板独立核对地址四个半字、寄存器及链接位。
static void expectJump(const uint32_t *code, uint64_t target, unsigned reg, bool link) {
    const uint32_t bases[] = {0xd2800000, 0xf2a00000, 0xf2c00000, 0xf2e00000};
    for (unsigned i = 0; i < JMPSIZ - 1; i++)
        assert(code[i] == (bases[i] | ((uint32_t)((target >> (i * 16)) & 0xffff) << 5) | reg));
    assert(code[JMPSIZ - 1] == ((link ? 0xd63f0000U : 0xd61f0000U) | (reg << 5)));
}

// 全寄存器和完整地址验证写入式接口零分配、包装接口一次分配及边界保护。
static void testAbsoluteJump(void) {
    const uint64_t addresses[] = {0, 0x123456789abcdef0ULL, UINT64_MAX, 0x100000000ULL};
    for (unsigned a = 0; a < sizeof(addresses) / sizeof(*addresses); a++) {
        for (unsigned reg = 0; reg < 31; reg++) {
            for (unsigned link = 0; link < 2; link++) {
                uint32_t output[JMPSIZ + 2] = {[0] = 0xfeedface, [JMPSIZ + 1] = 0xfeedface};
                allocations = 0;
                assert(assemble_jmp_into(output + 1, addresses[a], link, reg));
                assert(!allocations && output[0] == 0xfeedface && output[JMPSIZ + 1] == 0xfeedface);
                expectJump(output + 1, addresses[a], reg, link);
                uint32_t *allocated = assemble_jmp(addresses[a], link, reg);
                assert(allocated && allocations == 1 && allocationSize == JMPSIZ * sizeof(uint32_t));
                expectJump(allocated, addresses[a], reg, link);
                free(allocated);
            }
        }
    }
    uint32_t output[JMPSIZ], baseline[JMPSIZ];
    memset(output, 0xa5, sizeof(output));
    memcpy(baseline, output, sizeof(output));
    allocations = 0;
    assert(!assemble_jmp_into(NULL, 0, false, 16));
    assert(!assemble_jmp_into(output, 0, false, 31));
    assert(!assemble_jmp_into(output, 0, true, UINT8_MAX));
    assert(!memcmp(output, baseline, sizeof(output)) && !allocations);
    assert(!assemble_jmp(0, false, 31) && !allocations);
    failAllocation = true;
    assert(!assemble_jmp(0, false, 16) && allocations == 1);
    failAllocation = false;
}

// 覆盖三类条件跳转的正负边界、分支变体和内部目标重写，固定长度内只分配一次。
static void testConditionalRelocation(void) {
    const unsigned indices[] = {1, 2, 4};
    const uint64_t pc = 0x123456789000ULL, rewrittenTarget = 0xfedcba9876543210ULL;
    for (unsigned kind = 0; kind < 3; kind++) {
        const struct disasm_reg_t *handler = &disasm_registry[indices[kind]];
        uint32_t mask = kind == 1 ? 0x3fff : 0x7ffff;
        int32_t limit = (mask + 1) / 2;
        const int32_t displacements[] = {-limit, -1, 0, 1, limit - 1};
        if (kind == 2) assert(!handler->is_op(0x55000000));
        for (unsigned variant = 0; variant < (kind == 2 ? 32 : 4); variant++) {
            uint32_t base = kind == 0 ? 0x3400001f : kind == 1 ? 0x36f8001f : 0x54000000 | variant;
            if (kind != 2) base |= ((variant & 1) << 24) | ((variant >> 1) << 31);
            for (unsigned d = 0; d < sizeof(displacements) / sizeof(*displacements); d++) {
                uint32_t opcode = base | (((uint32_t)displacements[d] & mask) << 5);
                assert(handler->is_op(opcode) && LHIsBranch(opcode));
                for (unsigned rewrite = 0; rewrite < 2; rewrite++) {
                    uint64_t target = 0, expected = rewrite ? rewrittenTarget : pc + (int64_t)displacements[d] * 4;
                    allocations = 0;
                    uint32_t *code = rewrite ? handler->rehandle_op(opcode, 17, expected) :
                        handler->handle_op(pc, opcode, 17, &target);
                    size_t prefix = kind == 2 ? 2 : 1;
                    assert(code && allocations == 1 && allocationSize == handler->tramp_size);
                    assert(allocationSize == (JMPSIZ + prefix) * sizeof(uint32_t));
                    assert(rewrite || target == expected);
                    if (kind == 2) {
                        assert(code[0] == (0x54000040 | (variant & 0xf)));
                        assert(code[1] == (0x14000000 | (JMPSIZ + 1)));
                    } else {
                        assert(code[0] == ((base ^ 0x01000000) | ((JMPSIZ + 1) << 5)));
                    }
                    expectJump(code + prefix, expected, 17, false);
                    free(code);
                }
            }
        }
        allocations = 0;
        assert(!handler->rehandle_op(0, 31, pc) && !handler->handle_op(pc, 0, 31, NULL) && !allocations);
        failAllocation = true;
        assert(!handler->rehandle_op(0, 17, pc) && allocations == 1);
        assert(!handler->handle_op(pc, 0, 17, NULL) && allocations == 2);
        failAllocation = false;
    }
}

// 用只读指令样本检查覆盖窗口，不生成或执行补丁。
static void testEntryWindow(void) {
    const uint32_t nop = 0xd503201f, ret = 0xd65f03c0;
    uint32_t code[LH_ENTRY_SCAN_WORDS];
    for (size_t i = 0; i < LH_ENTRY_SCAN_WORDS; i++) code[i] = nop;
    assert(!LHCanCoverThreeInstructions(code, 2));
    assert(!LHCanCoverThreeInstructions(code, LH_ENTRY_SCAN_WORDS));
    code[LH_ENTRY_SCAN_WORDS - 1] = ret;
    assert(LHCanCoverThreeInstructions(code, LH_ENTRY_SCAN_WORDS));
    code[3] = ret;
    assert(LHCanCoverThreeInstructions(code, 4));
    const uint32_t traps[] = {0xd4200000, 0xd43fffe0, 0xd4400000, 0xd45fffe0};
    for (size_t i = 0; i < sizeof(traps) / sizeof(*traps); i++) {
        code[0] = traps[i];
        assert(LHIsTrapInstruction(code[0]) && !LHCanCoverThreeInstructions(code, 4));
        code[0] = nop;
        code[1] = traps[i];
        assert(!LHCanCoverThreeInstructions(code, 4));
        code[1] = nop;
    }
    // 从第四条跳回第二条或第三条；覆盖 B、BL、条件、比较和测试位分支。
    const uint32_t backEdges[] = {0x17fffffe, 0x97ffffff, 0x54ffffc0,
        0x54ffffd0, 0xb5ffffe0, 0x37ffffc0};
    code[4] = ret;
    for (size_t i = 0; i < sizeof(backEdges) / sizeof(*backEdges); i++) {
        code[3] = backEdges[i];
        assert(!LHCanCoverThreeInstructions(code, 5));
    }
    code[0] = 0x34000080; // 条件跳到第五条，另一条路径提前返回。
    code[3] = ret;
    code[4] = 0x17fffffe;
    assert(!LHCanCoverThreeInstructions(code, 5));
    code[4] = ret;
    assert(LHCanCoverThreeInstructions(code, 5));
    assert(!LHCanCoverThreeInstructions(code, 4)); // 跳出快照。
    code[0] = nop;
    code[3] = 0xd61f0200; // 间接跳转去向未知。
    assert(!LHCanCoverThreeInstructions(code, 5));
    code[3] = 0x14000000; // 窗口外的自循环可以结束分析。
    assert(LHCanCoverThreeInstructions(code, 4));
}

// 一次运行覆盖编码语义和分配失败，交由宿主脚本启用 ASan/UBSan。
int main(void) {
    testAbsoluteJump();
    testConditionalRelocation();
    testEntryWindow();
    puts("jump-encoding: exact opcodes, relocation boundaries and allocation counts passed");
    return 0;
}
