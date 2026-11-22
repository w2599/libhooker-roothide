//
//  disas-aarch64.c
//  libhooker
//
//  Created by CoolStar on 2/21/20.
//  Copyright © 2020 CoolStar. All rights reserved.
//

#include "funcMacros.h"
#include "disas-aarch64.h"
#include "../as-aarch64/as-aarch64.h"

// 按实际符号位扩展立即数，保留向前和向后的目标地址。
privateFunc int64_t signExtendImmediate(uint64_t immediate, uint8_t signBit){
    uint64_t sign = 1ULL << signBit;
    return (int64_t)(immediate & (sign - 1)) - (int64_t)(immediate & sign);
}

// 识别 CBZ 与 CBNZ。
privateFunc bool is_cbz(uint32_t opcode){
    return ((opcode >> 25) & 0x3f) == 0b011010;
}

// 生成反条件跳过绝对跳转的 CBZ/CBNZ 序列。
privateFunc uint32_t *rehandle_cbz(uint32_t opcode, uint8_t jmp_reg, uint64_t targetAddr) {
    if (jmp_reg >= 31) return NULL;
    uint8_t sf = (opcode >> 31) & 0x1; // 1 为 64 位，0 为 32 位。
    uint8_t op = (opcode >> 24) & 0x1; // 0 为 CBZ，1 为 CBNZ。
    uint8_t reg = (opcode & 0x1f); // 可包含零寄存器。

    uint32_t *opcodes = malloc((JMPSIZ + 1) * sizeof(*opcodes));
    if (!opcodes) return NULL;
    opcodes[0] = assemble_cbz(sf, (~op) & 0x1, reg, (JMPSIZ + 1) * sizeof(uint32_t));
    assemble_jmp_into(&opcodes[1], targetAddr, false, jmp_reg);
    return opcodes;
}

// 按 19 位有符号立即数重定位原指令。
privateFunc uint32_t *handle_cbz(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr) {
    if (jmp_reg >= 31) return NULL;
    dasmDbgPrint("[disasm] pc: 0x%llx, opcode: 0x%x (cbz/cbnz)\n", pc, opcode);

    uint32_t imm19 = (opcode >> 5) & 0x7ffff;
    int32_t offset = signExtendImmediate(imm19, 18) * 4;

    uint64_t targetAddr = pc + offset;
    dasmDbgPrint("[disasm] target address: 0x%llx\n", targetAddr);

    if (target_adr){
        *target_adr = targetAddr;
    }

    return rehandle_cbz(opcode, jmp_reg, targetAddr);
}

// 识别 TBZ 与 TBNZ。
privateFunc bool is_tbz(uint32_t opcode){
    return ((opcode >> 25) & 0x3f) == 0b011011;
}

// 生成反条件跳过绝对跳转的 TBZ/TBNZ 序列。
privateFunc uint32_t *rehandle_tbz(uint32_t opcode, uint8_t jmp_reg, uint64_t targetAddr) {
    if (jmp_reg >= 31) return NULL;
    uint8_t sf = (opcode >> 31) & 0x1; // 1 为 64 位，0 为 32 位。
    uint8_t op = (opcode >> 24) & 0x1; // 0 为 TBZ，1 为 TBNZ。
    uint8_t reg = (opcode & 0x1f); // 可包含零寄存器。

    uint16_t b40 = (opcode >> 19) & 0x1f;
    b40 |= (sf << 5);

    uint32_t *opcodes = malloc((JMPSIZ + 1) * sizeof(*opcodes));
    if (!opcodes) return NULL;
    opcodes[0] = assemble_tbz(b40, (~op) & 0x1, reg, (JMPSIZ + 1) * sizeof(uint32_t));
    assemble_jmp_into(&opcodes[1], targetAddr, false, jmp_reg);
    return opcodes;
}

// 按 14 位有符号立即数重定位原指令。
privateFunc uint32_t *handle_tbz(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr) {
    if (jmp_reg >= 31) return NULL;
    dasmDbgPrint("[disasm] pc: 0x%llx, opcode: 0x%x (tbz/tbnz)\n", pc, opcode);

    uint16_t imm14 = (opcode >> 5) & 0x3fff;
    int16_t offset = signExtendImmediate(imm14, 13) * 4;

    uint64_t targetAddr = pc + offset;
    dasmDbgPrint("[disasm] target address: 0x%llx\n", targetAddr);

    if (target_adr){
        *target_adr = targetAddr;
    }

    return rehandle_tbz(opcode, jmp_reg, targetAddr);
}

// 识别 B 与 BL。
privateFunc bool is_b(uint32_t opcode){
    return ((opcode >> 26) & 0x1f) == 0b00101;
}

// 只把无链接 B 识别为当前基本块的出口。
bool is_bExit(uint32_t opcode){
    uint8_t op = (opcode >> 31) & 0x01; // 0 为 B，1 为 BL。
    return op == 0 && is_b(opcode);
}

// 生成 B/BL 的绝对跳转序列。
privateFunc uint32_t *rehandle_b(uint32_t opcode, uint8_t jmp_reg, uint64_t targetAddr) {
    if (jmp_reg >= 31) return NULL;
    uint8_t op = (opcode >> 31) & 0x01; // 0 为 B，1 为 BL。

    return assemble_jmp(targetAddr, op == BLR_OP, jmp_reg);
}

// 按 26 位有符号立即数重定位原指令。
privateFunc uint32_t *handle_b(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr) {
    if (jmp_reg >= 31) return NULL;
    dasmDbgPrint("[disasm] pc: 0x%llx, opcode: 0x%x (b)\n", pc, opcode);

    uint32_t imm26 = opcode & 0x3ffffff;
    int32_t offset = signExtendImmediate(imm26, 25) * 4;

    uint64_t targetAddr = pc + offset;
    dasmDbgPrint("[disasm] target address: 0x%llx\n", targetAddr);

    if (target_adr){
        *target_adr = targetAddr;
    }

    return rehandle_b(opcode, jmp_reg, targetAddr);
}

// 保留条件码，以双分支转入绝对跳转序列。
privateFunc uint32_t *rehandle_bCond(uint32_t opcode, uint8_t jmp_reg, uint64_t targetAddr) {
    if (jmp_reg >= 31) return NULL;
    uint8_t cond = opcode & 0xf;

    uint32_t *opcodes = malloc((JMPSIZ + 2) * sizeof(*opcodes));
    if (!opcodes) return NULL;
    opcodes[0] = assemble_bcond(cond, 2 * sizeof(uint32_t));

    uint32_t b = assemble_b((JMPSIZ + 1) * sizeof(uint32_t));
    opcodes[1] = b;

    assemble_jmp_into(&opcodes[2], targetAddr, false, jmp_reg);

    return opcodes;
}

// 按 19 位有符号立即数重定位原指令。
privateFunc uint32_t *handle_bCond(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr) {
    if (jmp_reg >= 31) return NULL;
    dasmDbgPrint("[disasm] pc: 0x%llx, opcode: 0x%x (b.Cond) \n", pc, opcode);

    uint32_t imm19 = (opcode >> 5) & 0x7ffff;
    int32_t offset = signExtendImmediate(imm19, 18) * 4;

    uint64_t targetAddr = pc + offset;
    dasmDbgPrint("[disasm] target address: 0x%llx\n", targetAddr);

    if (target_adr){
        *target_adr = targetAddr;
    }

    return rehandle_bCond(opcode, jmp_reg, targetAddr);
}

// 识别整数 literal load，PRFM 由更早的注册项处理。
privateFunc bool is_ldr(uint32_t opcode){
    return ((opcode >> 24) & 0x3f) == 0b011000;
}

// 将整数 literal load 的原始地址保存在其目的寄存器中。
privateFunc uint32_t *rehandle_ldr(uint32_t opcode, uint8_t jmp_reg, uint64_t targetAddr) {
    uint8_t sig = (opcode >> 31) & 0x1; // 是否符号扩展。
    uint8_t sf = (opcode >> 30) & 0x1; //xN or wN register (1 = 64 bit; 0 = 32 bit)
    uint8_t reg = opcode & 0x1f;
    if (reg == 31) return NULL;

    uint32_t *opcodes = malloc((JMPSIZ) * sizeof(*opcodes));
    if (!opcodes) return NULL;
    opcodes[0] = assemble_mov(1, MOVZ_OP, 0, reg, targetAddr & 0xffff);
    opcodes[1] = assemble_mov(1, MOVK_OP, 16, reg, (targetAddr >> 16) & 0xffff);
#if __LP64__
    opcodes[2] = assemble_mov(1, MOVK_OP, 32, reg, (targetAddr >> 32) & 0xffff);
    opcodes[3] = assemble_mov(1, MOVK_OP, 48, reg, (targetAddr >> 48) & 0xffff);
    opcodes[4] = assemble_ldr(sf, sig ? LDRSW_OP : LDR_OP, reg, reg);
#else
    opcodes[2] = assemble_ldr(sf, sig ? LDRSW_OP : LDR_OP, reg, reg);
#endif
    return opcodes;
}

// 按 19 位有符号立即数重定位原指令。
privateFunc uint32_t *handle_ldr(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr) {
    dasmDbgPrint("[disasm] pc: 0x%llx, opcode: 0x%x (ldr/ldrsw [literal])\n", pc, opcode);

    uint32_t imm19 = (opcode >> 5) & 0x7ffff;
    int32_t offset = signExtendImmediate(imm19, 18) * 4;

    uint64_t targetAddr = pc + offset;
    dasmDbgPrint("[disasm] target address: 0x%llx\n", targetAddr);

    if (target_adr){
        *target_adr = targetAddr;
    }

    return rehandle_ldr(opcode, jmp_reg, targetAddr);
}

// 识别尚未支持的 SIMD/FP literal load。
privateFunc bool is_ldr_simd_fp(uint32_t opcode){
    return ((opcode >> 24) & 0x3f) == 0b011100;
}

// 未实现的 SIMD/FP literal load 返回失败，由调用方拒绝 Hook。
privateFunc uint32_t *handle_ldr_simd_fp(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr){
    dasmDbgPrint("[disasm] pc: 0x%llx, opcode: 0x%x (ldr [simd/fp])\n", pc, opcode);

    return NULL;
}

// 识别 PRFM，避免按整数 literal load 重定位。
privateFunc bool is_prfm(uint32_t opcode){
    return ((opcode >> 24) & 0xff) == 0b11011000;
}

// 把预取提示写为 NOP。
privateFunc uint32_t *handle_prfm(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr) {
    dasmDbgPrint("[disasm] pc: 0x%llx, opcode: 0x%x (prfm)\n", pc, opcode);

    uint32_t *opcodes = malloc((1) * sizeof(*opcodes));
    if (!opcodes) return NULL;
    opcodes[0] = assemble_nop();
    return opcodes;
}

// 识别 ADR 与 ADRP。
privateFunc bool is_adr(uint32_t opcode){
    return ((opcode >> 24) & 0x1f) == 0b10000;
}

// 用 MOV 序列保留 ADR/ADRP 的完整原始地址。
privateFunc uint32_t *rehandle_adr(uint32_t opcode, uint8_t jmp_reg, uint64_t targetAddr) {
    uint8_t reg = opcode & 0x1f;
    if (reg == 31) return NULL;

    uint32_t *opcodes = malloc((JMPSIZ - 1) * sizeof(*opcodes));
    if (!opcodes) return NULL;
    opcodes[0] = assemble_mov(1, MOVZ_OP, 0, reg, targetAddr & 0xffff);
    opcodes[1] = assemble_mov(1, MOVK_OP, 16, reg, (targetAddr >> 16) & 0xffff);
#if __LP64__
    opcodes[2] = assemble_mov(1, MOVK_OP, 32, reg, (targetAddr >> 32) & 0xffff);
    opcodes[3] = assemble_mov(1, MOVK_OP, 48, reg, (targetAddr >> 48) & 0xffff);
#endif
    return opcodes;
}

// 解码 ADR/ADRP 的 PC 相对目标，再复用同一个绝对取址编码器。
privateFunc uint32_t *handle_adr(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr) {
    dasmDbgPrint("[disasm] pc: 0x%llx, opcode: 0x%x (adr/adrp])\n", pc, opcode);
    uint8_t op = (opcode >> 31) & 0x1; // 0 为 ADR，1 为 ADRP。

    uint32_t immhi = (opcode >> 5) & 0x7ffff;
    uint8_t immlo = (opcode >> 29) & 0x3;

    uint64_t imm = (immhi << 2) | immlo; // 21 位立即数。
    if (op == 1){
        imm = imm << 12;
        pc = pc & ~0xfff; // ADRP 使用 4 KiB 页基址。
    }

    int64_t offset = signExtendImmediate(imm, op ? 32 : 20);

    uint64_t targetAddr = pc + offset;
    dasmDbgPrint("[disasm] target address: 0x%llx\n", targetAddr);

    if (target_adr){
        *target_adr = targetAddr;
    }

    return rehandle_adr(opcode, jmp_reg, targetAddr);
}

// 识别返回指令，保持注册表首项约定。
privateFunc bool is_ret(uint32_t opcode) {
    return (((opcode >> 25) & 0x7f) == 0b1101011) && (((opcode >> 21) & 0xf) == 0b10);
}

// 分配并复制返回指令。
privateFunc uint32_t *handle_ret(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr) {
    dasmDbgPrint("[disasm] pc: 0x%llx, opcode: 0x%x (ret)\n", pc, opcode);

    uint32_t *opcodes = malloc((1) * sizeof(*opcodes));
    if (!opcodes) return NULL;
    opcodes[0] = opcode;
    return opcodes;
}

// 匹配余下指令，保持注册表最后一项约定。
privateFunc bool is_nullop(uint32_t opcode){
    return true;
}

// 复制不需要 PC 重定位的普通指令。
privateFunc uint32_t *handle_nullop(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr) {
    dasmDbgPrint("[disasm] pc: 0x%llx, opcode: 0x%x (unhandled)\n", pc, opcode);

    uint32_t *opcodes = malloc((1) * sizeof(*opcodes));
    if (!opcodes) return NULL;
    opcodes[0] = opcode;
    return opcodes;
}

struct disasm_reg_t disasm_registry[] = {
    {&is_ret, &handle_ret, NULL, 1 * sizeof(uint32_t)}, // 首项必须为返回指令。
    {&is_cbz, &handle_cbz, &rehandle_cbz, (JMPSIZ + 1) * sizeof(uint32_t)},
    {&is_tbz, &handle_tbz, &rehandle_tbz, (JMPSIZ + 1) * sizeof(uint32_t)},
    {&is_b, &handle_b, &rehandle_b, JMPSIZ * sizeof(uint32_t)},
    {&LHIsConditionCodeBranch, &handle_bCond, &rehandle_bCond, (JMPSIZ + 2) * sizeof(uint32_t)},
    // PRFM 与整数 LDR 共用主编码，必须先识别预取指令。
    {&is_prfm, &handle_prfm, NULL, 1 * sizeof(uint32_t)},
    {&is_ldr, &handle_ldr, &rehandle_ldr, JMPSIZ * sizeof(uint32_t)},
    {&is_ldr_simd_fp, &handle_ldr_simd_fp, NULL, 0},
    {&is_adr, &handle_adr, &rehandle_adr, (JMPSIZ - 1) * sizeof(uint32_t)},
    {&is_nullop, &handle_nullop, NULL, 1 * sizeof(uint32_t)}
};

// 返回上游分配式重定位回调及每项生成长度。
void LHGetDisasmRegistry(struct disasm_reg_t **disasm_reg, int *size){
    *disasm_reg = (struct disasm_reg_t *)&disasm_registry;
    *size = sizeof(disasm_registry)/sizeof(struct disasm_reg_t);
}
