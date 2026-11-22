//
//  disas-aarch64.h
//  libhooker
//
//  Created by CoolStar on 2/21/20.
//  Copyright © 2020 CoolStar. All rights reserved.
//
#include <stdint.h>
#include <stdbool.h>

#ifndef disas_aarch64_h
#define disas_aarch64_h

#if DEBUG
#define DASMDBG 0
#else
#define DASMDBG 0
#endif

#if DASMDBG
#define dasmDbgPrint debugPrint
#else
#define dasmDbgPrint(...)
#endif

typedef bool (*is_opcode)(uint32_t);
typedef uint32_t *(*handle_opcode)(uint64_t, uint32_t, uint8_t, uint64_t *);
typedef uint32_t *(*rehandle_opcode)(uint32_t, uint8_t, uint64_t);

typedef struct disasm_reg_t {
    is_opcode is_op;
    handle_opcode handle_op;
    rehandle_opcode rehandle_op;
    int tramp_size;
} disasm_reg;

// B.cond 和 BC.cond 共用高字节；入口检查与原调用的目标校验须采用同一判定。
static inline bool LHIsConditionCodeBranch(uint32_t word) {
    return (word & 0xff000000) == 0x54000000;
}

// 仅分支目标随被覆盖的指令移动，普通取址指令保留原地址。
static inline bool LHIsBranch(uint32_t opcode) {
    return (opcode & 0x7c000000) == 0x14000000 ||
        (opcode & 0x7e000000) == 0x34000000 ||
        (opcode & 0x7e000000) == 0x36000000 ||
        LHIsConditionCodeBranch(opcode);
}

void LHGetDisasmRegistry(struct disasm_reg_t **disasm_reg, int *size);

bool is_bExit(uint32_t opcode);
#if DEBUG
uint32_t *handle_cbz(uint64_t pc, uint32_t op, uint8_t jmp_reg, uint64_t *target_adr);
uint32_t *handle_tbz(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr);
uint32_t *handle_b(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr);
uint32_t *handle_bCond(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr);
uint32_t *handle_ldr(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr);
uint32_t *handle_prfm(uint64_t pc, uint32_t opcode, uint8_t jmp_reg, uint64_t *target_adr);
#endif

#endif /* disas_aarch64_h */
