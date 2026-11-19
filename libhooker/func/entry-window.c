#include "entry-window.h"

// BRK、HLT 的立即数不影响入口边界；UDF 也是常见的短陷阱桩。
bool LHIsTrapInstruction(uint32_t word) {
    return (word & 0xffe0001f) == 0xd4200000 || (word & 0xffe0001f) == 0xd4400000 ||
        (word >> 16) == 0;
}

// 以指令为单位解码相对目标，索引可以落在快照之外。
static int LHRelativeIndex(int index, uint32_t bits, unsigned width) {
    uint32_t sign = 1u << (width - 1);
    return index + (int)(bits & (sign - 1)) - (int)(bits & sign);
}

// 只接受快照内能闭合的控制流；回到覆盖区内部或无法确定后继时使用单条入口。
bool LHCanCoverThreeInstructions(const uint32_t *words, size_t count) {
    if (count < 3 || count > LH_ENTRY_SCAN_WORDS) return false;
    uint64_t pending = 1, visited = 0;
    while (pending) {
        int index = __builtin_ctzll(pending);
        uint64_t bit = UINT64_C(1) << index;
        visited |= bit;
        pending &= ~bit;
        uint32_t word = words[index];
        // 陷阱既可能终止进程，也可能由异常处理器恢复，不能推断后续入口。
        if (LHIsTrapInstruction(word)) return false;
        if (word == 0xd65f03c0 || (word & 0xfffffbff) == 0xd65f0bff) {
            if (index < 2) return false;
            continue;
        }
        int next = index + 1;
        int target;
        bool conditional = true;
        if ((word & 0xfc000000) == 0x14000000) {
            target = LHRelativeIndex(index, word, 26);
            conditional = false;
            if (index < 2) return false;
        } else if ((word & 0xff000000) == 0x54000000 || (word & 0x7e000000) == 0x34000000) {
            target = LHRelativeIndex(index, word >> 5, 19);
            if ((word & 0xff000000) == 0x54000000 && (word & 0xf) >= 0xe) {
                if (index < 2) return false;
                conditional = false;
            }
        } else if ((word & 0x7e000000) == 0x36000000) {
            target = LHRelativeIndex(index, word >> 5, 14);
        } else {
            // 调用、间接分支和异常的返回位置无法从这个快照证明。
            if ((word & 0xfc000000) == 0x94000000 || (word & 0xfe000000) == 0xd6000000 ||
                    (word & 0xff000000) == 0xd4000000) return false;
            target = next;
            conditional = false;
        }
        if (target < 0 || (size_t)target >= count || (index >= 3 && target > 0 && target < 3))
            return false;
        pending |= (UINT64_C(1) << target) & ~visited;
        if (conditional) {
            if ((size_t)next >= count) return false;
            pending |= (UINT64_C(1) << next) & ~visited;
        }
    }
    return true;
}
