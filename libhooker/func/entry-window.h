#ifndef LH_ENTRY_WINDOW_H
#define LH_ENTRY_WINDOW_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

// 一个 64 位工作集即可覆盖整次分析，不分配内存。
#define LH_ENTRY_SCAN_WORDS 64

bool LHIsTrapInstruction(uint32_t word);
bool LHCanCoverThreeInstructions(const uint32_t *words, size_t count);

#endif
