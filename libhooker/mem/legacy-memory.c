// Dopamine 2 使用进程自身的调试权限，不依赖 Dopamine 3 的内存服务导出。
#include "legacy-memory.h"
#include "writeMem.h"
#include <libkern/OSCacheControl.h>
#include <ptrauth.h>
#include <stdatomic.h>
#include <stdint.h>
#include <string.h>

extern const uint8_t LHLegacyWriterStart[], LHLegacyWriterEnd[];
typedef kern_return_t (*LHLegacyWriter)(vm_map_t, void *, const void *, size_t, vm_prot_t);
static _Atomic(LHLegacyWriter) legacyWriter;

// 在线程暂停前创建独立执行页，目标页包含补丁器自身时也不会从可写页继续取指。
bool LHPrepareLegacyMemory(void) {
    if (atomic_load_explicit(&legacyWriter, memory_order_acquire)) return true;
    size_t size = (uintptr_t)LHLegacyWriterEnd - (uintptr_t)LHLegacyWriterStart;
    if (!size || size > vm_page_size) return false;
    mach_vm_address_t page = 0;
    if (mach_vm_allocate(mach_task_self(), &page, vm_page_size, VM_FLAGS_ANYWHERE) != KERN_SUCCESS) return false;
    memcpy((void *)page, LHLegacyWriterStart, size);
    sys_icache_invalidate((void *)page, size);
    if (LHLegacyProtect(mach_task_self(), page, vm_page_size, false,
            VM_PROT_READ | VM_PROT_EXECUTE) != KERN_SUCCESS) {
        mach_vm_deallocate(mach_task_self(), page, vm_page_size);
        return false;
    }
    LHLegacyWriter writer = ptrauth_sign_unauthenticated((void *)page, ptrauth_key_function_pointer, 0);
    LHLegacyWriter expected = NULL;
    if (!atomic_compare_exchange_strong_explicit(&legacyWriter, &expected, writer,
            memory_order_acq_rel, memory_order_acquire)) {
        mach_vm_deallocate(mach_task_self(), page, vm_page_size);
    }
    return true;
}

// 独立写入器完成 COW、拷贝和权限恢复；暂停区内不分配内存或解析符号。
kern_return_t LHLegacyPatch(void *destination, const void *source, size_t size) {
    LHLegacyWriter writer = atomic_load_explicit(&legacyWriter, memory_order_acquire);
    uint32_t protection;
    if (!writer || !destination || !source || size != vm_page_size ||
            !LHGetMemoryProtection((uintptr_t)destination, &protection)) return KERN_INVALID_ARGUMENT;
    return writer(mach_task_self(), destination, source, size, protection);
}
