#ifndef LH_LEGACY_MEMORY_H
#define LH_LEGACY_MEMORY_H
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <stdbool.h>
#include <stddef.h>

bool LHPrepareLegacyMemory(void);
kern_return_t LHLegacyProtect(vm_map_t task, mach_vm_address_t address,
    mach_vm_size_t size, boolean_t maximum, vm_prot_t protection);
kern_return_t LHLegacyPatch(void *destination, const void *source, size_t size);
#endif
