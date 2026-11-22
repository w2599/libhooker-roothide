// 仅供短函数及特殊前缀兼容；近页不可用时检查目标 __TEXT 的头部零填充。
#include "header-relay.h"
#include <dlfcn.h>
#include <mach/mach.h>
#include <mach/mach_vm.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach-o/reloc.h>
#include <stdlib.h>
#include <string.h>

#define LH_MAX_RELAY_BYTES 32
#define LH_MAX_LOAD_COMMAND_BYTES (1024 * 1024)
#define LH_MAX_PADDING_SCAN (64 * 1024)

struct LHHeaderRelay {
    uintptr_t address;
    uintptr_t target;
    size_t size;
    uintptr_t headerAddress;
    struct mach_header_64 header;
    uint8_t *commands;
    struct LHHeaderRelay *next;
};
static struct LHHeaderRelay *pending;
static struct LHHeaderRelay *retained;

// 通过内核有界读取，镜像已卸载或不可读时返回失败而不直接解引用地址。
static bool LHReadBytes(uintptr_t address, void *output, size_t size) {
    if (!address || !output || !size || size > UINTPTR_MAX - address) return false;
    mach_vm_size_t copied = 0;
    return mach_vm_read_overwrite(mach_task_self(), address, size,
        (mach_vm_address_t)output, &copied) == KERN_SUCCESS && copied == size;
}

// 检查完整槽位位于同一个实际 RX 映射和内存页，不根据段声明推测权限。
static bool LHRelayIsRX(uintptr_t address, size_t size) {
    size_t pageSize = vm_page_size;
    if (!pageSize || !size || size > UINTPTR_MAX - address ||
            address / pageSize != (address + size - 1) / pageSize) return false;
    natural_t depth = 0;
    for (unsigned iteration = 0; iteration < 32; iteration++) {
        mach_vm_address_t region = address;
        mach_vm_size_t length = 0;
        vm_region_submap_info_data_64_t info;
        mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
        kern_return_t result = mach_vm_region_recurse(mach_task_self(), &region, &length,
            &depth, (vm_region_recurse_info_t)&info, &count);
        if (result != KERN_SUCCESS || region > address || address - region > length ||
                size > length - (address - region)) return false;
        if (info.is_submap) { depth++; continue; }
        return info.protection == (VM_PROT_READ | VM_PROT_EXECUTE);
    }
    return false;
}

// 不借助带符号差值，直接检查单条 B 的精确可达范围。
static bool LHRelayReachable(uintptr_t target, uintptr_t address) {
    if ((target | address) & 3) return false;
    return address >= target ? address - target <= 0x7fffffcULL : target - address <= 0x8000000ULL;
}

// 取得一个完整且八字节对齐的加载命令，拒绝截断和越界。
static const struct load_command *LHRelayCommand(const struct LHHeaderRelay *relay, size_t offset) {
    size_t size = relay->header.sizeofcmds;
    if ((offset & 7) || offset > size || sizeof(struct load_command) > size - offset) return NULL;
    const struct load_command *command = (const void *)(relay->commands + offset);
    if (command->cmdsize < sizeof(*command) || (command->cmdsize & 7) ||
            command->cmdsize > size - offset) return NULL;
    return command;
}

// 文件偏移形式的元数据也必须与候选填充区分离，不能只检查 section。
static bool LHFileDataOutside(uint64_t offset, uint64_t size, uint64_t lower, uint64_t upper) {
    if (!size) return true;
    if (size > UINT64_MAX - offset) return false;
    return offset >= upper || offset + size <= lower;
}

// 名称类命令的第三个字段是 lc_str 偏移，字符串必须完整落在固定头之后。
static bool LHRelayHasInlineName(const struct load_command *command, size_t headerSize) {
    if (command->cmdsize < headerSize) return false;
    uint32_t offset;
    memcpy(&offset, command + 1, sizeof(offset));
    return offset >= headerSize && offset < command->cmdsize &&
        memchr((const char *)command + offset, '\0', command->cmdsize - offset) != NULL;
}

// 只接受用途已知的加载命令，并拒绝指向候选区的显式文件数据。
static bool LHRelayMetadataOutside(const struct load_command *command, uint64_t lower, uint64_t upper) {
    switch (command->cmd) {
        case LC_SEGMENT_64: case LC_UUID: case LC_PREBIND_CKSUM:
        case LC_VERSION_MIN_MACOSX: case LC_VERSION_MIN_IPHONEOS: case LC_VERSION_MIN_TVOS:
        case LC_VERSION_MIN_WATCHOS: case LC_SOURCE_VERSION: case LC_BUILD_VERSION:
            return true;
        case LC_SUB_FRAMEWORK: case LC_SUB_CLIENT: case LC_SUB_LIBRARY: case LC_SUB_UMBRELLA:
            return LHRelayHasInlineName(command, sizeof(struct sub_framework_command));
        case LC_RPATH: case LC_LOAD_DYLINKER: case LC_ID_DYLINKER: case LC_DYLD_ENVIRONMENT:
            return LHRelayHasInlineName(command, sizeof(struct dylinker_command));
        case LC_ID_DYLIB: case LC_LOAD_DYLIB: case LC_LOAD_WEAK_DYLIB: case LC_REEXPORT_DYLIB:
        case LC_LAZY_LOAD_DYLIB: case LC_LOAD_UPWARD_DYLIB:
            return LHRelayHasInlineName(command, sizeof(struct dylib_command));
        case LC_CODE_SIGNATURE: case LC_SEGMENT_SPLIT_INFO: case LC_FUNCTION_STARTS:
        case LC_DATA_IN_CODE: case LC_DYLIB_CODE_SIGN_DRS: case LC_LINKER_OPTIMIZATION_HINT:
        case LC_DYLD_EXPORTS_TRIE: case LC_DYLD_CHAINED_FIXUPS: {
            if (command->cmdsize < sizeof(struct linkedit_data_command)) return false;
            const struct linkedit_data_command *data = (const void *)command;
            return LHFileDataOutside(data->dataoff, data->datasize, lower, upper);
        }
        case LC_SYMTAB: {
            if (command->cmdsize < sizeof(struct symtab_command)) return false;
            const struct symtab_command *data = (const void *)command;
            return LHFileDataOutside(data->symoff, (uint64_t)data->nsyms * sizeof(struct nlist_64), lower, upper) &&
                LHFileDataOutside(data->stroff, data->strsize, lower, upper);
        }
        case LC_DYSYMTAB: {
            if (command->cmdsize < sizeof(struct dysymtab_command)) return false;
            const struct dysymtab_command *data = (const void *)command;
            return LHFileDataOutside(data->tocoff, (uint64_t)data->ntoc * sizeof(struct dylib_table_of_contents), lower, upper) &&
                LHFileDataOutside(data->modtaboff, (uint64_t)data->nmodtab * sizeof(struct dylib_module_64), lower, upper) &&
                LHFileDataOutside(data->extrefsymoff, (uint64_t)data->nextrefsyms * sizeof(struct dylib_reference), lower, upper) &&
                LHFileDataOutside(data->indirectsymoff, (uint64_t)data->nindirectsyms * sizeof(uint32_t), lower, upper) &&
                LHFileDataOutside(data->extreloff, (uint64_t)data->nextrel * sizeof(struct relocation_info), lower, upper) &&
                LHFileDataOutside(data->locreloff, (uint64_t)data->nlocrel * sizeof(struct relocation_info), lower, upper);
        }
        case LC_DYLD_INFO: case LC_DYLD_INFO_ONLY: {
            if (command->cmdsize < sizeof(struct dyld_info_command)) return false;
            const struct dyld_info_command *data = (const void *)command;
            return LHFileDataOutside(data->rebase_off, data->rebase_size, lower, upper) &&
                LHFileDataOutside(data->bind_off, data->bind_size, lower, upper) &&
                LHFileDataOutside(data->weak_bind_off, data->weak_bind_size, lower, upper) &&
                LHFileDataOutside(data->lazy_bind_off, data->lazy_bind_size, lower, upper) &&
                LHFileDataOutside(data->export_off, data->export_size, lower, upper);
        }
        case LC_ENCRYPTION_INFO: case LC_ENCRYPTION_INFO_64: {
            size_t minimum = command->cmd == LC_ENCRYPTION_INFO ? sizeof(struct encryption_info_command) :
                sizeof(struct encryption_info_command_64);
            if (command->cmdsize < minimum) return false;
            const struct encryption_info_command *data = (const void *)command;
            return LHFileDataOutside(data->cryptoff, data->cryptsize, lower, upper);
        }
        case LC_TWOLEVEL_HINTS: {
            if (command->cmdsize < sizeof(struct twolevel_hints_command)) return false;
            const struct twolevel_hints_command *data = (const void *)command;
            return LHFileDataOutside(data->offset, (uint64_t)data->nhints * sizeof(struct twolevel_hint), lower, upper);
        }
        case LC_MAIN: {
            if (command->cmdsize < sizeof(struct entry_point_command)) return false;
            const struct entry_point_command *data = (const void *)command;
            return LHFileDataOutside(data->entryoff, sizeof(uint32_t), lower, upper);
        }
        // NOTE 可声明任意 section 外数据；旧线程入口与未来未知命令也不猜测用途。
        default:
            return false;
    }
}

// 有界校验加载命令，并用段内偏移计算运行时范围，兼容共享缓存非零 fileoff。
static bool LHFindHeaderPadding(uintptr_t target, struct LHHeaderRelay *relay, uintptr_t *lower, uintptr_t *upper) {
    Dl_info info = {0};
    if (!dladdr((const void *)target, &info) || !info.dli_fbase) return false;
    relay->headerAddress = (uintptr_t)info.dli_fbase;
    if (!LHReadBytes(relay->headerAddress, &relay->header, sizeof(relay->header)) ||
            relay->header.magic != MH_MAGIC_64 || relay->header.cputype != CPU_TYPE_ARM64 ||
            (relay->header.filetype != MH_DYLIB && relay->header.filetype != MH_EXECUTE && relay->header.filetype != MH_BUNDLE) ||
            relay->header.sizeofcmds > LH_MAX_LOAD_COMMAND_BYTES || !relay->header.ncmds ||
            relay->header.ncmds > relay->header.sizeofcmds / sizeof(struct load_command)) return false;
    size_t headerSize = sizeof(relay->header) + (size_t)relay->header.sizeofcmds;
    if (headerSize > UINTPTR_MAX - relay->headerAddress) return false;
    relay->commands = malloc(relay->header.sizeofcmds);
    if (!relay->commands || !LHReadBytes(relay->headerAddress + sizeof(relay->header),
            relay->commands, relay->header.sizeofcmds)) return false;
    const struct segment_command_64 *text = NULL;
    size_t offset = 0;
    for (uint32_t i = 0; i < relay->header.ncmds; i++) {
        const struct load_command *command = LHRelayCommand(relay, offset);
        if (!command) return false;
        if (command->cmd == LC_SEGMENT_64) {
            if (command->cmdsize < sizeof(struct segment_command_64)) return false;
            const struct segment_command_64 *segment = (const void *)command;
            if (segment->nsects > (command->cmdsize - sizeof(*segment)) / sizeof(struct section_64) ||
                    segment->vmsize > UINT64_MAX - segment->vmaddr || segment->filesize > segment->vmsize ||
                    segment->filesize > UINT64_MAX - segment->fileoff) return false;
            if (!strncmp(segment->segname, "__TEXT", sizeof(segment->segname))) {
                if (text) return false;
                text = segment;
            }
        }
        offset += command->cmdsize;
    }
    if (offset != relay->header.sizeofcmds || !text || !text->nsects ||
            headerSize > text->filesize || text->vmsize > UINTPTR_MAX - relay->headerAddress ||
            target < relay->headerAddress || target - relay->headerAddress >= text->vmsize) return false;
    uint64_t firstSection = text->filesize;
    bool containsTarget = false, hasSection = false;
    const struct section_64 *sections = (const void *)(text + 1);
    for (uint32_t i = 0; i < text->nsects; i++) {
        const struct section_64 *section = &sections[i];
        if (strncmp(section->segname, "__TEXT", sizeof(section->segname)) || section->addr < text->vmaddr) return false;
        uint64_t relative = section->addr - text->vmaddr;
        if (relative > text->vmsize || section->size > text->vmsize - relative) return false;
        uint32_t type = section->flags & SECTION_TYPE;
        if (type == S_ZEROFILL || type == S_GB_ZEROFILL || type == S_THREAD_LOCAL_ZEROFILL) return false;
        if (relative > text->filesize || section->size > text->filesize - relative ||
                section->offset < text->fileoff || (uint64_t)section->offset - text->fileoff != relative) return false;
        // 任何 section 从命令区内开始都拒绝，不能跳过一个覆盖后方的 section。
        if (relative < headerSize) return false;
        if (relative < firstSection) firstSection = relative;
        if (section->size) hasSection = true;
        uint64_t targetOffset = target - relay->headerAddress;
        if (section->size && targetOffset >= relative && targetOffset - relative < section->size &&
                (section->flags & (S_ATTR_PURE_INSTRUCTIONS | S_ATTR_SOME_INSTRUCTIONS))) containsTarget = true;
    }
    if (!hasSection || !containsTarget || firstSection <= headerSize ||
            text->fileoff > UINT64_MAX - firstSection) return false;
    uint64_t fileLower = text->fileoff + headerSize, fileUpper = text->fileoff + firstSection;
    offset = 0;
    for (uint32_t i = 0; i < relay->header.ncmds; i++) {
        const struct load_command *command = LHRelayCommand(relay, offset);
        if (!command || !LHRelayMetadataOutside(command, fileLower, fileUpper)) return false;
        if (command->cmd == LC_SEGMENT_64) {
            const struct segment_command_64 *segment = (const void *)command;
            const struct section_64 *segmentSections = (const void *)(segment + 1);
            for (uint32_t j = 0; j < segment->nsects; j++)
                if (!LHFileDataOutside(segmentSections[j].reloff,
                        (uint64_t)segmentSections[j].nreloc * sizeof(struct relocation_info), fileLower, fileUpper)) return false;
            if (command != (const struct load_command *)text && segment->vmsize && segment->vmaddr < text->vmaddr + firstSection &&
                    segment->vmaddr + segment->vmsize > text->vmaddr) return false;
        }
        offset += command->cmdsize;
    }
    *lower = relay->headerAddress + headerSize;
    *upper = relay->headerAddress + (uintptr_t)firstSection;
    if (*upper - *lower > LH_MAX_PADDING_SCAN) *upper = *lower + LH_MAX_PADDING_SCAN;
    return *upper <= target;
}

// 检查本库未提交和已发布预留，避免同批准备阶段重复选择仍为零的槽位。
static bool LHRelayReserved(uintptr_t address, size_t size) {
    struct LHHeaderRelay *lists[] = {pending, retained};
    for (size_t i = 0; i < sizeof(lists) / sizeof(*lists); i++)
        for (const struct LHHeaderRelay *entry = lists[i]; entry; entry = entry->next)
            if (address < entry->address + entry->size && entry->address < address + size) return true;
    return false;
}

// 只返回完整零填充、同页 RX 且从目标可达的槽位，不在这里改写任何映射。
struct LHHeaderRelay *LHPrepareHeaderRelay(uintptr_t target, size_t size, uintptr_t *address) {
    if (address) *address = 0;
    if (!address || !target || (target & 3) || size < 16 || (size & 3) ||
            size > LH_MAX_RELAY_BYTES || !LHRelayIsRX(target, sizeof(uint32_t))) return NULL;
    struct LHHeaderRelay *relay = calloc(1, sizeof(*relay));
    if (!relay) return NULL;
    uintptr_t lower, upper;
    if (!LHFindHeaderPadding(target, relay, &lower, &upper) || lower > UINTPTR_MAX - 7) goto failure;
    uint8_t bytes[LH_MAX_RELAY_BYTES];
    for (uintptr_t candidate = (lower + 7) & ~(uintptr_t)7; candidate < upper && size <= upper - candidate; candidate += 8) {
        if (!LHRelayReachable(target, candidate) || LHRelayReserved(candidate, size) || !LHRelayIsRX(candidate, size)) continue;
        if (!LHReadBytes(candidate, bytes, size)) goto failure;
        bool zero = true;
        for (size_t i = 0; i < size; i++) zero &= bytes[i] == 0;
        if (!zero) continue;
        relay->address = candidate;
        relay->target = target;
        relay->size = size;
        relay->next = pending;
        pending = relay;
        *address = candidate;
        return relay;
    }
failure:
    free(relay->commands);
    free(relay);
    return NULL;
}

// 仅撤销尚未提交的本次预留；入口已经排队后由事务统一负责其生命周期。
void LHCancelHeaderRelay(struct LHHeaderRelay *relay) {
    if (!relay) return;
    struct LHHeaderRelay **cursor = &pending;
    while (*cursor && *cursor != relay) cursor = &(*cursor)->next;
    if (!*cursor) return;
    *cursor = relay->next;
    free(relay->commands);
    free(relay);
}

// 使用固定栈缓冲校验实际头部和加载命令，暂停期间不分配内存或调用 dyld。
static bool LHRelayImageUnchanged(const struct LHHeaderRelay *relay) {
    struct mach_header_64 header;
    if (!LHReadBytes(relay->headerAddress, &header, sizeof(header)) || memcmp(&header, &relay->header, sizeof(header))) return false;
    uint8_t bytes[1024];
    for (size_t offset = 0; offset < header.sizeofcmds;) {
        size_t amount = header.sizeofcmds - offset;
        if (amount > sizeof(bytes)) amount = sizeof(bytes);
        if (!LHReadBytes(relay->headerAddress + sizeof(header) + offset, bytes, amount) ||
                memcmp(bytes, relay->commands + offset, amount)) return false;
        offset += amount;
    }
    return true;
}

// 提交前再次确认所有预留仍为零且可执行；其它写入者占用时整批拒绝发布入口。
bool LHValidateHeaderRelays(void) {
    uint8_t bytes[LH_MAX_RELAY_BYTES];
    for (const struct LHHeaderRelay *relay = pending; relay; relay = relay->next) {
        if (!LHRelayImageUnchanged(relay) || !LHRelayIsRX(relay->target, sizeof(uint32_t)) ||
                !LHRelayIsRX(relay->address, relay->size) ||
                !LHReadBytes(relay->address, bytes, relay->size)) return false;
        for (size_t i = 0; i < relay->size; i++) if (bytes[i]) return false;
    }
    return true;
}

// 单独标记本批中继字节，撤销入口和输出槽后才允许清除此范围。
void LHGetPendingHeaderRelayMask(uintptr_t page, uint8_t *mask, size_t pageSize) {
    if (!mask || !pageSize) return;
    memset(mask, 0, pageSize / 8 + (pageSize % 8 != 0));
    for (const struct LHHeaderRelay *relay = pending; relay; relay = relay->next) {
        size_t offset = 0, length = relay->size;
        if (relay->address >= page) {
            uintptr_t distance = relay->address - page;
            if (distance >= pageSize) continue;
            offset = (size_t)distance;
        } else {
            uintptr_t skipped = page - relay->address;
            if (skipped >= length) continue;
            length -= (size_t)skipped;
        }
        if (length > pageSize - offset) length = pageSize - offset;
        for (size_t end = offset + length; offset < end; offset++)
            mask[offset / 8] |= (uint8_t)(1u << (offset & 7));
    }
}

// 可能仍生效的槽位不复用；未提交或完整回滚后可以释放本次预留。
void LHFinishHeaderRelays(bool preserve) {
    while (pending) {
        struct LHHeaderRelay *relay = pending;
        pending = relay->next;
        free(relay->commands);
        relay->commands = NULL;
        if (preserve) { relay->next = retained; retained = relay; }
        else free(relay);
    }
}
