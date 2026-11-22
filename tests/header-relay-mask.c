// 直接检查生产中继位图的截断、合并与高地址边界，不改写实际代码页。
#include <stdio.h>
#include <stdlib.h>
#include "../libhooker/mem/header-relay.c"

static unsigned checks;
#define REQUIRE(condition) do { \
    checks++; \
    if (!(condition)) { fprintf(stderr, "header-relay-mask failed at line %d: %s\n", __LINE__, #condition); abort(); } \
} while (0)

// 用围栏字节确认空列表、页两侧截断及保留列表不会污染调用方缓冲区。
static void testClippedRanges(void) {
    uint8_t bytes[6] = {0xa1, 0xff, 0xff, 0xff, 0xff, 0xb2};
    pending = NULL;
    LHGetPendingHeaderRelayMask(0x1000, bytes + 1, 32);
    REQUIRE(bytes[0] == 0xa1 && bytes[5] == 0xb2);
    for (size_t index = 1; index < 5; index++) REQUIRE(bytes[index] == 0);
    struct LHHeaderRelay nodes[4] = {
        {.address = 0x1003, .size = 8}, {.address = 0x101c, .size = 16},
        {.address = 0xffc, .size = 6}, {.address = 0x2000, .size = 4}
    };
    for (size_t index = 0; index < 3; index++) nodes[index].next = &nodes[index + 1];
    struct LHHeaderRelay old = {.address = 0x100c, .size = 4};
    retained = &old;
    pending = nodes;
    LHGetPendingHeaderRelayMask(0x1000, bytes + 1, 32);
    REQUIRE(bytes[0] == 0xa1 && bytes[5] == 0xb2);
    REQUIRE(bytes[1] == 0xfb && bytes[2] == 0x07 && bytes[3] == 0 && bytes[4] == 0xf0);
    pending = retained = NULL;
}

// 验证同字节和跨字节重叠范围按位合并，高地址计算不依赖会溢出的区间终点。
static void testOverlapAndHighAddresses(void) {
    uint8_t mask[4];
    struct LHHeaderRelay second = {.address = 0x1008, .size = 5};
    struct LHHeaderRelay first = {.address = 0x1007, .size = 4, .next = &second};
    pending = &first;
    LHGetPendingHeaderRelayMask(0x1000, mask, 32);
    REQUIRE(mask[0] == 0x80 && mask[1] == 0x1f && mask[2] == 0 && mask[3] == 0);
    first.address = UINTPTR_MAX - 4;
    first.size = 5;
    first.next = NULL;
    LHGetPendingHeaderRelayMask(UINTPTR_MAX - 31, mask, 32);
    REQUIRE(mask[0] == 0 && mask[1] == 0 && mask[2] == 0 && mask[3] == 0xf8);
    pending = NULL;
}

// 验证不足一字节的末尾位图和无效空参数不越界。
static void testSmallAndEmptyRanges(void) {
    uint8_t bytes[] = {0xa1, 0xff, 0xb2};
    struct LHHeaderRelay node = {.address = 0x1000, .size = 1};
    pending = &node;
    LHGetPendingHeaderRelayMask(0x1000, bytes + 1, 1);
    REQUIRE(bytes[0] == 0xa1 && bytes[1] == 1 && bytes[2] == 0xb2);
    LHGetPendingHeaderRelayMask(0x1000, bytes + 1, 0);
    LHGetPendingHeaderRelayMask(0x1000, NULL, 1);
    REQUIRE(bytes[0] == 0xa1 && bytes[1] == 1 && bytes[2] == 0xb2);
    pending = NULL;
}

// 用各命令的实际头长验证名称边界，损坏的元数据不得被当作填充。
static void testNameCommand(uint32_t type, uint32_t minimum) {
    struct {
        struct load_command command;
        uint32_t offset;
        char rest[28];
    } fixture = {{type, sizeof(fixture)}, minimum, {0}};
    memcpy((char *)&fixture + minimum, "System", sizeof("System"));
    REQUIRE(LHRelayMetadataOutside(&fixture.command, 0x1000, 0x2000));
    fixture.command.cmdsize = sizeof(struct load_command);
    REQUIRE(!LHRelayMetadataOutside(&fixture.command, 0x1000, 0x2000));
    fixture.command.cmdsize = sizeof(fixture);
    fixture.offset = sizeof(fixture) - 1;
    fixture.rest[sizeof(fixture.rest) - 1] = 'X';
    REQUIRE(!LHRelayMetadataOutside(&fixture.command, 0x1000, 0x2000));
    fixture.offset = sizeof(fixture);
    REQUIRE(!LHRelayMetadataOutside(&fixture.command, 0x1000, 0x2000));
    fixture.offset = minimum - 1;
    REQUIRE(!LHRelayMetadataOutside(&fixture.command, 0x1000, 0x2000));
}

// 运行全部纯内存边界检查，不连接设备。
int main(void) {
    testNameCommand(LC_SUB_FRAMEWORK, sizeof(struct sub_framework_command));
    testNameCommand(LC_SUB_CLIENT, sizeof(struct sub_client_command));
    testNameCommand(LC_SUB_LIBRARY, sizeof(struct sub_library_command));
    testNameCommand(LC_SUB_UMBRELLA, sizeof(struct sub_umbrella_command));
    testNameCommand(LC_RPATH, sizeof(struct rpath_command));
    testNameCommand(LC_LOAD_DYLINKER, sizeof(struct dylinker_command));
    testNameCommand(LC_ID_DYLINKER, sizeof(struct dylinker_command));
    testNameCommand(LC_DYLD_ENVIRONMENT, sizeof(struct dylinker_command));
    testNameCommand(LC_ID_DYLIB, sizeof(struct dylib_command));
    testNameCommand(LC_LOAD_DYLIB, sizeof(struct dylib_command));
    testNameCommand(LC_LOAD_WEAK_DYLIB, sizeof(struct dylib_command));
    testNameCommand(LC_REEXPORT_DYLIB, sizeof(struct dylib_command));
    testNameCommand(LC_LAZY_LOAD_DYLIB, sizeof(struct dylib_command));
    testNameCommand(LC_LOAD_UPWARD_DYLIB, sizeof(struct dylib_command));
    testClippedRanges();
    testOverlapAndHighAddresses();
    testSmallAndEmptyRanges();
    printf("header-relay-mask: %u checks passed\n", checks);
    return 0;
}
