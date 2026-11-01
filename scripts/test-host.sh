#!/bin/bash
# 用宿主接口桩检查事务边界，不连接设备或改写宿主代码页。
set -euo pipefail
cd "$(dirname "$0")/.."
mkdir -p worker/host-tests
common=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all
    -DLH_ROOTHIDE -Ilibhooker/include/apple -Ilibhooker/include)
xcrun clang "${common[@]}" tests/jump-encoding.c -o worker/host-tests/jump-encoding
worker/host-tests/jump-encoding
xcrun clang "${common[@]}" -c libhooker/mem/shadowMem.c -o worker/host-tests/shadow-memory-c.o
xcrun clang++ -std=c++11 "${common[@]}" tests/shadow-memory.cpp libhooker/mem/shadowMem.cpp \
    worker/host-tests/shadow-memory-c.o -o worker/host-tests/shadow-memory
worker/host-tests/shadow-memory
xcrun clang "${common[@]}" tests/thread-safety.c libhooker/mem/threadSafety.c \
    -o worker/host-tests/thread-safety
worker/host-tests/thread-safety
xcrun clang "${common[@]}" tests/memory-backend.c -o worker/host-tests/memory-backend
worker/host-tests/memory-backend
for mode in legacy partial-patch partial-protect unavailable; do
    worker/host-tests/memory-backend "$mode"
done
xcrun clang "${common[@]}" tests/hook-resources.c -o worker/host-tests/hook-resources
worker/host-tests/hook-resources
xcrun clang "${common[@]}" tests/header-relay-mask.c -o worker/host-tests/header-relay-mask
worker/host-tests/header-relay-mask
xcrun clang "${common[@]}" tests/symbol-cache.c libhooker/dyld/macho-symbols.c \
    -o worker/host-tests/symbol-cache
worker/host-tests/symbol-cache
