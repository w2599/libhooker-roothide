#!/bin/bash
# 使用带 XPC 头文件的 Xcode SDK 构建独立测试，不连接或安装到设备。
set -euo pipefail
cd "$(dirname "$0")/.."
source build-config.mk
mkdir -p worker/device-compat
for architecture in arm64 arm64e; do
    output="worker/device-compat/DeviceCompat-$architecture"
    xcrun --sdk iphoneos clang -arch "$architecture" "-miphoneos-version-min=$LH_IOS_MIN" \
        -isysroot "$(xcrun --sdk iphoneos --show-sdk-path)" -Ilibhooker/include \
        -O2 -g tests/device-roothide-compat.c -o "$output"
    ldid -Stests/device-rollback.entitlements.plist "$output"
    printf '已生成：%s\n' "$output"
done
