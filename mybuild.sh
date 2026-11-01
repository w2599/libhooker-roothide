#!/bin/bash
# 按参数选择引擎，构建 roothide 发行包并按需安装。
set -euo pipefail
cd "$(dirname "$0")"

if (( $# > 1 )); then
    echo "用法：$0 [1|2]（默认 1：构建并安装 libjoker.dylib；2：仅构建打包 libhooker.dylib）" >&2
    exit 2
fi
case "${1:-1}" in
    1) engine=libjoker; target=do ;;
    2) engine=libhooker; target=package ;;
    -h|--help)
        echo "用法：$0 [1|2]（默认 1：构建并安装 libjoker.dylib；2：仅构建打包 libhooker.dylib）"
        exit 0
        ;;
    *)
        echo "用法：$0 [1|2]（默认 1：构建并安装 libjoker.dylib；2：仅构建打包 libhooker.dylib）" >&2
        exit 2
        ;;
esac

: "${THEOS:?请设置 THEOS 为 roothide Theos 的安装目录}"
build_args=(FINALPACKAGE=1 THEOS_PACKAGE_SCHEME=roothide "LH_ENGINE_NAME=$engine")
printf '开始编译：%s.dylib\n' "$engine"
# 切换名称前清理旧目标、加载器依赖与打包暂存，避免混用两种产物。
make "${build_args[@]}" clean
make "${build_args[@]}" "$target"
if [[ "$target" == do ]]; then
    printf '构建并安装完成：.theos/obj/%s.dylib，deb 位于 packages/。\n' "$engine"
else
    sh update.sh
    printf '构建打包完成（未安装）：.theos/obj/%s.dylib，deb 位于 packages/。\n' "$engine"
fi
