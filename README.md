# libhooker roothide

配置好 roothide `THEOS` 和 `build-config.mk` 指定的 iOS SDK 后，在仓库根目录编译、打包并安装：

```sh
make do
```

默认构建发行版，包含 `arm64` 和 `arm64e`，最低系统版本由 `build-config.mk` 指定。通过 SSH 别名 `15` 安装，可用 `make do THEOS_DEVICE_IP=<地址或别名>` 指定设备。只打包用 `make package`，清理用 `make clean`，产物位于 `packages/`。

默认引擎为 `libjoker.dylib`，兼容入口链接到同一引擎。使用 `./mybuild.sh 1` 构建并安装默认引擎，或使用 `./mybuild.sh 2` 仅构建打包 `libhooker.dylib`，不安装到设备；脚本会先清理旧产物。安装后从 bootstrap／越狱工具重启用户空间，使已有进程载入新版。

内存后端优先使用 bootstrap 提供的完整 `substrate_vm_protect`／`substrate_hook_memory` 接口。Dopamine 2.4.9.x 缺少这两个导出时，使用基于进程调试权限的本地 COW 后端；写入器在独立执行页中恢复目标页权限，支持修改补丁器自身所在页。

包信息位于 `control`，安装布局与维护脚本位于 `layout/`。

需要使用原上游构建方式时，执行 `make clean THEOS_PACKAGE_SCHEME=`，再执行 `make package THEOS_PACKAGE_SCHEME=`。

## 代码结构

| 目录或文件 | 职责 |
| --- | --- |
| `libhooker/as-aarch64/`、`libhooker/disas-aarch64/` | AArch64 指令编码与重定位 |
| `libhooker/func/` | 函数入口 Hook、原调用跳板与短函数兼容 |
| `libhooker/mem/` | 内存后端、线程暂停、影子页事务、资源回滚和头部中继 |
| `libhooker/dyld/` | Mach-O 符号解析、镜像生命周期和共享缓存查询 |
| `libblackjack/objc/` | Objective-C 方法 Hook 与继承方法跳板 |
| `compat/` | Substrate 与 ElleKit 兼容接口 |
| `injector/`、`safemode/` | 插件筛选加载、崩溃保护与安全模式界面 |
| `roothide.mk`、`build-config.mk`、`layout/` | roothide 构建配置、安装布局和维护脚本 |
| `packaging/` | 原上游包信息与独立安装布局 |
| `tests/`、`scripts/` | 回归用例、包校验及设备测试工具 |

`roothide.mk` 按符号、重定位、内存、Objective-C 和兼容层分组维护实际源码清单。上游实现继续由根 `Makefile` 的非 roothide 分支管理。

## 本地验证

以下命令在仓库根目录执行：

```sh
bash scripts/test-host.sh
make package
python3 scripts/verify-package.py packages/org.coolstar.libhooker_1.6.9-22+roothide_iphoneos-arm64e.deb
bash scripts/build-device-rollback.sh
bash scripts/build-device-compat.sh
```

宿主测试在 macOS 上使用 Xcode 命令行工具及 AddressSanitizer、UndefinedBehaviorSanitizer，覆盖指令编码、影子页、线程暂停、内存后端、Hook 资源、头部中继和符号缓存。包校验另需 `dpkg-deb`，检查元数据、相对链接、双架构、最低系统版本、引擎依赖及导出接口；更改包版本后应传入对应 DEB。校验 `libhooker` 名称的产物时，在命令末尾追加 `libhooker`。

`build-device-rollback.sh` 使用 `tests/device-rollback.entitlements.plist` 签名独立的双架构回滚测试程序，输出到 `worker/device-rollback/`，不连接或安装到设备。

`build-device-compat.sh` 使用含 XPC 头文件的 Xcode SDK 生成 `worker/device-compat/DeviceCompat-{arm64,arm64e}`。在设备上以引擎真实路径为参数运行，可验证 Mach-O 同页 Hook 与 launchd 使用的 `xpc_receive_mach_msg` 拦截及回复；测试仅修改自身进程。回滚工具的 `legacy-self-page` 案例额外验证本地后端重写自身代码页。

本地测试与打包通过不代表设备验收完成。注入、安全模式和实际 Hook 行为仍需在目标设备上验证。构建中间文件位于 `.theos/`、`worker/`，发行包位于 `packages/`，均不纳入版本控制。
