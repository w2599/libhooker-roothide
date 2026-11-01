include build-config.mk
TARGET = iphone:clang:$(LH_IOS_SDK):$(LH_IOS_MIN)
ARCHS = arm64 arm64e
export CLANG_MODULE_CACHE_PATH := $(CURDIR)/worker/clang-module-cache
# 将 Theos 的开发库副本留在本仓库。
override THEOS_LIBRARY_PATH := $(CURDIR)/worker/link-libraries
include $(THEOS)/makefiles/common.mk

# 引擎名称同时用于编译目标、加载器依赖和包内兼容链接。
LH_ENGINE_NAME ?= libjoker
ifneq ($(LH_ENGINE_NAME),libjoker)
ifneq ($(LH_ENGINE_NAME),libhooker)
$(error LH_ENGINE_NAME must be libjoker or libhooker)
endif
endif
LIBRARY_NAME = $(LH_ENGINE_NAME) libinjector MobileSafety
# 按职责列出实际参与构建的模块，旧平台实现继续由原 Makefile 管理。
LH_SYMBOL_FILES = libhooker/dyld/dyldSyms-modern.c libhooker/dyld/macho-symbols.c libhooker/dyld/image-registry.c
LH_RELOCATION_FILES = libhooker/as-aarch64/as-aarch64.c libhooker/disas-aarch64/disas-aarch64.c libhooker/func/funcHook.c
LH_MEMORY_FILES = libhooker/mem/writeMem-roothide.c libhooker/mem/legacy-memory.c libhooker/mem/legacy-syscalls.S libhooker/mem/threadSafety.c libhooker/mem/shadowMem.c libhooker/mem/shadowMem.cpp libhooker/mem/hook-transaction.c libhooker/mem/header-relay.c
LH_OBJC_FILES = libblackjack/objc/objc.c
LH_COMPAT_FILES = compat/substrate.c compat/ellekit.c
LH_CORE_FILES = $(LH_SYMBOL_FILES) $(LH_RELOCATION_FILES) $(LH_MEMORY_FILES) $(LH_OBJC_FILES) $(LH_COMPAT_FILES) libhooker/misc/misc.c
LH_FLAGS = -Ilibhooker/include/apple -Ilibhooker/include -Ilibblackjack/include -DTHEOS -DLH_ROOTHIDE=1 -fvisibility=hidden
$(LH_ENGINE_NAME)_FILES = $(LH_CORE_FILES)
$(LH_ENGINE_NAME)_CFLAGS = $(LH_FLAGS)
$(LH_ENGINE_NAME)_CCFLAGS = $(LH_FLAGS) -std=c++11
$(LH_ENGINE_NAME)_LDFLAGS = -lobjc
$(LH_ENGINE_NAME)_LINKAGE_TYPE = both

libinjector_FILES = injector/injector.c
libinjector_CFLAGS = -Ilibhooker/include
libinjector_FRAMEWORKS = CoreFoundation
libinjector_LDFLAGS = -lobjc -lroothide -Wl,-needed_library,$(THEOS_OBJ_DIR)/$(LH_ENGINE_NAME).dylib
libinjector_INSTALL_PATH = /usr/lib/libhooker

MobileSafety_FILES = safemode/MobileSafety.m safemode/safe-mode-ui.m safemode/crash-guard.c
MobileSafety_CFLAGS = -fobjc-arc
MobileSafety_FRAMEWORKS = Foundation UIKit QuartzCore CoreGraphics IOKit
MobileSafety_LDFLAGS = -lroothide
MobileSafety_INSTALL_PATH = /usr/lib/libhooker

include $(THEOS_MAKE_PATH)/library.mk

after-stage::
	@for binary in "usr/lib/$(LH_ENGINE_NAME).dylib" usr/lib/libhooker/libinjector.dylib usr/lib/libhooker/MobileSafety.dylib; do \
		test -f "$(THEOS_STAGING_DIR)/$$binary" && test ! -L "$(THEOS_STAGING_DIR)/$$binary" || exit 1; \
	done
	# 兼容入口随实际引擎名称变化，使用相对链接适配越狱根目录。
	@set -e; for alias in libjoker libhooker libblackjack libsubstrate libellekit; do \
		if [ "$$alias" != "$(LH_ENGINE_NAME)" ]; then \
			ln -s "$(LH_ENGINE_NAME).dylib" "$(THEOS_STAGING_DIR)/usr/lib/$$alias.dylib"; \
		fi; \
	done
	@mkdir -p "$(THEOS_STAGING_DIR)/Library/Frameworks/CydiaSubstrate.framework" "$(THEOS_STAGING_DIR)/usr/lib/TweakInject"
	@ln -s "../../../usr/lib/$(LH_ENGINE_NAME).dylib" "$(THEOS_STAGING_DIR)/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate"
	# 静态库留在构建目录供开发验证，设备运行包只安装动态库。
	@rm -f "$(THEOS_STAGING_DIR)/usr/lib/$(LH_ENGINE_NAME).a"
