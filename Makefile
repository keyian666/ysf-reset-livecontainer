# v3: 用 library.mk 而不是 tweak.mk。
#   tweak.mk 会强制链接 CydiaSubstrate, 产物里会写入
#     LC_LOAD_DYLIB /Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate
#   LiveContainer 的 TweakLoader 不重写这条依赖, 于是 dlopen 直接失败:
#     Library not loaded: '/Library/Frameworks/CydiaSubstrate.framework/CydiaSubstrate'
#   library.mk 生成的是普通 dylib, 没有任何 substrate 依赖。

TARGET := iphone:clang:16.5:15.0
ARCHS = arm64

include $(THEOS)/makefiles/common.mk

LIBRARY_NAME = YSFDeviceReset
YSFDeviceReset_FILES = Tweak.m
YSFDeviceReset_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable
YSFDeviceReset_FRAMEWORKS = UIKit Foundation Security CoreFoundation

include $(THEOS_MAKE_PATH)/library.mk
