# Qt 6.8 and the node's C++20 code require a modern SDK. Linux cross builds
# use an external OSXCross installation; native builds use Xcode's tools.
OSX_MIN_VERSION ?= 12.0
OSX_SDK_VERSION ?= 14.5
darwin_native_toolchain =

ifeq ($(build_os),darwin)
OSX_SDK ?= $(shell xcrun --sdk macosx --show-sdk-path)
darwin_CC = $(shell xcrun --find clang)
darwin_CXX = $(shell xcrun --find clang++)
darwin_CFLAGS = -pipe -mmacosx-version-min=$(OSX_MIN_VERSION)
darwin_CXXFLAGS = $(darwin_CFLAGS) -stdlib=libc++
$(foreach tool,AR RANLIB STRIP NM LIBTOOL OTOOL INSTALL_NAME_TOOL,$(eval darwin_$(tool) = $$(shell xcrun --find $(shell echo $(tool) | tr A-Z a-z))))
else
OSXCROSS_ROOT ?= $(BASEDIR)/../MAC/toolchain
OSX_SDK ?= $(OSXCROSS_ROOT)/SDK/MacOSX$(OSX_SDK_VERSION).sdk
darwin_CC = $(OSXCROSS_ROOT)/bin/$(host)-clang
darwin_CXX = $(OSXCROSS_ROOT)/bin/$(host)-clang++
darwin_AR = $(OSXCROSS_ROOT)/bin/$(host)-ar
darwin_RANLIB = $(OSXCROSS_ROOT)/bin/$(host)-ranlib
darwin_STRIP = $(OSXCROSS_ROOT)/bin/$(host)-strip
darwin_NM = $(OSXCROSS_ROOT)/bin/$(host)-nm
darwin_LIBTOOL = $(OSXCROSS_ROOT)/bin/$(host)-libtool
darwin_OTOOL = $(OSXCROSS_ROOT)/bin/$(host)-otool
darwin_INSTALL_NAME_TOOL = $(OSXCROSS_ROOT)/bin/$(host)-install_name_tool
darwin_CFLAGS = -pipe -mmacosx-version-min=$(OSX_MIN_VERSION)
darwin_CXXFLAGS = $(darwin_CFLAGS)
endif

darwin_CPPFLAGS = -isysroot $(OSX_SDK)

# Invalidate target caches when the SDK or deployment target changes, even
# when clang's version and the source recipes are identical.
darwin_id_extra = min-macos=$(OSX_MIN_VERSION) sdk=$(OSX_SDK) $(shell $(build_SHA256SUM) $(OSX_SDK)/SDKSettings.json 2>/dev/null)
darwin_release_CFLAGS = -O2
darwin_release_CXXFLAGS = -O2
darwin_debug_CFLAGS = -O1
darwin_debug_CXXFLAGS = -O1
darwin_cmake_system = Darwin
