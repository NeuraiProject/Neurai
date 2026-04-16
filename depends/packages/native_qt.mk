PACKAGE=native_qt

# Same source as qt.mk — only qtbase + qttools are needed.
# qttranslations is not required for the host-tools-only build.
$(package)_version=6.8.3
$(package)_download_path=https://download.qt.io/archive/qt/6.8/$($(package)_version)/submodules
$(package)_suffix=everywhere-src-$($(package)_version).tar.xz
$(package)_file_name=qtbase-$($(package)_suffix)
$(package)_sha256_hash=56001b905601bb9023d399f3ba780d7fa940f3e4861e496a7c490331f49e0b80

$(package)_qttools_file_name=qttools-$($(package)_suffix)
$(package)_qttools_sha256_hash=02a4e219248b94f1333df843d25763f35251c1074cdc4fb5bda67d340f8c8b3a

$(package)_extra_sources = $($(package)_qttools_file_name)

# native_qt provides moc, rcc, uic, lrelease and lupdate for the BUILD HOST.
# It is required when cross-compiling Qt for a different target (macOS, Windows,
# aarch64) because Qt6 CMake mandates that host tools are native executables
# (QT_HOST_PATH).  For native Linux x86_64 → x86_64 builds it is not needed
# since the target Qt tools can run directly on the build machine.

define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_qttools_file_name),$($(package)_qttools_file_name),$($(package)_qttools_sha256_hash))
endef

define $(package)_extract_cmds
  mkdir -p $($(package)_extract_dir) && \
  echo "$($(package)_sha256_hash)  $($(package)_source)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_qttools_sha256_hash)  $($(package)_source_dir)/$($(package)_qttools_file_name)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  mkdir qtbase && \
  tar --no-same-owner --strip-components=1 -xf $($(package)_source) -C qtbase && \
  mkdir qttools && \
  tar --no-same-owner --strip-components=1 -xf $($(package)_source_dir)/$($(package)_qttools_file_name) -C qttools
endef

define $(package)_preprocess_cmds
  : # intentionally empty — no patches needed for Qt 6.8.3
endef

# Minimal feature set: only what is required to build the host tools.
# No OpenSSL, XCB, DBus, fontconfig, or any target-specific subsystem.
# $(firstword) strips flags like -m64 from the compiler variable so CMake
# receives a bare executable name (same fix as qt.mk).
define $(package)_config_cmds
  cmake -B qtbase/build -S qtbase \
    -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_INSTALL_PREFIX=$(build_prefix) \
    -DCMAKE_C_COMPILER="$(firstword $($(package)_cc))" \
    -DCMAKE_CXX_COMPILER="$(firstword $($(package)_cxx))" \
    -DBUILD_SHARED_LIBS=OFF \
    -DQT_BUILD_EXAMPLES=OFF \
    -DQT_BUILD_TESTS=OFF \
    -DQT_FEATURE_pch=OFF \
    -DINPUT_openssl=no \
    -DQT_FEATURE_dbus=OFF \
    -DQT_FEATURE_egl=OFF \
    -DQT_FEATURE_eglfs=OFF \
    -DQT_FEATURE_glib=OFF \
    -DQT_FEATURE_icu=OFF \
    -DQT_FEATURE_kms=OFF \
    -DQT_FEATURE_linuxfb=OFF \
    -DQT_FEATURE_libudev=OFF \
    -DQT_FEATURE_opengl=OFF \
    -DQT_FEATURE_sql=OFF \
    -DQT_FEATURE_vulkan=OFF \
    -DQT_FEATURE_xcb=OFF \
    -DQT_FEATURE_system_zlib=OFF \
    -DQT_FEATURE_system_png=OFF \
    -DQT_FEATURE_system_jpeg=OFF \
    -DQT_FEATURE_system_pcre2=OFF \
    -DQT_FEATURE_system_harfbuzz=OFF
endef

# Build order:
#   1. Build + locally install qtbase  → qt_install (provides CMake config for qttools)
#   2. Configure + build qttools       (needs lrelease/lupdate)
#   3. Install qttools                 → qt_install
define $(package)_build_cmds
  ninja -C qtbase/build && \
  cmake --install qtbase/build --prefix $($(package)_extract_dir)/qt_install && \
  cmake -B qttools/build -S qttools \
    -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$($(package)_extract_dir)/qt_install \
    -DCMAKE_INSTALL_PREFIX=$($(package)_extract_dir)/qt_install \
    -DBUILD_SHARED_LIBS=OFF \
    -DQT_BUILD_EXAMPLES=OFF \
    -DQT_BUILD_TESTS=OFF \
    -DFEATURE_assistant=OFF \
    -DFEATURE_clang=OFF \
    -DFEATURE_clangcpp=OFF \
    -DFEATURE_designer=OFF \
    -DFEATURE_distancefieldgenerator=OFF \
    -DFEATURE_kmap2qmap=OFF \
    -DFEATURE_pixeltool=OFF \
    -DFEATURE_pkg_config=OFF \
    -DFEATURE_qev=OFF \
    -DFEATURE_qtattributionsscanner=OFF \
    -DFEATURE_qtdiag=OFF \
    -DFEATURE_qtplugininfo=OFF && \
  ninja -C qttools/build
endef

define $(package)_stage_cmds
  cmake --install qtbase/build --prefix $($(package)_staging_prefix) && \
  cmake --install qttools/build --prefix $($(package)_staging_prefix)
endef

define $(package)_postprocess_cmds
  rm -rf lib/cmake/ lib/pkgconfig/
endef
