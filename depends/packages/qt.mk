PACKAGE=qt
$(package)_version=6.8.3
$(package)_download_path=https://download.qt.io/archive/qt/6.8/$($(package)_version)/submodules
$(package)_suffix=everywhere-src-$($(package)_version).tar.xz
$(package)_file_name=qtbase-$($(package)_suffix)
$(package)_sha256_hash=56001b905601bb9023d399f3ba780d7fa940f3e4861e496a7c490331f49e0b80
$(package)_dependencies=openssl
$(package)_linux_dependencies=freetype fontconfig libxcb libxkbcommon libxcb_util libxcb_util_cursor libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm libwayland wayland_protocols

# When cross-compiling, native_qt provides moc/rcc/uic/lrelease for the build
# host.  For native Linux x86_64→x86_64 builds this is not needed.
ifneq ($(host),$(build))
$(package)_dependencies += native_qt
endif

$(package)_qttranslations_file_name=qttranslations-$($(package)_suffix)
$(package)_qttranslations_sha256_hash=c3c61d79c3d8fe316a20b3617c64673ce5b5519b2e45535f49bee313152fa531

$(package)_qttools_file_name=qttools-$($(package)_suffix)
$(package)_qttools_sha256_hash=02a4e219248b94f1333df843d25763f35251c1074cdc4fb5bda67d340f8c8b3a

$(package)_qtwayland_file_name=qtwayland-$($(package)_suffix)
$(package)_qtwayland_sha256_hash=20fe385887d21190165a3180c17dcfc8b9a0e1da4ec76865b6334bdc709994b0

$(package)_extra_sources  = $($(package)_qttranslations_file_name)
$(package)_extra_sources += $($(package)_qttools_file_name)
$(package)_extra_sources += $($(package)_qtwayland_file_name)

# Qt 6.8.7 is commercial-only; 6.8.3 is the latest open-source LTS (March 2025).
# Qt6 uses CMake instead of qmake.  All qmake -no-feature-* flags are replaced
# with -DQT_FEATURE_xxx=OFF equivalents.

define $(package)_set_vars
$(package)_config_opts_release = -DCMAKE_BUILD_TYPE=Release
$(package)_config_opts_debug   = -DCMAKE_BUILD_TYPE=Debug

# --- Core build settings ---
$(package)_config_opts += -DBUILD_SHARED_LIBS=OFF
$(package)_config_opts += -DCMAKE_INSTALL_PREFIX=$(host_prefix)
$(package)_config_opts += -DQT_BUILD_EXAMPLES=OFF
$(package)_config_opts += -DQT_BUILD_TESTS=OFF
$(package)_config_opts += -DQT_FEATURE_precompile_header=OFF

# --- OpenSSL: linked (not bundled) ---
$(package)_config_opts += -DINPUT_openssl=linked
$(package)_config_opts += -DOPENSSL_ROOT_DIR=$(host_prefix)
$(package)_config_opts += -DOPENSSL_USE_STATIC_LIBS=TRUE

# --- Bundled third-party libs (use Qt's copies, not system) ---
$(package)_config_opts += -DQT_FEATURE_system_zlib=OFF
$(package)_config_opts += -DQT_FEATURE_system_png=OFF
$(package)_config_opts += -DQT_FEATURE_system_jpeg=OFF
$(package)_config_opts += -DQT_FEATURE_system_pcre2=OFF
$(package)_config_opts += -DQT_FEATURE_system_harfbuzz=OFF

# --- Disable unused subsystems ---
$(package)_config_opts += -DQT_FEATURE_cups=OFF
$(package)_config_opts += -DQT_FEATURE_dbus=OFF
$(package)_config_opts += -DQT_FEATURE_egl=OFF
$(package)_config_opts += -DQT_FEATURE_eglfs=OFF
$(package)_config_opts += -DQT_FEATURE_gif=OFF
$(package)_config_opts += -DQT_FEATURE_glib=OFF
$(package)_config_opts += -DQT_FEATURE_icu=OFF
$(package)_config_opts += -DQT_FEATURE_ico=OFF
$(package)_config_opts += -DQT_FEATURE_kms=OFF
$(package)_config_opts += -DQT_FEATURE_linuxfb=OFF
$(package)_config_opts += -DQT_FEATURE_libudev=OFF
$(package)_config_opts += -DQT_FEATURE_mtdev=OFF
$(package)_config_opts += -DINPUT_opengl=no
$(package)_config_opts += -DQT_FEATURE_opengl=OFF
$(package)_config_opts += -DQT_FEATURE_openvg=OFF
$(package)_config_opts += -DQT_FEATURE_reduce_relocations=OFF
$(package)_config_opts += -DQT_FEATURE_sql=OFF
$(package)_config_opts += -DQT_FEATURE_system_proxies=OFF
$(package)_config_opts += -DQT_FEATURE_vulkan=OFF

# --- Disable unneeded widgets, dialogs, and network features ---
$(package)_config_opts += -DQT_FEATURE_colordialog=OFF
$(package)_config_opts += -DQT_FEATURE_concurrent=OFF
$(package)_config_opts += -DQT_FEATURE_dial=OFF
$(package)_config_opts += -DQT_FEATURE_fontcombobox=OFF
$(package)_config_opts += -DQT_FEATURE_image_heuristic_mask=OFF
$(package)_config_opts += -DQT_FEATURE_keysequenceedit=OFF
$(package)_config_opts += -DQT_FEATURE_lcdnumber=OFF
$(package)_config_opts += -DQT_FEATURE_networkdiskcache=OFF
$(package)_config_opts += -DQT_FEATURE_pdf=OFF
$(package)_config_opts += -DQT_FEATURE_printdialog=OFF
$(package)_config_opts += -DQT_FEATURE_printer=OFF
$(package)_config_opts += -DQT_FEATURE_printpreviewdialog=OFF
$(package)_config_opts += -DQT_FEATURE_printpreviewwidget=OFF
$(package)_config_opts += -DQT_FEATURE_sessionmanager=OFF
$(package)_config_opts += -DQT_FEATURE_syntaxhighlighter=OFF
$(package)_config_opts += -DQT_FEATURE_textodfwriter=OFF
$(package)_config_opts += -DQT_FEATURE_topleveldomain=OFF
$(package)_config_opts += -DQT_FEATURE_udpsocket=OFF
$(package)_config_opts += -DQT_FEATURE_undocommand=OFF
$(package)_config_opts += -DQT_FEATURE_undogroup=OFF
$(package)_config_opts += -DQT_FEATURE_undostack=OFF
$(package)_config_opts += -DQT_FEATURE_undoview=OFF
$(package)_config_opts += -DQT_FEATURE_wizard=OFF
$(package)_config_opts += -DQT_FEATURE_xml=OFF

# --- Linux: XCB platform, system freetype/fontconfig, D-Bus runtime ---
$(package)_config_opts_linux += -DQT_FEATURE_xcb=ON
$(package)_config_opts_linux += -DQT_FEATURE_xcb_xlib=OFF
$(package)_config_opts_linux += -DQT_FEATURE_xlib=OFF
$(package)_config_opts_linux += -DQT_FEATURE_system_freetype=ON
$(package)_config_opts_linux += -DQT_FEATURE_fontconfig=ON
$(package)_config_opts_linux += -DQT_FEATURE_opengl=OFF
$(package)_config_opts_linux += -DINPUT_dbus=runtime
# Enable the Wayland client feature in qtbase.  The actual platform plugin
# (qwayland-generic) is built from the qtwayland submodule in $(package)_build_cmds.
$(package)_config_opts_linux += -DQT_FEATURE_wayland_client=ON

# --- Linux cross-compilation (aarch64) ---
$(package)_config_opts_aarch64_linux += -DQT_HOST_PATH=$(build_prefix)
$(package)_config_opts_aarch64_linux += -DCMAKE_SYSTEM_NAME=Linux
$(package)_config_opts_aarch64_linux += -DCMAKE_SYSTEM_PROCESSOR=aarch64
$(package)_config_opts_aarch64_linux += -DCMAKE_C_COMPILER=$(host)-gcc
$(package)_config_opts_aarch64_linux += -DCMAKE_CXX_COMPILER=$(host)-g++

# --- macOS ---
$(package)_config_opts_darwin += -DQT_FEATURE_dbus=OFF
$(package)_config_opts_darwin += -DQT_FEATURE_opengl=OFF
$(package)_config_opts_darwin += -DCMAKE_OSX_DEPLOYMENT_TARGET=$(OSX_MIN_VERSION)
$(package)_config_opts_darwin += -DQT_HOST_PATH=$(build_prefix)

ifneq ($(build_os),darwin)
$(package)_config_opts_darwin += -DCMAKE_SYSTEM_NAME=Darwin
$(package)_config_opts_darwin += -DCMAKE_C_COMPILER=$(host)-clang
$(package)_config_opts_darwin += -DCMAKE_CXX_COMPILER=$(host)-clang++
$(package)_config_opts_darwin += -DCMAKE_OSX_SYSROOT=$(OSX_SDK)
endif

# --- Windows (MinGW cross-compilation) ---
$(package)_config_opts_mingw32 += -DQT_FEATURE_dbus=OFF
$(package)_config_opts_mingw32 += -DQT_FEATURE_opengl=OFF
$(package)_config_opts_mingw32 += -DCMAKE_SYSTEM_NAME=Windows
$(package)_config_opts_mingw32 += -DCMAKE_C_COMPILER=$(host)-gcc
$(package)_config_opts_mingw32 += -DCMAKE_CXX_COMPILER=$(host)-g++
$(package)_config_opts_mingw32 += -DCMAKE_RC_COMPILER=$(host)-windres
$(package)_config_opts_mingw32 += -DCMAKE_FIND_ROOT_PATH=$(host_prefix)
$(package)_config_opts_mingw32 += -DCMAKE_FIND_ROOT_PATH_MODE_PROGRAM=NEVER
$(package)_config_opts_mingw32 += -DCMAKE_FIND_ROOT_PATH_MODE_LIBRARY=ONLY
$(package)_config_opts_mingw32 += -DCMAKE_FIND_ROOT_PATH_MODE_INCLUDE=ONLY
$(package)_config_opts_mingw32 += -DQT_HOST_PATH=$(build_prefix)

$(package)_build_env  = QT_RCC_TEST=1
$(package)_build_env += QT_RCC_SOURCE_DATE_OVERRIDE=1
endef

define $(package)_fetch_cmds
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_qttranslations_file_name),$($(package)_qttranslations_file_name),$($(package)_qttranslations_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_qttools_file_name),$($(package)_qttools_file_name),$($(package)_qttools_sha256_hash)) && \
$(call fetch_file,$(package),$($(package)_download_path),$($(package)_qtwayland_file_name),$($(package)_qtwayland_file_name),$($(package)_qtwayland_sha256_hash))
endef

define $(package)_extract_cmds
  mkdir -p $($(package)_extract_dir) && \
  echo "$($(package)_sha256_hash)  $($(package)_source)" > $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_qttranslations_sha256_hash)  $($(package)_source_dir)/$($(package)_qttranslations_file_name)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_qttools_sha256_hash)  $($(package)_source_dir)/$($(package)_qttools_file_name)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  echo "$($(package)_qtwayland_sha256_hash)  $($(package)_source_dir)/$($(package)_qtwayland_file_name)" >> $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  $(build_SHA256SUM) -c $($(package)_extract_dir)/.$($(package)_file_name).hash && \
  mkdir qtbase && \
  tar --no-same-owner --strip-components=1 -xf $($(package)_source) -C qtbase && \
  mkdir qttranslations && \
  tar --no-same-owner --strip-components=1 -xf $($(package)_source_dir)/$($(package)_qttranslations_file_name) -C qttranslations && \
  mkdir qttools && \
  tar --no-same-owner --strip-components=1 -xf $($(package)_source_dir)/$($(package)_qttools_file_name) -C qttools && \
  mkdir qtwayland && \
  tar --no-same-owner --strip-components=1 -xf $($(package)_source_dir)/$($(package)_qtwayland_file_name) -C qtwayland
endef

# No patches are required for Qt 6.8.3.  All issues addressed by the Qt5 patches
# (qmake mkspecs, Android JNI, lrelease path, lib paths, endian headers, etc.)
# are either fixed upstream in Qt6 or handled differently by CMake.
define $(package)_preprocess_cmds
  : # intentionally empty
endef

# depends/hosts/linux.mk sets x86_64_linux_CXX="g++ -m64" — compiler + flag in one
# variable.  CMake requires CMAKE_CXX_COMPILER to be the bare executable; the
# extra flags must go into CMAKE_CXX_FLAGS.  Use GNU Make $(firstword) /
# $(wordlist) to split them at configure time.
define $(package)_config_cmds
  export PKG_CONFIG_SYSROOT_DIR=/ && \
  export PKG_CONFIG_LIBDIR=$(host_prefix)/lib/pkgconfig && \
  export PKG_CONFIG_PATH=$(host_prefix)/share/pkgconfig && \
  cmake -B qtbase/build -S qtbase \
    -GNinja \
    $($(package)_config_opts) \
    -DCMAKE_C_COMPILER="$(firstword $($(package)_cc))" \
    -DCMAKE_CXX_COMPILER="$(firstword $($(package)_cxx))" \
    -DCMAKE_C_FLAGS="$(wordlist 2,99,$($(package)_cc)) $($(package)_cflags) $($(package)_cppflags)" \
    -DCMAKE_CXX_FLAGS="$(wordlist 2,99,$($(package)_cxx)) $($(package)_cxxflags) $($(package)_cppflags)" \
    -DCMAKE_EXE_LINKER_FLAGS="$($(package)_ldflags)" \
    -DCMAKE_SHARED_LINKER_FLAGS="$($(package)_ldflags)"
endef

# Build order:
#   1. Build+locally-install qtbase    → $($(package)_extract_dir)/qt_install
#   2. Configure+build qttools         (needs Qt6 CMake config from step 1)
#   3. Install qttools                 → qt_install (provides lrelease for step 5)
#   4. Configure+build+install qtwayland on Linux (needs libwayland + wayland-protocols from host_prefix)
#   5. Configure+build qttranslations  (needs lrelease from step 3)
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
  ninja -C qttools/build && \
  cmake --install qttools/build --prefix $($(package)_extract_dir)/qt_install && \
  if [ "$(host_os)" = "linux" ]; then \
    export PKG_CONFIG_SYSROOT_DIR=/ ; \
    export PKG_CONFIG_LIBDIR=$(host_prefix)/lib/pkgconfig ; \
    export PKG_CONFIG_PATH=$(host_prefix)/share/pkgconfig ; \
    export PATH=$(host_prefix)/bin:$$$$PATH ; \
    cmake -B qtwayland/build -S qtwayland \
      -GNinja \
      -DCMAKE_BUILD_TYPE=Release \
      -DCMAKE_PREFIX_PATH="$($(package)_extract_dir)/qt_install;$(host_prefix)" \
      -DCMAKE_INSTALL_PREFIX=$($(package)_extract_dir)/qt_install \
      -DBUILD_SHARED_LIBS=OFF \
      -DQT_BUILD_EXAMPLES=OFF \
      -DQT_BUILD_TESTS=OFF \
      -DFEATURE_wayland_client=ON \
      -DFEATURE_wayland_server=OFF \
      -DFEATURE_wayland_compositor=OFF \
      -DFEATURE_wayland_compositor_quick=OFF \
      -DFEATURE_wayland_egl_client=OFF \
      -DFEATURE_opengl=OFF && \
    ninja -C qtwayland/build && \
    cmake --install qtwayland/build --prefix $($(package)_extract_dir)/qt_install ; \
  fi && \
  cmake -B qttranslations/build -S qttranslations \
    -GNinja \
    -DCMAKE_BUILD_TYPE=Release \
    -DCMAKE_PREFIX_PATH=$($(package)_extract_dir)/qt_install \
    -DCMAKE_INSTALL_PREFIX=$($(package)_extract_dir)/qt_install && \
  ninja -C qttranslations/build
endef

# Install all modules to the depends staging prefix.
# cmake --install --prefix overrides CMAKE_INSTALL_PREFIX without DESTDIR indirection.
# qtwayland is only staged on Linux (built conditionally in build_cmds).
define $(package)_stage_cmds
  cmake --install qtbase/build         --prefix $($(package)_staging_prefix_dir) && \
  cmake --install qttools/build        --prefix $($(package)_staging_prefix_dir) && \
  if [ -d qtwayland/build ]; then \
    cmake --install qtwayland/build    --prefix $($(package)_staging_prefix_dir) ; \
  fi && \
  cmake --install qttranslations/build --prefix $($(package)_staging_prefix_dir)
endef

# Qt6's cmake build does not emit usable pkg-config files and installs the
# host tools (moc/rcc/uic) under libexec/ instead of bin/.  Without these the
# top-level configure cannot detect Qt and neurai-qt is silently skipped.
# We patch both up here so any depends consumer (Docker, gitian, local) gets
# a fully wired Qt6 toolchain with no extra steps.
#
# Symlinks live in two places:
#   - bin/        : convenience for direct CLI use
#   - native/bin/ : where depends's config.site points $with_qt_bindir, so
#                   the top-level configure (AC_PATH_PROGS) finds the tools
#                   in native (host==build) Linux builds without
#                   --with-qt-bindir.
#
# .pc files use $$$${pcfiledir} so they are relocatable: pkg-config resolves
# the prefix relative to the .pc file's own directory at lookup time.
# Four dollars are required because make expands the recipe twice: once via
# $(call ...) and again as a recipe line.
#
# Qt6Gui.pc Libs intentionally omits BundledFreetype (Qt links system
# freetype per QT_FEATURE_system_freetype=ON) and the xcb-glx/xinerama/xinput
# libs (not built by depends and not needed by our XCB plugin).
define $(package)_postprocess_cmds
  rm -rf lib/cmake/ && \
  rm -f lib/lib*.la lib/*.prl plugins/*/*.prl && \
  mkdir -p bin native/bin && \
  ln -sf ../libexec/moc bin/moc && \
  ln -sf ../libexec/rcc bin/rcc && \
  ln -sf ../libexec/uic bin/uic && \
  ln -sf ../../libexec/moc native/bin/moc && \
  ln -sf ../../libexec/rcc native/bin/rcc && \
  ln -sf ../../libexec/uic native/bin/uic && \
  ln -sf ../../bin/lrelease native/bin/lrelease && \
  ln -sf ../../bin/lupdate native/bin/lupdate && \
  mkdir -p lib/pkgconfig && \
  printf '%s\n' \
    'prefix=$$$${pcfiledir}/../..' \
    'exec_prefix=$$$${prefix}' \
    'libdir=$$$${prefix}/lib' \
    'includedir=$$$${prefix}/include' \
    'bindir=$$$${prefix}/bin' \
    'libexecdir=$$$${prefix}/libexec' \
    '' \
    'Name: Qt6Core' \
    'Description: Qt6 Core module (static, generated by depends)' \
    'Version: $($(package)_version)' \
    'Libs: -L$$$${libdir} -lQt6Core -lQt6BundledPcre2 -lQt6BundledZLIB -ldl -lpthread' \
    'Cflags: -I$$$${includedir} -I$$$${includedir}/QtCore -DQT_STATIC' \
    > lib/pkgconfig/Qt6Core.pc && \
  printf '%s\n' \
    'prefix=$$$${pcfiledir}/../..' \
    'exec_prefix=$$$${prefix}' \
    'libdir=$$$${prefix}/lib' \
    'includedir=$$$${prefix}/include' \
    'plugindir=$$$${prefix}/plugins' \
    '' \
    'Name: Qt6Gui' \
    'Description: Qt6 Gui module (static, generated by depends)' \
    'Version: $($(package)_version)' \
    'Requires: Qt6Core' \
    'Libs: -L$$$${libdir} -L$$$${plugindir}/platforms -lqxcb -lQt6XcbQpa -lQt6FbSupport -lQt6InputSupport -lQt6DeviceDiscoverySupport -lQt6Gui -lQt6BundledHarfbuzz -lQt6BundledLibpng -lxcb -lxcb-icccm -lxcb-image -lxcb-keysyms -lxcb-randr -lxcb-render -lxcb-render-util -lxcb-shape -lxcb-shm -lxcb-sync -lxcb-xfixes -lxcb-xkb -lxcb-cursor -lxcb-ewmh -lxcb-util -lxkbcommon -lxkbcommon-x11 -lfontconfig -lfreetype -lexpat -lXau' \
    'Cflags: -I$$$${includedir} -I$$$${includedir}/QtGui -DQT_STATIC' \
    > lib/pkgconfig/Qt6Gui.pc && \
  printf '%s\n' \
    'prefix=$$$${pcfiledir}/../..' \
    'exec_prefix=$$$${prefix}' \
    'libdir=$$$${prefix}/lib' \
    'includedir=$$$${prefix}/include' \
    '' \
    'Name: Qt6Widgets' \
    'Description: Qt6 Widgets module (static, generated by depends)' \
    'Version: $($(package)_version)' \
    'Requires: Qt6Gui' \
    'Libs: -L$$$${libdir} -lQt6Widgets' \
    'Cflags: -I$$$${includedir} -I$$$${includedir}/QtWidgets -DQT_STATIC' \
    > lib/pkgconfig/Qt6Widgets.pc && \
  printf '%s\n' \
    'prefix=$$$${pcfiledir}/../..' \
    'exec_prefix=$$$${prefix}' \
    'libdir=$$$${prefix}/lib' \
    'includedir=$$$${prefix}/include' \
    '' \
    'Name: Qt6Network' \
    'Description: Qt6 Network module (static, generated by depends)' \
    'Version: $($(package)_version)' \
    'Requires: Qt6Core' \
    'Libs: -L$$$${libdir} -lQt6Network -lssl -lcrypto' \
    'Cflags: -I$$$${includedir} -I$$$${includedir}/QtNetwork -DQT_STATIC' \
    > lib/pkgconfig/Qt6Network.pc && \
  printf '%s\n' \
    'prefix=$$$${pcfiledir}/../..' \
    'exec_prefix=$$$${prefix}' \
    'libdir=$$$${prefix}/lib' \
    'includedir=$$$${prefix}/include' \
    '' \
    'Name: Qt6Test' \
    'Description: Qt6 Test module (static, generated by depends)' \
    'Version: $($(package)_version)' \
    'Requires: Qt6Core' \
    'Libs: -L$$$${libdir} -lQt6Test' \
    'Cflags: -I$$$${includedir} -I$$$${includedir}/QtTest -DQT_STATIC' \
    > lib/pkgconfig/Qt6Test.pc && \
  printf '%s\n' \
    'prefix=$$$${pcfiledir}/../..' \
    'exec_prefix=$$$${prefix}' \
    'libdir=$$$${prefix}/lib' \
    'includedir=$$$${prefix}/include' \
    '' \
    'Name: Qt6PrintSupport' \
    'Description: Qt6 PrintSupport module (static, generated by depends)' \
    'Version: $($(package)_version)' \
    'Requires: Qt6Widgets' \
    'Libs: -L$$$${libdir} -lQt6PrintSupport' \
    'Cflags: -I$$$${includedir} -I$$$${includedir}/QtPrintSupport -DQT_STATIC' \
    > lib/pkgconfig/Qt6PrintSupport.pc && \
  if [ -f lib/libQt6WaylandClient.a ]; then \
    printf '%s\n' \
      'prefix=$$$${pcfiledir}/../..' \
      'exec_prefix=$$$${prefix}' \
      'libdir=$$$${prefix}/lib' \
      'includedir=$$$${prefix}/include' \
      'plugindir=$$$${prefix}/plugins' \
      '' \
      'Name: Qt6WaylandClient' \
      'Description: Qt6 WaylandClient module (static, generated by depends)' \
      'Version: $($(package)_version)' \
      'Requires: Qt6Gui' \
      'Libs: -L$$$${libdir} -L$$$${plugindir}/platforms -lqwayland-generic -lQt6WaylandClient -lwayland-client -lwayland-cursor -lxkbcommon' \
      'Cflags: -I$$$${includedir} -I$$$${includedir}/QtWaylandClient -DQT_STATIC' \
      > lib/pkgconfig/Qt6WaylandClient.pc ; \
  fi
endef
