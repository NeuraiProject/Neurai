package=libxkbcommon
$(package)_version=1.6.0
$(package)_download_path=https://xkbcommon.org/download/
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=0edc14eccdd391514458bc5f5a4b99863ed2d651e4dd761a90abf4f46ef99c2b
$(package)_dependencies=libxcb xcb_proto libwayland wayland_protocols
$(package)_build_subdir=build

# Meson-only since 1.0. Build static with explicit X11 and Wayland support so
# the Qt6 XCB plugin can resolve libxkbcommon-x11 (required for keyboard
# dispatch; without it Qt emits "failed to get core keyboard device info"
# and keystrokes never reach the wallet).
define $(package)_set_vars
  $(package)_config_opts  = --prefix=$(host_prefix)
  $(package)_config_opts += --libdir=lib
  $(package)_config_opts += --buildtype=release
  $(package)_config_opts += --default-library=static
  $(package)_config_opts += -Denable-x11=true
  $(package)_config_opts += -Denable-wayland=true
  $(package)_config_opts += -Denable-docs=false
  $(package)_config_opts += -Denable-tools=false
  $(package)_config_opts += -Denable-xkbregistry=false
endef

define $(package)_config_cmds
  env CC="$($(package)_cc)" CXX="$($(package)_cxx)" \
      CFLAGS="$($(package)_cppflags) $($(package)_cflags)" \
      CXXFLAGS="$($(package)_cppflags) $($(package)_cxxflags)" \
      LDFLAGS="$($(package)_ldflags)" \
      PKG_CONFIG_SYSROOT_DIR=/ \
      PKG_CONFIG_LIBDIR=$(host_prefix)/lib/pkgconfig \
      PKG_CONFIG_PATH=$(host_prefix)/share/pkgconfig \
    meson setup $($(package)_config_opts) .. .
endef

# Build only the static libraries we ship. Avoids compiling the test and
# benchmark binaries (test-x11, test-x11comp, bench-x11), which link against
# libxcb.a and would pull in libXau symbols (XauGetBestAuthByAddr,
# XauDisposeAuth) that are not provided by the depends tree.
define $(package)_build_cmds
  ninja libxkbcommon.a libxkbcommon-x11.a
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) meson install --no-rebuild
endef

define $(package)_postprocess_cmds
  rm -rf share lib/*.la
endef
