package=libwayland
$(package)_version=1.22.0
$(package)_download_path=https://gitlab.freedesktop.org/wayland/wayland/-/releases/$($(package)_version)/downloads
$(package)_file_name=wayland-$($(package)_version).tar.xz
$(package)_sha256_hash=1540af1ea698a471c2d8e9d288332c7e0fd360c8f1d12936ebb7e7cbc2425842
$(package)_dependencies=expat libffi
$(package)_build_subdir=build

# Meson-only since 1.20. Build libwayland-client/server/cursor static, plus the
# wayland-scanner code generator (needed as a BUILD-time tool by qtwayland).
define $(package)_set_vars
  $(package)_config_opts  = --prefix=$(host_prefix)
  $(package)_config_opts += --libdir=lib
  $(package)_config_opts += --buildtype=release
  $(package)_config_opts += --default-library=static
  $(package)_config_opts += -Ddocumentation=false
  $(package)_config_opts += -Dtests=false
  $(package)_config_opts += -Ddtd_validation=false
  $(package)_config_opts += -Dicon_directory=$(host_prefix)/share/icons
endef

define $(package)_config_cmds
  env CC="$($(package)_cc)" CXX="$($(package)_cxx)" \
      CFLAGS="$($(package)_cppflags) $($(package)_cflags)" \
      CXXFLAGS="$($(package)_cppflags) $($(package)_cxxflags)" \
      LDFLAGS="$($(package)_ldflags)" \
    meson setup $($(package)_config_opts) .. .
endef

define $(package)_build_cmds
  ninja
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) ninja install
endef

define $(package)_postprocess_cmds
  rm -f lib/*.la
endef
