package=wayland_protocols
$(package)_version=1.33
$(package)_download_path=https://gitlab.freedesktop.org/wayland/wayland-protocols/-/releases/$($(package)_version)/downloads
$(package)_file_name=wayland-protocols-$($(package)_version).tar.xz
$(package)_sha256_hash=94f0c50b090d6e61a03f62048467b19abbe851be4e11ae7b36f65f8b98c3963a
$(package)_dependencies=libwayland
$(package)_build_subdir=build

# Pure XML-protocol package. No compiled code, just installs .xml + a .pc file.
define $(package)_set_vars
  $(package)_config_opts  = --prefix=$(host_prefix)
  $(package)_config_opts += --buildtype=release
  $(package)_config_opts += -Dtests=false
endef

define $(package)_config_cmds
  meson setup $($(package)_config_opts) .. .
endef

define $(package)_build_cmds
  ninja
endef

define $(package)_stage_cmds
  DESTDIR=$($(package)_staging_dir) ninja install
endef
