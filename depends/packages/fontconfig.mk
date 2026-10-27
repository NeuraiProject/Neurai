package=fontconfig
$(package)_version=2.15.0
$(package)_download_path=https://www.freedesktop.org/software/fontconfig/release/
$(package)_file_name=$(package)-$($(package)_version).tar.xz
$(package)_sha256_hash=63a0658d0e06e0fa886106452b58ef04f21f58202ea02a94c39de0d3335d7c0e
$(package)_dependencies=freetype expat native_gperf

define $(package)_set_vars
  $(package)_config_opts=--disable-docs --disable-static
endef

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install && \
  mkdir -p $($(package)_staging_prefix_dir)/share/licenses/fontconfig && \
  cp COPYING $($(package)_staging_prefix_dir)/share/licenses/fontconfig/COPYING
endef
