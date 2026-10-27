package=native_gperf
$(package)_version=3.1
$(package)_download_path=https://ftp.gnu.org/gnu/gperf
$(package)_file_name=gperf-$($(package)_version).tar.gz
$(package)_sha256_hash=588546b945bba4b70b6a3a616e80b4ab466e3f33024a352fc2198112cdbb3ae2

define $(package)_config_cmds
  $($(package)_autoconf)
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf share
endef
