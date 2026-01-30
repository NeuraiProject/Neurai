package=liboqs
$(package)_version=0.15.0
$(package)_download_path=https://github.com/open-quantum-safe/liboqs/archive/refs/tags
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c
$(package)_build_subdir=build

define $(package)_set_vars
  $(package)_config_opts=-DBUILD_SHARED_LIBS=OFF
  $(package)_config_opts+=-DOQS_BUILD_ONLY_LIB=ON
  $(package)_config_opts+=-DOQS_USE_OPENSSL=OFF
  $(package)_config_opts+=-DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
  $(package)_config_opts+=-DOQS_DIST_BUILD=ON
  $(package)_config_opts_linux=-DCMAKE_POSITION_INDEPENDENT_CODE=ON
  $(package)_config_opts_mingw32=-DCMAKE_SYSTEM_NAME=Windows
  $(package)_config_opts_darwin=-DCMAKE_OSX_ARCHITECTURES=$(host_arch)
endef

define $(package)_preprocess_cmds
  mkdir -p build
endef

define $(package)_config_cmds
  $($(package)_cmake) $($(package)_config_opts) ..
endef

define $(package)_build_cmds
  $(MAKE)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef

define $(package)_postprocess_cmds
  rm -rf bin share
endef
