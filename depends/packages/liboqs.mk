package=liboqs
$(package)_version=0.15.0
$(package)_download_path=https://github.com/open-quantum-safe/liboqs/archive/refs/tags
$(package)_file_name=$($(package)_version).tar.gz
$(package)_sha256_hash=3983f7cd1247f37fb76a040e6fd684894d44a84cecdcfbdb90559b3216684b5c
$(package)_dependencies=

define $(package)_set_vars
$(package)_cmake_opts=-DCMAKE_BUILD_TYPE=Release
$(package)_cmake_opts+=-DBUILD_SHARED_LIBS=OFF
$(package)_cmake_opts+=-DOQS_BUILD_ONLY_LIB=ON
$(package)_cmake_opts+=-DOQS_MINIMAL_BUILD="SIG_ml_dsa_44;SIG_ml_dsa_65;SIG_ml_dsa_87"
$(package)_cmake_opts+=-DOQS_USE_OPENSSL=OFF
$(package)_cmake_opts+=-DOQS_DIST_BUILD=ON
$(package)_cmake_opts+=-DCMAKE_INSTALL_PREFIX=$(host_prefix)
endef

define $(package)_config_cmds
  cmake -G "Unix Makefiles" \
    $($(package)_cmake_opts) \
    .
endef

define $(package)_build_cmds
  $(MAKE) -j$(JOBS)
endef

define $(package)_stage_cmds
  $(MAKE) DESTDIR=$($(package)_staging_dir) install
endef
