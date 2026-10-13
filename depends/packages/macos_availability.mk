package=macos_availability
$(package)_version=18.1.3
$(package)_download_path=https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-$($(package)_version)/compiler-rt/lib/builtins
$(package)_download_file=os_version_check.c
$(package)_file_name=llvm-$($(package)_version)-os_version_check.c
$(package)_sha256_hash=8ed75fa38482b18f17797c1530739688b6939b7c6495b2ffc1361114b1184c1c
$(package)_license_file=llvm-$($(package)_version)-compiler-rt-LICENSE.TXT
$(package)_license_hash=1a8f1058753f1ba890de984e48f0242a3a5c29a6a8f2ed9fd813f36985387e8d
$(package)_extra_sources=$($(package)_license_file)

# Linux clang does not ship Darwin compiler-rt. Qt's Objective-C @available
# checks need this upstream implementation of __isPlatformVersionAtLeast.
# Use the real OS checks rather than assuming every API exists at runtime.
define $(package)_fetch_cmds
  $(call fetch_file,$(package),$($(package)_download_path),$($(package)_download_file),$($(package)_file_name),$($(package)_sha256_hash)) && \
  $(call fetch_file,$(package),https://raw.githubusercontent.com/llvm/llvm-project/llvmorg-$($(package)_version)/compiler-rt,LICENSE.TXT,$($(package)_license_file),$($(package)_license_hash))
endef

define $(package)_extract_cmds
  cp $($(package)_source) os_version_check.c
endef

define $(package)_build_cmds
  $($(package)_cc) $($(package)_cflags) $($(package)_cppflags) -std=c11 -fPIC -c os_version_check.c -o os_version_check.o && \
  $($(package)_ar) crs libmacos-availability.a os_version_check.o
endef

define $(package)_stage_cmds
  mkdir -p $($(package)_staging_prefix_dir)/lib $($(package)_staging_prefix_dir)/share/licenses/compiler-rt && \
  cp libmacos-availability.a $($(package)_staging_prefix_dir)/lib/ && \
  cp $($(package)_source_dir)/$($(package)_license_file) $($(package)_staging_prefix_dir)/share/licenses/compiler-rt/LICENSE.TXT
endef
