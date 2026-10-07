packages:=boost openssl libevent zeromq liboqs
native_packages := native_ccache native_b2

qt_native_packages = native_protobuf
# qt.mk depends on native_qt (moc, rcc, uic... for the build machine) when the
# target runs on another architecture or system: Windows, macOS, ARM. Without
# it here, make has no rule for native_qt.
ifneq ($(host_arch)_$(host_os),$(build_arch)_$(build_os))
qt_native_packages += native_qt
endif
qt_packages = qrencode protobuf

qt_x86_64_linux_packages:=qt expat dbus libxcb xcb_proto libXau xproto freetype fontconfig libxkbcommon libxcb_util libxcb_util_cursor libxcb_util_render libxcb_util_keysyms libxcb_util_image libxcb_util_wm libwayland wayland_protocols libffi
qt_i686_linux_packages:=$(qt_x86_64_linux_packages)
qt_arm_linux_packages:=$(qt_x86_64_linux_packages)
qt_aarch64_linux_packages:=$(qt_x86_64_linux_packages)

qt_darwin_packages=qt
qt_mingw32_packages=qt

wallet_packages=bdb

upnp_packages=miniupnpc

darwin_native_packages = native_biplist native_ds_store native_mac_alias

ifneq ($(build_os),darwin)
darwin_native_packages += native_cctools native_libtapi native_cdrkit native_libdmg-hfsplus native_clang
endif
