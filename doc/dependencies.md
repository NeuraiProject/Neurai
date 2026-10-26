Dependencies
============

These are the dependencies currently used by Neurai. You can find instructions for installing them in the `build-*.md` file for your platform.

| Dependency | Version used | Minimum required | CVEs | Shared | [Bundled Qt library](https://doc.qt.io/qt-6/configure-options.html) |
| --- | --- | --- | --- | --- | --- |
| Berkeley DB | [4.8.30](http://www.oracle.com/technetwork/database/database-technologies/berkeleydb/downloads/index.html) | 4.8.x | No |  |  |
| Boost | [1.81.0](http://www.boost.org/users/download/) | 1.81.0 | No |  |  |
| ccache | [3.3.4](https://ccache.samba.org/download.html) |  | No |  |  |
| Clang | 18 (macOS cross-build through OSXCross, see [build-osx.md](build-osx.md)) | [14+](http://llvm.org/releases/download.html) (C++20 support) |  |  |  |
| D-Bus | [1.10.18](https://cgit.freedesktop.org/dbus/dbus/tree/NEWS?h=dbus-1.10) |  | No | Yes |  |
| Expat | [2.4.1](https://libexpat.github.io/) |  | Yes | Yes |  |
| fontconfig | [2.12.1](https://www.freedesktop.org/software/fontconfig/release/) |  | No | Yes |  |
| FreeType | [2.11.1](http://download.savannah.gnu.org/releases/freetype) |  | No |  |  |
| GCC |  | [12+](https://gcc.gnu.org/) |  |  |  |
| HarfBuzz-NG |  |  |  |  |  |
| libevent | [2.1.12-stable](https://github.com/libevent/libevent/releases) | 2.0.22 | No |  |  |
| libffi | 3.4.6 | | | | (Linux only, Wayland) |
| libICE    | 1.0.9  | | | | |
| libjpeg |  |  |  |  | [Yes](../depends/packages/qt.mk) |
| libpng |  |  |  |  | [Yes](../depends/packages/qt.mk) |
| liboqs | [0.16.0](https://github.com/open-quantum-safe/liboqs/releases) | 0.16.0 (required) | | | |
| libSM    | 1.2.2  | | | | |
| libX11    | 1.6.2  | | | | |
| libXau    | 1.0.8  | | | | |
| libXext    | 1.3.2  | | | | |
| macos_availability | 18.1.3 (LLVM OS-availability support, macOS only) | | | | |
| MiniUPnPc | [2.0.20170509](http://miniupnp.free.fr/files) |  | No |  |  |
| OpenSSL | [1.1.1k](https://www.openssl.org/source) |  | Yes |  |  |
| PCRE |  |  |  |  | [Yes](../depends/packages/qt.mk) |
| protobuf | [2.6.1](https://github.com/google/protobuf/releases) |  | No |  |  |
| Python (tests) |  | [3.4](https://www.python.org/downloads) |  |  |  |
| qrencode | [3.4.4](https://fukuchi.org/works/qrencode) |  | No |  |  |
| Qt | [6.8.3](https://download.qt.io/archive/qt/) | 6.x | No |  |  |
| Wayland | 1.22.0 |  |  |  | (Linux only) |
| XCB | 1.17.0 |  |  |  | [Yes](../depends/packages/qt.mk) (Linux only) |
| xkbcommon | 1.6.0 |  |  |  | [Yes](../depends/packages/qt.mk) (Linux only) |
| ZeroMQ | [4.3.4](https://github.com/zeromq/libzmq/releases) |  | No |  |  |
| zlib | [1.2.11](http://zlib.net/) |  |  |  | No |

Bundled in the source tree (no installation needed):

| Library | Version | Location |
| --- | --- | --- |
| BLAKE3 | 1.5.4 | `src/crypto/blake3` |
| Ed25519 ref10 (from libsodium) | | `src/crypto/ed25519` |
| mcl | commit `cbb18eb` ([herumi/mcl](https://github.com/herumi/mcl)) | `src/crypto/mcl` |
| Monocypher | 4.0.2 | `src/monocypher` |
| wasm3 | 0.5.0 | `src/wasm3` |
