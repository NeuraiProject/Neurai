macOS build instructions
========================

The supported cross-build target is **x86-64, macOS 12.0 or later**. The
NIP-018 `mcl` backend currently requires x86-64; an arm64 or universal binary
needs a separate backend port and cryptographic validation.

Linux cross-compilation
-----------------------

The maintained build stages are in `.github/scripts/`. The macOS entry point
below uses those same stages to build dependencies, configure the project,
verify the Mach-O executables and produce release packages. It does not patch
source files or edit generated pkg-config files.

On Ubuntu 24.04, install the build tools from the repository root:

```sh
sudo ./.github/scripts/00-install-deps.sh osx
```

Choose a persistent work directory. SDKs, OSXCross sources and tools, dependency
archives, build outputs and reports stay there:

```sh
JOBS=16 ./contrib/mac-cross/setup.sh /home/docker-test/MAC
JOBS=16 ./contrib/mac-cross/build.sh /home/docker-test/MAC gui
```

For the daemon, CLI, transaction utility and unit-test executable without Qt:

```sh
JOBS=16 ./contrib/mac-cross/build.sh /home/docker-test/MAC headless
```

`setup.sh` downloads the pinned macOS 14.5 SDK and OSXCross revision, verifies
the SDK SHA-256, and builds the LLVM toolchain with clang/LLD 18. Downloads
are reused. The SDK archive may also be supplied with `MACOS_SDK_ARCHIVE` and
`MACOS_SDK_SHA256`. The default work directory is `MAC/` in the repository;
that generated directory is ignored by Git.

The SDK comes from Xcode and retains Apple's license terms. The default
packaged archive is hosted by [macosx-sdks](https://github.com/joseluisq/macosx-sdks/releases/tag/14.5).
The cross-toolchain is [OSXCross](https://github.com/tpoechtrager/osxcross).

Docker on a Linux build machine
-------------------------------

The supplied Dockerfile installs the build tools; the persistent work directory
is mounted into the container. Copy the project into `MAC/sources/neurai` on
the build machine, then run:

```sh
docker build -t neurai-mac-cross -f contrib/mac-cross/Dockerfile contrib/mac-cross
mkdir -p /home/docker-test/MAC
docker run --rm --user "$(id -u):$(id -g)" --cpus 16 --memory 48g \
  --mount type=bind,source=/home/docker-test/MAC,target=/MAC \
  --env JOBS=16 --env MAC_WORKDIR=/MAC \
  neurai-mac-cross /MAC/sources/neurai/contrib/mac-cross/setup.sh /MAC
docker run --rm --user "$(id -u):$(id -g)" --cpus 16 --memory 48g \
  --mount type=bind,source=/home/docker-test/MAC,target=/MAC \
  --env JOBS=16 --env MAC_WORKDIR=/MAC \
  neurai-mac-cross /MAC/sources/neurai/contrib/mac-cross/build.sh /MAC gui
```

Adjust CPU and memory limits for the build machine. CPU-intensive builds and
all downloads happen on the machine running these commands.

Configuration
-------------

Paths are configurable; no recipe requires `/home/docker-test` or `/MAC`:

| Variable | Purpose |
| --- | --- |
| `MAC_WORKDIR` | Persistent downloads, toolchain, dependency cache and build directory. |
| `OSXCROSS_ROOT` | An existing OSXCross installation (`bin/` and `SDK/`). |
| `OSX_SDK` | SDK directory; defaults to the SDK reported by OSXCross. |
| `OSX_MIN_VERSION` | Deployment target and application-bundle minimum; defaults to `12.0`. |
| `MAC_HOST` | x86-64 Darwin triplet; defaults to the OSXCross target. |
| `MAC_DEPENDS_PREFIX` | Dependency installation directory. |
| `MAC_BUILD_DIR` | Out-of-tree project build directory. |
| `MAC_RELEASE_DIR` | Package output directory. |
| `MAC_BUILD_TESTS` | `yes` (default) compiles the tests; `no` omits them. |
| `JOBS` | Compilation parallelism; defaults to `2`. |

The default release directory is `MAC/build/project-gui/release` (or
`project-headless/release`). It contains a CLI `.tar.gz`, an unsigned `.app`
ZIP for GUI builds, SHA-256 files and `macos-build.json`. The bundle contains
static Qt, its translations and a `qt.conf` that resolves paths relative to
the application. The compiler and `Info.plist` use the same minimum macOS version.

Qt's Cocoa integration and TLS plugins are linked explicitly. The macOS
GSS dependency and the pinned LLVM OS-availability implementation are part of
the normal `depends` recipes, including download hashes and the LLVM license.
Linux/XCB libraries are not used by the Darwin Qt metadata.

The LLVM flavor of OSXCross uses `ld64.lld`, whose relocatable `-r` link is
not supported by the libtool shared-consensus-library build. The scripts
therefore select `--with-libs=no` with that flavor; the node, wallet, GUI,
CLI, transaction utility and test executables are built normally.

Verification and execution
--------------------------

The macOS binary-check stage verifies Mach-O format, x86-64 architecture,
SDK/deployment versions, PIE, stack/segment permissions, system-only dynamic
dependencies, and the object format of dependency archives. A failed check
fails the build and removes its previous successful report.

Linux cannot run the resulting macOS executables. The unit tests are compiled
but require a Mac for execution. For example, after unpacking the CLI archive:

```sh
./bin/neuraid --version
./bin/neurai-cli --version
./bin/test_neurai
```

Packages produced by these scripts are unsigned. Signing and notarization
are subsequent release steps.

Native Intel macOS builds
-------------------------

`depends/hosts/darwin.mk` selects the Xcode compiler and SDK through `xcrun`
on macOS, and `depends/builders/darwin.mk` selects the corresponding build
host tools. The integration was validated by cross-compiling on Linux;
execution and a native macOS build require validation on a Mac. Apple Silicon
is still rejected by the existing x86-64 backend guard.
