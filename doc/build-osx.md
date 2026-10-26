macOS build instructions
========================

The cross-build targets are **Intel (`x86_64`) and Apple Silicon (`arm64`),
macOS 12.0 or later**. Each build produces one architecture. The pinned
NIP-018 `mcl` backend uses the same portable C++ implementation for both,
with architecture-specific baseline compiler flags and no JIT or assembly.

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

For a native Apple Silicon application, select ARM64:

```sh
MAC_ARCH=arm64 JOBS=16 ./contrib/mac-cross/build.sh /home/docker-test/MAC gui
MAC_ARCH=arm64 JOBS=16 ./contrib/mac-cross/build.sh /home/docker-test/MAC headless
```

ARM64 uses the canonical Automake triplet `aarch64-apple-darwin23.5`; Qt and
Mach-O metadata use Apple's architecture name `arm64`. Separate dependency
prefixes, project build directories and package names prevent an ARM64 build
from reusing Intel objects. The download cache and host tools are reusable.

`setup.sh` downloads the pinned macOS 14.5 SDK and OSXCross revision, verifies
the SDK SHA-256, and builds the Intel and ARM64 LLVM wrappers with clang/LLD 18. Downloads
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
all downloads happen on the machine running these commands. Add
`--env MAC_ARCH=arm64` to the build container to select Apple Silicon.

Configuration
-------------

Paths are configurable; no recipe requires `/home/docker-test` or `/MAC`:

| Variable | Purpose |
| --- | --- |
| `MAC_WORKDIR` | Persistent downloads, toolchain, dependency cache and build directory. |
| `OSXCROSS_ROOT` | An existing OSXCross installation (`bin/` and `SDK/`). |
| `OSX_SDK` | SDK directory; defaults to the SDK reported by OSXCross. |
| `OSX_MIN_VERSION` | Deployment target and application-bundle minimum; defaults to `12.0`. |
| `MAC_ARCH` | `x86_64` (default) or `arm64`; `aarch64` is accepted as an alias. |
| `MAC_HOST` | Canonical Darwin triplet; must match the architecture and OSXCross target. |
| `MAC_DEPENDS_PREFIX` | Dependency installation directory. |
| `MAC_BUILD_DIR` | Out-of-tree project build directory. |
| `MAC_RELEASE_DIR` | Package output directory. |
| `MAC_BUILD_TESTS` | `yes` (default) compiles the tests; `no` omits them. |
| `JOBS` | Compilation parallelism; defaults to `2`. |

The default release directory is `MAC/build/project-gui/release` (or
`project-headless/release`); ARM64 appends `-arm64` to the project directory.
It contains a CLI `.tar.gz`, an unsigned `.app`
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

The macOS binary-check stage verifies Mach-O format, the selected architecture,
SDK/deployment versions, PIE, stack/segment permissions, system-only dynamic
dependencies, and the object format of dependency archives. ARM64 executables
must also contain the linker's ad-hoc code signature; its SHA-256 code-page
hashes are checked. A failed check
fails the build and removes its previous successful report.

Linux cannot run the resulting macOS executables. The unit tests are compiled
but require a Mac for execution. For example, after unpacking the CLI archive:

```sh
./bin/neuraid --version
./bin/neurai-cli --version
./bin/test_neurai
```

On an Apple Silicon Mac, `file bin/neuraid` must report `arm64`. A short first
check of the privacy pool's cryptographic primitives and proof verification is:

```sh
./bin/test_neurai --run_test='mcl_backend_tests,groth16_tests,zkverify_*,bn254_fr_tests,poseidon_*'
codesign --verify --strict ./bin/neuraid
```

Then run the complete unit suite and open `Neurai-Qt.app` from the GUI ZIP.
The unit-test executable is in the CLI archive. Record the macOS version,
processor and test output when checking the build on a real Mac.

Packages are not signed with an Apple Developer certificate or notarized.
The ARM64 linker signature is ad-hoc. Developer signing and notarization
are subsequent release steps. GitHub CI builds and packages each macOS
architecture separately; it does not execute those artifacts on Linux.

Native macOS builds
--------------------

`depends/hosts/darwin.mk` selects the Xcode compiler and SDK through `xcrun`
on macOS, and `depends/builders/darwin.mk` selects the corresponding build
host tools. The integration was validated by cross-compiling on Linux;
execution and a native macOS build require validation on a Mac. The same
ARMv8-A baseline backend configuration is selected for an Apple Silicon host.
Universal packaging is a separate step: these scripts generate individual
Intel and ARM64 packages.
