# Release binaries with Docker

Three Dockerfiles build a remote Neurai branch and always extract the binaries
into `doc/docker/create-bin/tests/output` in this checkout. Docker with BuildKit,
Git, Bash, and Internet access are required. On Windows, use WSL with Docker Desktop in Linux
container mode. All builder images target Linux amd64; ARM hosts require
Docker's amd64 emulation.

## Build and extract with one command

Start inside your checkout to resolve the repository location automatically.
The examples below reuse `NEURAI_REPO_ROOT`. You can run the script from any
directory; the output location is always `tests/output` next to `build.sh`:

```bash
NEURAI_REPO_ROOT="$(git rev-parse --show-toplevel)"
"$NEURAI_REPO_ROOT/doc/docker/create-bin/build.sh" linux DePIN-Test user
```

Other platform and profile examples:

```bash
# Linux x86_64, server without a graphical interface.
"$NEURAI_REPO_ROOT/doc/docker/create-bin/build.sh" linux DePIN-Test server

# Windows x86_64, with a graphical interface.
"$NEURAI_REPO_ROOT/doc/docker/create-bin/build.sh" windows DePIN-Test user

# Windows x86_64, server.
"$NEURAI_REPO_ROOT/doc/docker/create-bin/build.sh" windows DePIN-Test server

# macOS Intel and Apple Silicon, respectively.
"$NEURAI_REPO_ROOT/doc/docker/create-bin/build.sh" macos DePIN-Test user x86_64
"$NEURAI_REPO_ROOT/doc/docker/create-bin/build.sh" macos DePIN-Test user arm64

# macOS Apple Silicon, server.
"$NEURAI_REPO_ROOT/doc/docker/create-bin/build.sh" macos DePIN-Test server arm64
```

The syntax is `build.sh [--no-cache] platform [branch] [user|server] [architecture]`.
Defaults are `DePIN-Test`, `user`, and `x86_64`. Builds use the remote repository,
so local changes are not included. The selected branch must provide a compatible
`depends` system and configure options; macOS also requires `contrib/mac-cross`.
The `DePIN-Test` branch includes these.

The builder compiles the selected remote revision without applying source
patches. Commit and push local fixes to the branch before building it. A local
commit alone is not available to the remote clone. To include the Fontconfig
and Qt startup fixes, select a revision containing those changes and the
`depends/packages/native_gperf.mk` recipe.

| Platform | `server` profile | `user` profile |
| --- | --- | --- |
| Linux x86_64 | `neuraid`, `neurai-cli`, `neurai-tx` | Server binaries plus `neurai-qt` |
| Windows x86_64 | `neuraid.exe`, `neurai-cli.exe` | Server binaries plus `neurai-qt.exe` |
| macOS x86_64 / arm64 | `neuraid`, `neurai-cli`, `neurai-tx` | Server binaries plus `neurai-qt` |

Both profiles retain the daemon's wallet support. The `server` profile skips
downloading and building Qt. Windows omits `neurai-tx` because it currently does
not link on that platform, matching the project's CI. macOS exports Mach-O
executables without packaging an `.app` bundle.

The output also includes `COPYING`, licenses available in `depends`,
`BUILD-INFO.txt` with the exact branch and commit, and `SHA256SUMS`. macOS adds
a verification report. All builds share `tests/output`; files with matching names
are overwritten. Copy results elsewhere if you need to retain multiple platforms
or profiles. The repository's root `.gitignore` excludes the entire output
directory. The `tests` directory also contains the wrapper and GUI regression tests.

## Size, debugging, and dependencies

- Debugging, tests, benchmarks, and development library builds are disabled.
- Neurai code is compiled with `-Os -g0`, unused sections are removed, and symbols
  are stripped. Assertions and hardening remain enabled.
- `depends` builds libraries in release mode and provides static Qt, Berkeley DB,
  Boost, OpenSSL, and other dependencies. You do not need to install Qt or Neurai's
  libraries on the target machine.
- For graphical Linux builds, the script also forces static FreeType, Fontconfig,
  Expat, and D-Bus, and separates their cache from regular `depends` builds.
  Font and configuration paths point to the user's system.
  The Fontconfig 2.15.0 recipe in this checkout supports configuration descriptions
  and font width ranges used by current Linux font configurations; the selected
  remote revision must include that recipe to receive those fixes.
- Linux also links `libstdc++` and `libgcc` statically. It retains glibc and basic
  system libraries: the Debian 12 base uses glibc 2.36. The graphical interface
  requires an X11 or Wayland server, system XKB data, and fonts. The build fails
  if it detects additional shared dependencies.
- Windows links the MinGW runtimes statically and checks that their DLLs and
  the project's dependency DLLs are not required. It uses Windows system DLLs.
- macOS uses OSXCross and the SDK configured by `contrib/mac-cross/setup.sh`
  (currently 14.5 with a verified SHA-256), targeting macOS 12.0 or later.
  It retains Apple's system libraries and frameworks. The report checks
  architecture, minimum version, and dependencies, but the binaries must be
  tested on a Mac. Developer ID signing and notarization are not included.

The final image contains BusyBox, the exporter, and the build outputs. It contains
no compilers, source code, or build caches. Windows and macOS binaries are copied
without attempting to execute them inside the Linux container.

## Options

```bash
# Limit memory usage.
JOBS=2 "$NEURAI_REPO_ROOT/doc/docker/create-bin/build.sh" linux DePIN-Test server

# Select another branch.
"$NEURAI_REPO_ROOT/doc/docker/create-bin/build.sh" linux my-branch user

# Pin a full commit hash from that branch.
SOURCE_COMMIT='<full-commit-hash>' "$NEURAI_REPO_ROOT/doc/docker/create-bin/build.sh" linux DePIN-Test server

# Rebuild Docker layers without reusing cached instruction results.
"$NEURAI_REPO_ROOT/doc/docker/create-bin/build.sh" linux DePIN-Test user --no-cache
```

`REPOSITORY` changes the remote repository; `IMAGE` sets the image name;
`OSX_MIN_VERSION` changes the minimum macOS version. `JOBS` defaults to 2:
building Qt requires substantial memory and disk space. Downloaded sources and
built `depends` packages are reused through BuildKit caches. The script resolves
the remote commit on every invocation so that new commits on the branch
invalidate the corresponding Docker layer.

`--no-cache` can appear before or after the positional arguments. It passes
Docker's `--no-cache` option to the build, rerunning the Dockerfile instructions.
Downloaded sources and built `depends` packages in cache mounts remain reusable;
this option does not clear those mounts. See
[Docker's cache mount documentation](https://docs.docker.com/build/cache/optimize/#use-cache-mounts).
Cached builds remain the default; resolving the remote commit already ensures
that new commits on the selected branch trigger a rebuild.

## Using Docker directly

The build context is **this directory**. From inside your checkout, resolve its
location and use it for both the Dockerfile and build context. Replace
`<full-commit-hash>` with the desired commit hash:

```bash
NEURAI_DOCKER_DIR="$(git rev-parse --show-toplevel)/doc/docker/create-bin"
docker build --platform linux/amd64 \
  -f "$NEURAI_DOCKER_DIR/Dockerfile-Linux64" \
  --build-arg BRANCH=DePIN-Test --build-arg BUILD_TYPE=server \
  --build-arg JOBS=2 --build-arg 'SOURCE_COMMIT=<full-commit-hash>' \
  -t neurai-linux-release "$NEURAI_DOCKER_DIR"

mkdir -p "$NEURAI_DOCKER_DIR/tests/output"
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$NEURAI_DOCKER_DIR/tests/output:/output" neurai-linux-release
```

For Windows, use `Dockerfile-Win64`; for macOS, use `Dockerfile-MacOS` and add
`--build-arg MAC_ARCH=arm64` when appropriate. `SOURCE_COMMIT` is optional when
using Docker directly, but you must update it when the branch advances or use
`--no-cache` to refresh the clone. The `build.sh` script resolves it automatically.

You can repeat just `docker run` to extract the outputs again without rebuilding.
Create `tests/output` before running the exporter. The volume mount makes that
host directory available as `/output` inside the container.

If the image build succeeds but extraction is interrupted, run the following
from inside your checkout. Replace the placeholder with the image name and tag
shown in the build log:

```bash
NEURAI_DOCKER_DIR="$(git rev-parse --show-toplevel)/doc/docker/create-bin"
mkdir -p "$NEURAI_DOCKER_DIR/tests/output"
NEURAI_RELEASE_IMAGE='<image-name>:<tag>'
docker run --rm --user "$(id -u):$(id -g)" \
  -v "$NEURAI_DOCKER_DIR/tests/output:/output" "$NEURAI_RELEASE_IMAGE"
```

## Validation

Run the wrapper regression tests with Python 3. To also check Linux
GUI startup against the host's font configuration, install `xvfb-run` and point
`NEURAI_GUI_BINARY` to an exported binary:

```bash
python3 -B -m unittest discover -s "$NEURAI_REPO_ROOT/doc/docker/create-bin/tests" -v
NEURAI_GUI_BINARY="$NEURAI_REPO_ROOT/doc/docker/create-bin/tests/output/neurai-qt" \
  python3 -B -m unittest discover -s "$NEURAI_REPO_ROOT/doc/docker/create-bin/tests" -v
```
