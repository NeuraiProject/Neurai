#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source_root=$(cd "$script_dir/../.." && pwd)
source "$script_dir/env.sh"
if [[ -n "${1:-}" ]]; then export MAC_WORKDIR=$1; fi
mode=${2:-gui}
case "$mode" in gui) export NO_QT= ;; headless) export NO_QT=1 ;; *) echo "Use gui or headless" >&2; exit 2 ;; esac
mac_paths "$source_root"
if [[ ! -x "$OSXCROSS_ROOT/bin/osxcross-conf" ]] || \
   { [[ "$MAC_ARCH" == arm64 ]] && ! compgen -G "$OSXCROSS_ROOT/bin/aarch64-apple-darwin*-clang++" >/dev/null; }; then
    "$script_dir/setup.sh"
fi
depends_prefix=${MAC_DEPENDS_PREFIX:-}
mac_environment "$source_root"
export MAC_DEPENDS_PREFIX="${depends_prefix:-$MAC_WORKDIR/dependencies/$mode/$MAC_HOST}"
build_name=project-$mode
if [[ "$MAC_ARCH" != x86_64 ]]; then build_name+="-$MAC_ARCH"; fi
build_dir=${MAC_BUILD_DIR:-"$MAC_WORKDIR/build/$build_name"}
mkdir -p "$build_dir" "$MAC_WORKDIR/results" "$MAC_WORKDIR/cache"
rm -f "$MAC_WORKDIR/results/$build_name-status.txt"
export SOURCES_PATH=${SOURCES_PATH:-"$MAC_WORKDIR/downloads/depends"}
export BASE_CACHE=${BASE_CACHE:-"$MAC_WORKDIR/cache/depends"}
"$source_root/.github/scripts/02-copy-build-dependencies.sh" osx "$source_root"
(cd "$source_root" && flock "$MAC_WORKDIR/cache/autogen.lock" ./autogen.sh)
cd "$build_dir"
"$source_root/.github/scripts/04-configure-build.sh" osx "$source_root"
make -j"$JOBS"
"$source_root/.github/scripts/05-binary-checks.sh" osx "$source_root"
"$source_root/.github/scripts/06-package.sh" osx "$source_root" local
printf 'success\n' > "$MAC_WORKDIR/results/$build_name-status.txt"
