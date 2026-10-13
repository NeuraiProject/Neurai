#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
source "$script_dir/env.sh"
if [[ -n "${1:-}" ]]; then export MAC_WORKDIR=$1; fi
mac_paths "$(cd "$script_dir/../.." && pwd)"
mkdir -p "$MAC_WORKDIR"/{downloads,sources,logs,results}
MAC_WORKDIR=$(cd "$MAC_WORKDIR" && pwd)
export MAC_WORKDIR

osxcross_commit=27d21e4977c9751d01199c7a226a6faf494c3dd9
sdk_version=${OSX_SDK_VERSION:-14.5}
sdk_hash=${MACOS_SDK_SHA256:-6e146275d19f027faa2e8354da5e0267513abf013b8f16ad65a231653a2b1c5d}
sdk_archive=${MACOS_SDK_ARCHIVE:-"$MAC_WORKDIR/downloads/MacOSX$sdk_version.sdk.tar.xz"}
if [[ "$sdk_version" != 14.5 && -z "${MACOS_SDK_SHA256:-}" ]]; then
    echo "A different SDK requires MACOS_SDK_ARCHIVE and MACOS_SDK_SHA256" >&2
    exit 1
fi
if [[ ! -f "$sdk_archive" ]]; then
    if [[ -n "${MACOS_SDK_ARCHIVE:-}" ]]; then echo "SDK archive not found: $sdk_archive" >&2; exit 1; fi
    curl --fail --location --retry 3 \
      "https://github.com/joseluisq/macosx-sdks/releases/download/$sdk_version/MacOSX$sdk_version.sdk.tar.xz" \
      --output "$sdk_archive.part"
    mv "$sdk_archive.part" "$sdk_archive"
fi
printf '%s  %s\n' "$sdk_hash" "$sdk_archive" | sha256sum -c -
cross_source="$MAC_WORKDIR/sources/osxcross"
if [[ ! -d "$cross_source/.git" ]]; then
    git init "$cross_source"
    git -C "$cross_source" remote add origin https://github.com/tpoechtrager/osxcross.git
    git -C "$cross_source" fetch --depth 1 origin "$osxcross_commit"
    git -C "$cross_source" checkout --detach "$osxcross_commit"
fi
[[ $(git -C "$cross_source" rev-parse HEAD) == "$osxcross_commit" ]] || { echo "Unexpected OSXCross revision" >&2; exit 1; }
mkdir -p "$cross_source/tarballs"
ln -sfn "$sdk_archive" "$cross_source/tarballs/MacOSX$sdk_version.sdk.tar.xz"
export PATH="/usr/lib/llvm-18/bin:$PATH"
if [[ ! -x "$OSXCROSS_ROOT/bin/x86_64-apple-darwin23.5-clang++" || \
      ! -x "$OSXCROSS_ROOT/bin/aarch64-apple-darwin23.5-clang++" || "$sdk_version" != 14.5 ]]; then
    (cd "$cross_source" && UNATTENDED=1 BUILD_FLAVOR=llvm ENABLE_REPLACEMENT_LIPO=0 \
      ENABLE_ARCHS="x86_64 arm64" TARGET_DIR="$OSXCROSS_ROOT" OSX_VERSION_MIN="$OSX_MIN_VERSION" ./build.sh)
fi
git -C "$cross_source" rev-parse HEAD > "$MAC_WORKDIR/results/osxcross-commit.txt"
"$OSXCROSS_ROOT/bin/osxcross-conf" > "$MAC_WORKDIR/results/toolchain.txt"
