#!/usr/bin/env bash
# Shared by the local build command and the existing GitHub build stages.

mac_paths() {
    local source_root=$1
    MAC_WORKDIR=${MAC_WORKDIR:-"$source_root/MAC"}
    OSXCROSS_ROOT=${OSXCROSS_ROOT:-"$MAC_WORKDIR/toolchain"}
    MAC_WORKDIR=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).expanduser().resolve())' "$MAC_WORKDIR")
    OSXCROSS_ROOT=$(python3 -c 'from pathlib import Path; import sys; print(Path(sys.argv[1]).expanduser().resolve())' "$OSXCROSS_ROOT")
    OSX_MIN_VERSION=${OSX_MIN_VERSION:-12.0}
    JOBS=${JOBS:-2}
    [[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "JOBS must be a positive integer" >&2; return 1; }
    export MAC_WORKDIR OSXCROSS_ROOT OSX_MIN_VERSION JOBS
}

mac_environment() {
    mac_paths "$1"
    local conf target flavor
    if [[ ! -x "$OSXCROSS_ROOT/bin/osxcross-conf" ]]; then
        echo "OSXCross is missing: run contrib/mac-cross/setup.sh with MAC_WORKDIR=$MAC_WORKDIR" >&2
        return 1
    fi
    conf=$("$OSXCROSS_ROOT/bin/osxcross-conf")
    target=$(sed -n 's/^export OSXCROSS_TARGET="\([^"]*\)".*/\1/p' <<< "$conf")
    flavor=$(sed -n 's/^export OSXCROSS_BUILD_FLAVOR="\([^"]*\)".*/\1/p' <<< "$conf")
    [[ "$target" == darwin* ]] || { echo "Cannot read the OSXCross target" >&2; return 1; }
    MAC_HOST=${MAC_HOST:-"x86_64-apple-$target"}
    [[ "$MAC_HOST" == x86_64-apple-darwin* ]] || { echo "The current NIP-018 backend requires x86-64" >&2; return 1; }
    [[ -x "$OSXCROSS_ROOT/bin/$MAC_HOST-clang++" ]] || { echo "Compiler missing for $MAC_HOST" >&2; return 1; }
    OSX_SDK=${OSX_SDK:-$("$OSXCROSS_ROOT/bin/xcrun" --sdk macosx --show-sdk-path)}
    OSX_SDK_VERSION=$("$OSXCROSS_ROOT/bin/xcrun" --sdk "$OSX_SDK" --show-sdk-version)
    MAC_DEPENDS_PREFIX=${MAC_DEPENDS_PREFIX:-"$MAC_WORKDIR/dependencies/$MAC_HOST"}
    SOURCES_PATH=${SOURCES_PATH:-"$MAC_WORKDIR/downloads/depends"}
    BASE_CACHE=${BASE_CACHE:-"$MAC_WORKDIR/cache/depends"}
    MAC_CONSENSUS_LIBS=${MAC_CONSENSUS_LIBS:-yes}
    # ld64.lld does not support the relocatable -r link used by libtool.
    if [[ "$flavor" == llvm ]]; then MAC_CONSENSUS_LIBS=no; fi
    export PATH="$OSXCROSS_ROOT/bin:$PATH"
    export MACOSX_DEPLOYMENT_TARGET="$OSX_MIN_VERSION"
    export MAC_HOST OSX_SDK OSX_SDK_VERSION MAC_DEPENDS_PREFIX MAC_CONSENSUS_LIBS
    export SOURCES_PATH BASE_CACHE
}
