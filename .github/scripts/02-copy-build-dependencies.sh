#!/usr/bin/env bash

OS=${1}
GITHUB_WORKSPACE=${2}
GITHUB_REF=${3:-}

if [[ ! ${OS} || ! ${GITHUB_WORKSPACE} ]]; then
    echo "Error: Invalid options"
    echo "Usage: ${0} <operating system> <github workspace path>"
    exit 1
fi
echo "----------------------------------------"
echo "OS: ${OS}"
echo "----------------------------------------"

if [[ ${OS} == "arm32v7-disable-wallet" || ${OS} == "linux-disable-wallet" || ${OS} == "aarch64-disable-wallet" ]]; then
    OS=`echo ${OS} | cut -d"-" -f1`
fi

echo "----------------------------------------"
echo "Building Dependencies for ${OS}"
echo "----------------------------------------"

cd "$GITHUB_WORKSPACE/depends"
if [[ ${OS} == "windows" ]]; then
    make HOST=x86_64-w64-mingw32 -j2
elif [[ ${OS} == "osx" ]]; then
    set -euo pipefail
    source "${GITHUB_WORKSPACE}/contrib/mac-cross/env.sh"
    mac_paths "$GITHUB_WORKSPACE"
    if [[ ! -x "$OSXCROSS_ROOT/bin/osxcross-conf" ]] || \
       { [[ "$MAC_ARCH" == arm64 ]] && ! compgen -G "$OSXCROSS_ROOT/bin/aarch64-apple-darwin*-clang++" >/dev/null; }; then
        "${GITHUB_WORKSPACE}/contrib/mac-cross/setup.sh"
    fi
    mac_environment "$GITHUB_WORKSPACE"
    make -j"$JOBS" HOST="$MAC_HOST" PREFIX="$MAC_DEPENDS_PREFIX" \
      OSXCROSS_ROOT="$OSXCROSS_ROOT" OSX_SDK="$OSX_SDK" \
      OSX_SDK_VERSION="$OSX_SDK_VERSION" OSX_MIN_VERSION="$OSX_MIN_VERSION" JOBS="$JOBS"
elif [[ ${OS} == "linux" || ${OS} == "linux-disable-wallet" ]]; then
    make HOST=x86_64-linux-gnu -j2
elif [[ ${OS} == "arm32v7" || ${OS} == "arm32v7-disable-wallet" ]]; then
    make HOST=arm-linux-gnueabihf -j2
elif [[ ${OS} == "aarch64" || ${OS} == "aarch64-disable-wallet" ]]; then
    make HOST=aarch64-linux-gnu -j2
fi
