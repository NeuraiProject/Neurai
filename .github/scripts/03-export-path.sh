#!/usr/bin/env bash
set -euo pipefail

OS=${1:-}
GITHUB_WORKSPACE=${2:-}

if [[ ! ${OS} || ! ${GITHUB_WORKSPACE} ]]; then
    echo "Error: Invalid options"
    echo "Usage: ${0} <operating system> <github workspace path>"
    exit 1
fi

# Puts the depends native tools first on the PATH of the steps that follow.
# An `export PATH=...` here ended with this script; on GitHub Actions only a
# line appended to $GITHUB_PATH reaches the next steps.
add_to_path() {
    if [[ -n "${GITHUB_PATH:-}" ]]; then
        echo "$1" >> "${GITHUB_PATH}"
    else
        echo "GITHUB_PATH is not set (not on GitHub Actions): add $1 to PATH yourself"
    fi
}

if [[ ${OS} == "windows" ]]; then
    add_to_path "${GITHUB_WORKSPACE}/depends/x86_64-w64-mingw32/native/bin"
elif [[ ${OS} == "osx" ]]; then
    source "${GITHUB_WORKSPACE}/contrib/mac-cross/env.sh"
    mac_environment "$GITHUB_WORKSPACE"
    add_to_path "$OSXCROSS_ROOT/bin"
    add_to_path "$MAC_DEPENDS_PREFIX/native/bin"
    add_to_path /usr/lib/llvm-18/bin
    if [[ -n "${GITHUB_ENV:-}" ]]; then
        for variable in MAC_WORKDIR MAC_ARCH OSXCROSS_ROOT MAC_HOST OSX_SDK OSX_SDK_VERSION OSX_MIN_VERSION MAC_DEPENDS_PREFIX MAC_CONSENSUS_LIBS; do
            printf '%s=%s\n' "$variable" "${!variable}" >> "$GITHUB_ENV"
        done
    fi
elif [[ ${OS} == "linux" || ${OS} == "linux-disable-wallet" ]]; then
    add_to_path "${GITHUB_WORKSPACE}/depends/x86_64-linux-gnu/native/bin"
elif [[ ${OS} == "arm32v7" || ${OS} == "arm32v7-disable-wallet" ]]; then
    add_to_path "${GITHUB_WORKSPACE}/depends/arm-linux-gnueabihf/native/bin"
elif [[ ${OS} == "aarch64" || ${OS} == "aarch64-disable-wallet" ]]; then
    add_to_path "${GITHUB_WORKSPACE}/depends/aarch64-linux-gnu/native/bin"
else
    echo "You must pass an OS."
    echo "Usage: ${0} <operating system> <github workspace path>"
    exit 1
fi
