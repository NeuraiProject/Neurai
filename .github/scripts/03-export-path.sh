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
    add_to_path "${GITHUB_WORKSPACE}/depends/x86_64-apple-darwin14/native/bin"
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
