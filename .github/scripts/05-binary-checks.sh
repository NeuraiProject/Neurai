#!/usr/bin/env bash
# Any failing command fails the step: without this, a failed `make check` was
# hidden whenever the command after it succeeded.
set -euo pipefail

OS=${1:-}
GITHUB_WORKSPACE=${2:-}

# "all" is too much log information. This will increase from verbosity from error"
#export BOOST_TEST_LOG_LEVEL=all

if [[ ${OS} == "windows" ]]; then
    echo "----------------------------------------"
    echo "Checking binary security for ${OS}"
    echo "----------------------------------------"
    make -C src check-security
    make -C src check-symbols
elif [[ ${OS} == "osx" ]]; then
    source "${GITHUB_WORKSPACE}/contrib/mac-cross/env.sh"
    mac_environment "$GITHUB_WORKSPACE"
    mkdir -p "$MAC_WORKDIR/results"
    binaries=(src/neuraid src/neurai-cli src/neurai-tx)
    if [[ -z "${NO_QT:-}" ]]; then binaries+=(src/qt/neurai-qt); fi
    if [[ "${MAC_BUILD_TESTS:-yes}" != no ]]; then
        binaries+=(src/test/test_neurai src/test/test_neurai_fuzzy src/test/test_neurai_hash)
    fi
    python3 "$GITHUB_WORKSPACE/contrib/mac-cross/verify.py" \
      --minimum "$OSX_MIN_VERSION" --sdk "$OSX_SDK_VERSION" \
      --depends "$MAC_DEPENDS_PREFIX" --ar "$OSXCROSS_ROOT/bin/$MAC_HOST-ar" \
      --output "$MAC_WORKDIR/results/$(basename "$PWD")-verification.json" "${binaries[@]}"
elif [[ ${OS} == "linux" || ${OS} == "linux-disable-wallet" ]]; then
    echo "----------------------------------------"
    echo "Checking binary security for ${OS}"
    echo "----------------------------------------"
    make -C src check-security
    echo "----------------------------------------"
    echo "Running unit tests for ${OS}"
    echo "----------------------------------------"
    # test_neurai plus the util, secp256k1 and univalue checks. VERBOSE=1
    # prints the log of whatever fails. (test_neurai used to run a second time
    # here as "functional tests": it is the same unit test binary.)
    make check VERBOSE=1
elif [[ ${OS} == "arm32v7" || ${OS} == "arm32v7-disable-wallet" || ${OS} == "aarch64" || ${OS} == "aarch64-disable-wallet" ]]; then
    echo "----------------------------------------"
    echo "No binary checks available for ${OS}"
    echo "----------------------------------------"
else
    echo "You must pass an OS."
    echo "Usage: ${0} <operating system> <github workspace path>"
    exit 1
fi

