#!/usr/bin/env bash
# A package that fails to install fails the step.
set -euo pipefail
# Never stop at a debconf question (pbuilder asks for a mirror): with no
# terminal it repeats the prompt until the job times out. Set here because
# sudo drops the caller's environment.
export DEBIAN_FRONTEND=noninteractive

OS=${1:-}

if [[ ! ${OS} ]]; then
    echo "Error: Invalid options"
    echo "Usage: ${0} <operating system>"
    exit 1
fi

echo "----------------------------------------"
echo "Installing Build Packages for ${OS}"
echo "----------------------------------------"

apt-get update

if [[ ${OS} == "windows" ]]; then
    # depends builds liboqs and Qt with cmake, Qt through ninja.
    apt-get install -y \
    automake \
    autotools-dev \
    bsdmainutils \
    build-essential \
    cmake \
    curl \
    mingw-w64 \
    mingw-w64-x86-64-dev \
    git \
    libcurl4-openssl-dev \
    libssl-dev \
    libtool \
    osslsigncode \
    nsis \
    ninja-build \
    pkg-config \
    python3 \
    rename \
    zip \
    bison

    update-alternatives --set x86_64-w64-mingw32-g++ /usr/bin/x86_64-w64-mingw32-g++-posix 


elif [[ ${OS} == "osx" ]]; then
    apt -y install \
    autoconf \
    automake \
    awscli \
    bsdmainutils \
    ca-certificates \
    cmake \
    curl \
    fonts-tuffy \
    g++ \
    git \
    imagemagick \
    libbz2-dev \
    libcap-dev \
    librsvg2-bin \
    libtiff-tools \
    libtool \
    libz-dev \
    p7zip-full \
    pkg-config \
    python3 \
    python3-dev \
    python3-setuptools \
    s3curl \
    sleuthkit \
    bison \
    libtinfo5 \
    python3-pip

    pip3 install ds-store
    
elif [[ ${OS} == "linux" || ${OS} == "linux-disable-wallet" ]]; then
    # x86-64 build on ubuntu-24.04. The aarch64 cross toolchain and the GCC 9
    # packages this list used to share with the aarch64 entries do not exist
    # on 24.04. depends builds liboqs and Qt with cmake, Qt through ninja, and
    # the Wayland and xkbcommon libraries Qt uses with meson.
    apt-get -y install \
    apt-file \
    autoconf \
    automake \
    autotools-dev \
    binutils \
    bsdmainutils \
    build-essential \
    ca-certificates \
    cmake \
    curl \
    git \
    gnupg \
    libtool \
    meson \
    ninja-build \
    nsis \
    pbuilder \
    pkg-config \
    python3 \
    rename \
    ubuntu-dev-tools \
    xkb-data \
    zip \
    bison

elif [[ ${OS} == "aarch64" || ${OS} == "aarch64-disable-wallet" ]]; then
    # Out of the CI matrix: configure refuses non-x86-64 hosts for the NIP-018
    # mcl backend. The GCC 9 packages below no longer exist on ubuntu-24.04;
    # update this list before enabling these entries again.
    apt -y install \
    apt-file \
    autoconf \
    automake \
    autotools-dev \
    binutils-aarch64-linux-gnu \
    binutils \
    bsdmainutils \
    build-essential \
    ca-certificates \
    curl \
    g++-aarch64-linux-gnu \
    g++-9-aarch64-linux-gnu \
    g++-9-multilib \
    gcc-9-aarch64-linux-gnu \
    gcc-9-multilib \
    git \
    gnupg \
    libtool \
    nsis \
    pbuilder \
    pkg-config \
    python3 \
    rename \
    ubuntu-dev-tools \
    xkb-data \
    zip \
    bison



elif [[ ${OS} == "arm32v7" || ${OS} == "arm32v7-disable-wallet" ]]; then
    apt -y install \
    autoconf \
    automake \
    binutils-aarch64-linux-gnu \
    binutils-arm-linux-gnueabihf \
    binutils \
    bsdmainutils \
    ca-certificates \
    curl \
    g++-aarch64-linux-gnu \
    g++-9-aarch64-linux-gnu \
    gcc-9-aarch64-linux-gnu \
    g++-arm-linux-gnueabihf \
    g++-9-arm-linux-gnueabihf \
    gcc-9-arm-linux-gnueabihf \
    g++-9-multilib \
    gcc-9-multilib \
    git \
    libtool \
    pkg-config \
    python3 \
    bison
else
    echo "you must pass the OS to build for"
    exit 1
fi
    # python2 is gone from ubuntu-24.04
    if [[ -x /usr/bin/python2 ]]; then
        update-alternatives --install /usr/bin/python python /usr/bin/python2 1
    fi
    update-alternatives --install /usr/bin/python python /usr/bin/python3 2
