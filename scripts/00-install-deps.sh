#!/usr/bin/env bash

OS=${1}

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
    ninja-build \
    osslsigncode \
    nsis \
    pkg-config \
    python3 \
    rename \
    zip \
    bison \
    unzip \
    wget

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
    sleuthkit \
    bison \
    unzip \
    wget

elif [[ ${OS} == "linux" || ${OS} == "linux-disable-wallet" || ${OS} == "aarch64" || ${OS} == "aarch64-disable-wallet" ]]; then
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
    cmake \
    curl \
    g++-aarch64-linux-gnu \
    g++-12-aarch64-linux-gnu \
    g++-12-multilib \
    gcc-12-aarch64-linux-gnu \
    gcc-12-multilib \
    git \
    gnupg \
    libxcb-cursor0 \
    libssl-dev \
    libtool \
    ninja-build \
    nsis \
    pbuilder \
    pkg-config \
    python3 \
    rename \
    ubuntu-dev-tools \
    xkb-data \
    zip \
    bison \
    unzip \
    wget

elif [[ ${OS} == "arm32v7" || ${OS} == "arm32v7-disable-wallet" ]]; then
    apt -y install \
    autoconf \
    automake \
    binutils-aarch64-linux-gnu \
    binutils-arm-linux-gnueabihf \
    binutils \
    bsdmainutils \
    ca-certificates \
    cmake \
    curl \
    g++-aarch64-linux-gnu \
    g++-12-aarch64-linux-gnu \
    gcc-12-aarch64-linux-gnu \
    g++-arm-linux-gnueabihf \
    g++-12-arm-linux-gnueabihf \
    gcc-12-arm-linux-gnueabihf \
    g++-12-multilib \
    gcc-12-multilib \
    git \
    libssl-dev \
    libtool \
    ninja-build \
    pkg-config \
    python3 \
    bison \
    unzip \
    wget
else
    echo "you must pass the OS to build for"
    exit 1
fi
    update-alternatives --install /usr/bin/python python /usr/bin/python3 1
