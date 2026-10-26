WINDOWS BUILD NOTES
====================

Below are some notes on how to build Neurai for Windows.

Most developers use cross-compilation from Ubuntu to build executables for
Windows. Cross-compilation is also used to build the release binaries.

Neurai requires a C++20 compiler. The release builds use Ubuntu 24.04
(MinGW-w64 GCC 13, posix thread model); older distributions are not tested.

The most straightforward way to build on a Windows machine is the Windows
Subsystem for Linux (WSL 2). Install it from an administrator PowerShell with:

    wsl --install -d Ubuntu-24.04

then open the Ubuntu shell and follow the "Cross-compilation" section below.

Cross-compilation
-------------------

These steps can be performed on, for example, an Ubuntu VM. The depends system
will also work on other Linux distributions, however the commands for
installing the toolchain will be different.

First, install the general dependencies:

    sudo apt-get install build-essential libtool autotools-dev automake pkg-config bsdmainutils cmake ninja-build curl nsis python3

A host toolchain (`build-essential`) is necessary because some dependency
packages (such as `protobuf`) need to build host utilities that are used in the
build process. `cmake` is needed by the liboqs and Qt packages of the depends system, and
`ninja-build` by Qt.

See also: [dependencies.md](dependencies.md).

Run these two commands, selecting the 'posix' variant for both, so that
mingw-w64 provides C++ threads (`std::thread`, `std::mutex`):
```
sudo update-alternatives --config x86_64-w64-mingw32-g++
sudo update-alternatives --config x86_64-w64-mingw32-gcc
```

## Building for 64-bit Windows

To build executables for Windows 64-bit, install the following dependencies:

    sudo apt-get install g++-mingw-w64-x86-64 mingw-w64-x86-64-dev

Then build using:

    PATH=$(echo "$PATH" | sed -e 's/:\/mnt.*//g') # strip out problematic Windows %PATH% imported var
    cd depends
    make HOST=x86_64-w64-mingw32
    cd ..
    ./autogen.sh # not required when building from tarball
    CONFIG_SITE=$PWD/depends/x86_64-w64-mingw32/share/config.site ./configure --prefix=/
    make

## 32-bit Windows

32-bit Windows is not supported: Qt 6 has no 32-bit Windows build, and the
release binaries are 64-bit only.

## Depends system

For further documentation on the depends system see [README.md](../depends/README.md) in the depends directory.

Installation
-------------

After building using the Windows subsystem it can be useful to copy the compiled
executables to a directory on the windows drive in the same directory structure
as they appear in the release `.zip` archive. This can be done in the following
way. This will install to `c:\workspace\neurai`, for example:

    make install DESTDIR=/mnt/c/workspace/neurai
