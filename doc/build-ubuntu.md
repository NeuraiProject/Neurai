Build instructions for Neurai
=================================

This will install most of the dependencies from Ubuntu.
The ones we build are Berkeley DB 4.8 and liboqs 0.16.0.

Neurai needs a C++20 compiler (GCC 12 or newer), Boost 1.81 or newer and
Qt 6 for the GUI (see [dependencies.md](dependencies.md)), so these
instructions target Ubuntu 24.04 (Noble Numbat) or newer. Older releases are
not supported; on them, build with Docker instead (see
[build-docker.md](build-docker.md)).

Install dependencies
---------------------------
```
sudo apt install build-essential autoconf automake libtool pkg-config cmake git \
    python3 bsdmainutils libssl-dev \
    libevent-dev libboost-chrono-dev libboost-filesystem-dev \
    libboost-program-options-dev libboost-system-dev libboost-thread-dev \
    libboost-test-dev libminiupnpc-dev libzmq3-dev
```

For the GUI (optional):
```
sudo apt install qt6-base-dev qt6-tools-dev qt6-tools-dev-tools qt6-l10n-tools \
    libgl-dev libqrencode-dev libprotobuf-dev protobuf-compiler
```

Directory structure
------------------
Neurai sources in `$HOME/src`

Berkeley DB will be installed to `$HOME/src/db4`


Neurai
------------------

Start in $HOME

Make the directory for sources and go into it.

`mkdir src`

`cd src`

__Download Neurai source.__

`git clone https://github.com/NeuraiProject/Neurai`

`cd Neurai`

`git checkout <tag>` # the release tag you want to build, e.g. `2.0.0` (see `git tag`)

__Build liboqs 0.16.0 (required)__

The post-quantum signatures (ML-DSA-44) need liboqs 0.16.0; `configure` fails
without it. Build it as a static library:

```
git clone --branch 0.16.0 --depth 1 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
      -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON \
      -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build liboqs/build -j4
sudo cmake --install liboqs/build
```

If you install it elsewhere, pass `CPPFLAGS="-I<prefix>/include"` and
`LDFLAGS="-L<prefix>/lib"` to `configure`. The depends system builds liboqs
automatically.

__Download and build Berkeley DB 4.8__

`contrib/install_db4.sh ../`

__The build process:__

`./autogen.sh`

`export BDB_PREFIX=$HOME/src/db4`

`./configure BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" BDB_CFLAGS="-I${BDB_PREFIX}/include" --prefix=/usr/local` 

_Adjust to own needs. This will install the binaries to `/usr/local/bin`_


`make -j8`  # 8 for 8 build threads, adjust to fit your setup.

You can now start neurai-qt from the build directory.

`src/qt/neurai-qt`

neuraid and neurai-cli are in `src/`


__Optional:__

`sudo make install`  # if you want to install the binaries to /usr/local/bin (if this prefix was used above).


__Only Daemon:__

`mkdir src`

`cd src`

`git clone https://github.com/NeuraiProject/Neurai`

`cd Neurai`

Build liboqs as described above, then:

`contrib/install_db4.sh ../`

`./autogen.sh`

`export BDB_PREFIX=$HOME/src/db4`

`./configure BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" BDB_CFLAGS="-I${BDB_PREFIX}/include" --prefix=/usr/local --disable-tests --disable-bench --with-gui=no --with-miniupnpc=no`

`make -j4`

`sudo make install`