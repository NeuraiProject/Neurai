RASPBERRY PI BUILD NOTES
====================

Native build of the daemon and command-line tools on Raspberry Pi OS (64-bit)
based on Debian 13 (trixie) or newer: the system Boost must be 1.81 or newer
(Debian 12 ships 1.74). The 32-bit system is not supported: `configure`
accepts only x86-64 and ARM64 for the NIP-018 `mcl` backend. Compiling takes
several hours on a Pi; cross-compiling with the depends system
(`make -C depends HOST=aarch64-linux-gnu`) on a PC is faster.

# Install necessary packages:
```
sudo apt-get update
sudo apt-get install git build-essential libtool autotools-dev automake cmake pkg-config bsdmainutils python3 libssl-dev
sudo apt-get install libevent-dev libboost-system-dev libboost-filesystem-dev libboost-test-dev libboost-thread-dev
sudo apt-get install libminiupnpc-dev libzmq3-dev
```

# Increase your swap size:
```
sudo nano /etc/dphys-swapfile
- In this file, change CONF_SWAPSIZE=100 to CONF_SWAPSIZE=2048
sudo reboot
```

# Build liboqs 0.16.0 (required)

The post-quantum signatures (ML-DSA-44) need liboqs 0.16.0; `configure` fails
without it. Build it as a static library:

```
git clone --branch 0.16.0 --depth 1 https://github.com/open-quantum-safe/liboqs.git
cmake -S liboqs -B liboqs/build -DCMAKE_BUILD_TYPE=Release -DBUILD_SHARED_LIBS=OFF \
      -DOQS_BUILD_ONLY_LIB=ON -DOQS_USE_OPENSSL=OFF -DOQS_DIST_BUILD=ON \
      -DCMAKE_INSTALL_PREFIX=/usr/local
cmake --build liboqs/build -j2
sudo cmake --install liboqs/build
```

If you install it elsewhere, pass `CPPFLAGS="-I<prefix>/include"` and
`LDFLAGS="-L<prefix>/lib"` to `configure`. The depends system builds liboqs
automatically.

# Build Berkeley DB 4.8 and Neurai
```
cd ~
git clone https://github.com/NeuraiProject/Neurai
cd Neurai/
./contrib/install_db4.sh `pwd`
export BDB_PREFIX="$(pwd)/db4"
./autogen.sh
./configure --disable-tests --with-gui=no \
    BDB_LIBS="-L${BDB_PREFIX}/lib -ldb_cxx-4.8" BDB_CFLAGS="-I${BDB_PREFIX}/include"
make
```

`contrib/install_db4.sh` downloads Berkeley DB 4.8.30, patches it for current
compilers and installs it under `db4/`. To build without a wallet, skip it and
pass `--disable-wallet` instead of the `BDB_*` variables.
