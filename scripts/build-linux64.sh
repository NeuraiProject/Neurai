#!/bin/bash

set -e  # Exit on error

rm -f neurai.zip

# Create zip of source code
(
  cd ../.. && zip -rq neurai.zip Neurai
)

mv ../../neurai.zip ./

rm -f neurai-qt.exe neurai-qt
rm -f neuraid.exe neuraid
rm -f neurai-cli.exe neurai-cli

docker start neurai-linux64-temp

docker cp neurai.zip neurai-linux64-temp:/root/

# Clean depends completely to avoid cache corruption
docker exec neurai-linux64-temp sh -c "cd /root/Neurai/depends && rm -rf work built sources/0.15.0.tar.gz 2>/dev/null || true"

# Install build dependencies (including cmake for liboqs)
docker exec neurai-linux64-temp sh -c "apt update && apt install -y cmake ninja-build"

# Extract source
docker exec neurai-linux64-temp sh -c "cd /root/ && unzip -oq neurai.zip"

# Install Neurai dependencies
docker exec neurai-linux64-temp sh -c "cd /root/Neurai && scripts/00-install-deps.sh linux"

# Build depends (includes liboqs and Qt)
docker exec neurai-linux64-temp sh -c "cd /root/Neurai/depends && make HOST=x86_64-pc-linux-gnu -j8"

# Generate build system
docker exec neurai-linux64-temp sh -c "cd /root/Neurai && ./autogen.sh"

# Install BDB4.8 to /root/db4
docker exec neurai-linux64-temp sh -c "cd /root/Neurai && contrib/install_db4.sh /root"

# Configure with Qt enabled
docker exec neurai-linux64-temp sh -c '
  cd /root/Neurai && \
  BDB_PREFIX=/root/db4 \
  CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site \
  ./configure \
    --prefix=$PWD/depends/x86_64-pc-linux-gnu \
    --enable-cxx \
    --disable-shared \
    --disable-tests \
    --disable-bench \
    --with-pic \
    --with-gui=qt5 \
    LDFLAGS="-L/root/db4/lib/" \
    CPPFLAGS="-I/root/db4/include/"
'

# Build
docker exec neurai-linux64-temp sh -c "cd /root/Neurai && make -j8"

# Copy Linux binaries
echo "Extracting Linux binaries..."
docker cp neurai-linux64-temp:/root/Neurai/src/neuraid ./neuraid
docker cp neurai-linux64-temp:/root/Neurai/src/neurai-cli ./neurai-cli
docker cp neurai-linux64-temp:/root/Neurai/src/qt/neurai-qt ./neurai-qt

docker stop neurai-linux64-temp

echo "Build complete!"
ls -la neuraid neurai-cli neurai-qt
