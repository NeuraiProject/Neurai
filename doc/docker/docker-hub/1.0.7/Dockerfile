# Build the official Neurai 1.0.7 release for publication on Docker Hub as
# neuraiproject/neurai-node:v1.0.7. Build context: this directory.

FROM debian:11 AS build

ARG DEBIAN_FRONTEND=noninteractive
ARG NEURAI_REPOSITORY=https://github.com/NeuraiProject/Neurai.git
ARG NEURAI_REF=1.0.7
ARG BUILD_JOBS=2

# Debian 11 packages are served by the official archive. APT still verifies
# repository signatures and package checksums.
RUN printf '%s\n' \
    'deb http://archive.debian.org/debian bullseye main' \
    'deb http://archive.debian.org/debian bullseye-updates main' \
    'deb http://archive.debian.org/debian-security bullseye-security main' \
    > /etc/apt/sources.list

# Native Linux dependencies; the release's general install script also requests
# obsolete cross-compilers and Python 2 packages that are not needed here.
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake bison bsdextrautils build-essential bzip2 ca-certificates \
    cmake curl git libtool patch pkg-config python3 unzip wget xz-utils \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
RUN git clone --depth 1 --branch "${NEURAI_REF}" "${NEURAI_REPOSITORY}" Neurai

WORKDIR /root/Neurai/depends
RUN make HOST=x86_64-pc-linux-gnu NO_QT=1 -j"${BUILD_JOBS}"

WORKDIR /root/Neurai
RUN ./autogen.sh
RUN CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure \
    --prefix=$PWD/depends/x86_64-pc-linux-gnu \
    --enable-cxx --disable-shared --disable-tests --disable-bench --with-gui=no --with-pic
RUN make -j"${BUILD_JOBS}"

# Debug symbols are not useful inside the published image and dominate its size.
RUN strip src/neuraid src/neurai-cli

FROM debian:11-slim

ARG DEBIAN_FRONTEND=noninteractive

LABEL maintainer="NeuraiProject"
LABEL description="Neurai Linux node built from the official repository"
LABEL org.opencontainers.image.title="Neurai node"
LABEL org.opencontainers.image.version="1.0.7"
LABEL org.opencontainers.image.source="https://github.com/NeuraiProject/Neurai"

# Debian 11 packages are served by the official archive. APT still verifies
# repository signatures and package checksums.
RUN printf '%s\n' \
    'deb http://archive.debian.org/debian bullseye main' \
    'deb http://archive.debian.org/debian bullseye-updates main' \
    'deb http://archive.debian.org/debian-security bullseye-security main' \
    > /etc/apt/sources.list

# Match the UID/GID of v1.0.6 so existing /data volumes keep their permissions.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 999 neurai \
    && useradd --system --uid 999 --gid neurai --home-dir /data --no-create-home neurai \
    && mkdir /data \
    && chown neurai:neurai /data

COPY --from=build /root/Neurai/src/neuraid /usr/local/bin/neuraid
COPY --from=build /root/Neurai/src/neurai-cli /usr/local/bin/neurai-cli
COPY docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

RUN chmod 0755 /usr/local/bin/docker-entrypoint.sh

# 19000: P2P. 19001: JSON-RPC/REST; do not publish it without access controls.
EXPOSE 19000 19001
VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
CMD ["-printtoconsole"]
