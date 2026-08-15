# Build the official Neurai 1.0.6 release for publication on Docker Hub as
# neuraiproject/neurai-node:v1.0.6. Build context: this directory.

FROM debian:11 AS build

ARG DEBIAN_FRONTEND=noninteractive
ARG NEURAI_REPOSITORY=https://github.com/NeuraiProject/Neurai.git
ARG NEURAI_REF=1.0.6

RUN apt-get update && apt-get install -y --no-install-recommends git unzip wget ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /root
RUN git clone --depth 1 --branch "${NEURAI_REF}" "${NEURAI_REPOSITORY}" Neurai

WORKDIR /root/Neurai
RUN scripts/00-install-deps.sh linux

WORKDIR /root/Neurai/depends
RUN make HOST=x86_64-pc-linux-gnu NO_QT=1 -j2

WORKDIR /root/Neurai
RUN ./autogen.sh
RUN CONFIG_SITE=$PWD/depends/x86_64-pc-linux-gnu/share/config.site ./configure \
    --prefix=$PWD/depends/x86_64-pc-linux-gnu \
    --enable-cxx --disable-shared --disable-tests --disable-bench --with-gui=no --with-pic
RUN make -j2

# Debug symbols are not useful inside the published image and dominate its size.
RUN strip src/neuraid src/neurai-cli

FROM debian:11-slim

ARG DEBIAN_FRONTEND=noninteractive

LABEL maintainer="NeuraiProject"
LABEL description="Neurai Linux node built from the official repository"
LABEL org.opencontainers.image.title="Neurai node"
LABEL org.opencontainers.image.version="1.0.6"
LABEL org.opencontainers.image.source="https://github.com/NeuraiProject/Neurai"

RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates gosu \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system neurai \
    && useradd --system --gid neurai --home-dir /data --no-create-home neurai \
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
