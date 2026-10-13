FROM ubuntu:24.04@sha256:534baea6a22c03a63003dbc8dbe78fe34bc0d7e595d9a9dc9834884ff530eb55
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
    autoconf automake bash bison bsdextrautils build-essential ca-certificates \
    clang-18 cmake curl file flex gettext git libbz2-dev libclang-18-dev \
    libssl-dev libtool libxml2-dev lld-18 llvm-18 llvm-18-dev make ninja-build patch perl \
    pkg-config python3 unzip uuid-dev xz-utils zip zlib1g-dev \
    && rm -rf /var/lib/apt/lists/*
ENV LANG=C.UTF-8
ENV PATH=/usr/lib/llvm-18/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
WORKDIR /MAC
