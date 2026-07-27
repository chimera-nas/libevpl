# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: Unlicense

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

ADD Gemfile Gemfile
ADD Gemfile.lock Gemfile.lock

RUN apt-get -y update && \
    apt-get -y --no-install-recommends upgrade && \
    apt-get -y --no-install-recommends install unminimize apt-utils && \
    yes | unminimize && \
    apt-get -y --no-install-recommends install clang clang-tools cmake ninja-build git lldb gdb less psmisc uncrustify reuse \
    net-tools tshark tcpdump uuid-dev iproute2 man-db manpages-dev ca-certificates ssh libjansson-dev libclang-rt-18-dev llvm \
    libxxhash-dev librdmacm-dev liburing-dev libaio-dev libunwind-dev flex bison libcurl4-openssl-dev build-essential ruby-full npm \
    libssl-dev openssl clangd uthash-dev libnuma-dev && \
    gem install jekyll bundler && \
    bundler install && \
    npm install -g @anthropic-ai/claude-code

# SPDK, built from source with shared libraries so libevpl can link it via
# pkg-config (EVPL_CORE_MECH_SPDK guest mode + spdk_mem_register framework).
# nvme-cuse is disabled to avoid a libfuse3 dependency; tests run without
# hugepages via spdk_env_opts.no_huge.  The sed repoints the stale DPDK
# build-tree -L path in the generated .pc files at the install prefix, since
# the source tree is deleted after install.
ARG SPDK_VERSION=v25.09
RUN apt-get -y --no-install-recommends install \
        python3 python3-pip python3-pyelftools python3-setuptools \
        meson pkg-config nasm patchelf autoconf automake libtool help2man && \
    git clone --depth 1 --branch ${SPDK_VERSION} --recurse-submodules \
        --shallow-submodules https://github.com/spdk/spdk.git /tmp/spdk && \
    cd /tmp/spdk && \
    ./configure --prefix=/usr/local --with-shared \
        --disable-tests --disable-unit-tests --disable-examples \
        --disable-apps --without-nvme-cuse && \
    make -j$(nproc) && \
    make install && \
    sed -i "s|-L/tmp/spdk/dpdk/build/lib|-L/usr/local/lib|g" \
        /usr/local/lib/pkgconfig/*.pc && \
    ldconfig && \
    cd / && rm -rf /tmp/spdk

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
