# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: Unlicense

# Every ARG that a FROM interpolates has to be declared before the FIRST FROM.
# An ARG below one belongs to that stage instead, so a later FROM sees it empty
# -- which buildkit reports as `failed to parse stage name ":"`, several levels
# away from the line that is actually wrong.  Hence one block, all of them, up
# here, before anything else.
ARG DOCKER_MIRROR=""
ARG QUINT_REGISTRY=ghcr.io/chimera-nas/quint
ARG QUINT_VERSION=0.32.0
ARG CCACHE_REGISTRY=ghcr.io/chimera-nas/ccache
ARG CCACHE_VERSION=4.14

# The pinned quint toolchain, mirrored into GHCR by chimera's Mirror quint
# workflow, rather than an npm install here.  Same pin, but the image build no
# longer reaches the npm registry.
#
# Both trees are copied below: /opt/quint is node + quint, and /quint-home is
# the pre-warmed Rust evaluator.  quint downloads that evaluator on first
# simulate and ABORTS rather than falling back when the download fails, so
# shipping it in the image is what stops every conformance generation depending
# on a network fetch at test time -- the same reason the npm install this
# replaces was followed by a warm-up step.
FROM ${QUINT_REGISTRY}:${QUINT_VERSION} AS quint

# ccache, from the same mirror.  This image had none at all -- every other image
# here installs the distro package -- so the compiler cache the workflow
# configures had nothing to run.  Taking the pinned upstream binary rather than
# apt's also removes version skew across bases: ubuntu 22.04 and rocky 9 ship
# 4.6, old enough to differ from the rest in what it honours.
FROM ${CCACHE_REGISTRY}:${CCACHE_VERSION} AS ccache

FROM ${DOCKER_MIRROR}ubuntu:24.04
ARG APT_MIRROR=""
ARG UBUNTU_MIRROR=""

ENV DEBIAN_FRONTEND=noninteractive

# CI points these at an internal registry and apt mirror; both default empty so
# a plain "docker build" of this devcontainer still pulls from upstream.
# Two mirror mechanisms, both off by default, so a plain `docker build` reaches
# whatever the base image ships and nothing unexpected.
#
# APT_MIRROR=<url> replaces the sources list outright.  The public CI has no
# such mirror, but private forks do, and this is what they set.
#
# UBUNTU_MIRROR=azure instead swaps the archive hosts for Azure's, which is
# what the public CI passes: the GitHub-hosted runners are Azure VMs -- their
# own host apt is pointed there for the same reason -- and the public mirrors
# are periodically caught mid-sync, serving an index whose size disagrees with
# its Release file, which fails the whole image build.  A host swap rather than
# a rewritten sources list, so the suites, components and Signed-By the base
# image chose all survive; archive and security are amd64's two hosts, ports is
# arm64's, and each keeps its path under the Azure name.
#
# APT_MIRROR wins if both are set: a fork that has stood one up means it.
RUN if [ -n "$APT_MIRROR" ]; then \
    echo "deb $APT_MIRROR noble main universe" > /etc/apt/sources.list.d/local-mirror.list && \
    echo "deb $APT_MIRROR noble-updates main universe" >> /etc/apt/sources.list.d/local-mirror.list && \
    echo "deb $APT_MIRROR noble-security main universe" >> /etc/apt/sources.list.d/local-mirror.list && \
    rm -f /etc/apt/sources.list.d/ubuntu.sources; \
    elif [ "$UBUNTU_MIRROR" = azure ]; then \
        sed -i -e 's|//archive\.ubuntu\.com|//azure.archive.ubuntu.com|g' \
               -e 's|//security\.ubuntu\.com|//azure.archive.ubuntu.com|g' \
               -e 's|//ports\.ubuntu\.com|//azure.ports.ubuntu.com|g' \
            /etc/apt/sources.list.d/ubuntu.sources; \
    fi

ADD Gemfile Gemfile
ADD Gemfile.lock Gemfile.lock

# clang, llvm and libclang-rt-dev are all installed unversioned so they resolve
# to the same LLVM release from the base image.  They have to match: clang looks
# for its compiler-rt profile/sanitizer runtimes under a resource directory
# named for its own major version, so pinning one of them to a different
# release leaves the runtimes missing and any -fprofile-instr-generate or
# -fsanitize build fails to link.  (This previously pinned libclang-rt-18-dev
# while clang tracked the default, which broke `make coverage` once the base
# image moved past 18.)
RUN apt-get -y update && \
    apt-get -y --no-install-recommends upgrade && \
    apt-get -y --no-install-recommends install unminimize apt-utils && \
    yes | unminimize && \
    apt-get -y --no-install-recommends install clang clang-tools cmake ninja-build git lldb gdb less psmisc uncrustify reuse \
    net-tools tshark tcpdump uuid-dev iproute2 man-db manpages-dev ca-certificates ssh libjansson-dev libclang-rt-dev llvm \
    libxxhash-dev librdmacm-dev liburing-dev libaio-dev libunwind-dev flex bison libcurl4-openssl-dev build-essential ruby-full npm \
    libssl-dev openssl clangd uthash-dev libnuma-dev && \
    gem install jekyll bundler && \
    bundler install && \
    npm install -g @anthropic-ai/claude-code

# quint drives the Core/HTTP/RPC2 conformance tests: cmake detects it and
# generates their case tables from the models at build time.  Without it those
# suites, and the quint_model checks, silently disable themselves.
COPY --from=quint /opt/quint  /opt/quint
COPY --from=quint /quint-home /root/.quint
ENV PATH=/opt/quint/bin:$PATH

COPY --from=ccache /ccache /usr/local/bin/ccache

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
