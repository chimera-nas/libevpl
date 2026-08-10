# SPDX-FileCopyrightText: 2025 Ben Jarvis
#
# SPDX-License-Identifier: Unlicense

FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive

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
    npm install -g @anthropic-ai/claude-code && \
    # Quint drives the RPC2 conformance test: cmake detects it and generates
    # that test's cases from the models at build time, so the version is pinned
    # -- trace generation is seeded and reproducible for a given release, but
    # different releases may sample the state space differently.
    npm install -g @informalsystems/quint@0.32.0

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8
