FROM ubuntu:24.04

ARG USERNAME
ARG USER_UID=1000
ARG USER_GID=$USER_UID

RUN apt-get -y update && \
    apt-get -y --no-install-recommends upgrade && \
    apt-get -y --no-install-recommends install unminimize && \
    echo y | unminimize && \
    apt-get -y --no-install-recommends install clang cmake ninja-build git lldb gdb less psmisc uncrustify \
    net-tools tshark tcpdump uuid-dev iproute2 man-db manpages-dev ca-certificates ssh libjansson-dev libclang-rt-18-dev llvm \
    libxxhash-dev librdmacm-dev liburing-dev libunwind-dev flex bison libcurl4-openssl-dev && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*
