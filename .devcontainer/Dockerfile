FROM ubuntu:24.04

ADD Gemfile Gemfile
ADD Gemfile.lock Gemfile.lock

RUN apt-get -y update && \
    apt-get -y --no-install-recommends upgrade && \
    apt-get -y --no-install-recommends install unminimize && \
    echo y | unminimize && \
    apt-get -y --no-install-recommends install clang clang-tools cmake ninja-build git lldb gdb less psmisc uncrustify reuse \
    net-tools tshark tcpdump uuid-dev iproute2 man-db manpages-dev ca-certificates ssh libjansson-dev libclang-rt-18-dev llvm \
    libxxhash-dev librdmacm-dev liburing-dev libunwind-dev flex bison libcurl4-openssl-dev build-essential ruby-full && \
    gem install jekyll bundler && \
    bundler install
