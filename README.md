# libevpl

## Purpose

libevpl is a network library inspired by libraries like libevent and libev.
It intends to maintain a consistent, easy to use front end API while having
some additional capabilities.

* Support for both event-based and poll-based operatioon.  evpl is
  a contraction of event and poll.  In an event based mode, libevpl uses file
  descriptors and kernel provided mechanisms like linux epoll to sleep and wait
  foe traffic to be available.  In polling mode, the process can simply spin for
  awhile waiting for traffic without blocking or involving the kernel.  Support
  for polling mode is important for transports like RDMA verbs which can be
  implemented with complete kernel bypass.
* A pluggable framework backend so that transport protocols that are not socket
  based may be used, such as RDMA, DPDK, etc.
* A pluggable layered front end API suite to allow utilization of the backends
  as streaming channels, message passing channels, RPC, message brokers, etc.

## Status

libevpl is in early development and is not stable/usable yet
