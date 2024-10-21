# libevpl

## Introduction

As network speeds reach 400Gbps and beyond, efficiently harnessing this performance in distributed systems and applications presents significant challenges.

Traditional socket-based networking models struggle to fully utilize available bandwidth. Userspace-kernel memory copies, page pinning, context switching, and interrupt handling contribute to increased latency and inefficient CPU usage. Achieving optimal performance often requires extensive, specific tuning, making predictable real-world performance difficult.

To address this, various hardware offload techniques and kernel bypass solutions offer higher performance. However, each alternative networking stack comes with its own APIs, semantics, and hardware limitations, complicating development and limiting portability.

libevpl aims to simplify this by providing a unified, high-performance network library that leverages a variety of backend protocol implementations.

## Events and Polling

There are two general strategies for handling asynchronous operation completion:

- **Event-driven**: The kernel is informed of the events we're interested in, and the process sleeps until the kernel wakes it upon event occurrence. This is scalable and simple but incurs additional latency and is CPU-inefficient in fully loaded scenarios where there are always completed events to process.

- **Polling**: The process continuously checks memory buffers for completed events, consuming CPU even when no work is done. However, it introduces lower latency than event-driven models and can be more CPU-efficient in fully loaded scenarios.

libevpl supports a hybrid approach, automatically switching between event-driven and polling as appropriate. The name "libevpl" is a contraction of "event" and "poll."

## Features

libevpl offers the following features:

- A core API similar to the familiar sockets model
- Asynchronous, non-blocking operations only
- Memory buffer management and memory registration tracking
- Zero-copy with supported backends

## Protocol Support

Currently supported protocols:

- Kernel TCP and UDP sockets
- NVIDIA XLIO TCP sockets
- RDMA CM RC and UD queue pairs (RoCE V2)

Potential future additions:

- io_uring
- DPDK
- libfabric
- VPP

## Modules

Current modules:

- **core**: Provides a protocol-agnostic API similar to sockets
- **thread**: Creates threads that run event loops
- **threadpool**: Manages pools of threads running event loops

Planned future modules:

- **rpc2**: Support for ONC RPC2 protocol for NFS
- **http**: HTTP client/server support
- **ZMTP**: Message broker support, wire-compatible with ZMQ
- **numa**: Assistance in building NUMA-aware thread pools within libevpl

## Status

libevpl is primarily being developed as the foundation for Chimera, a high-performance multi-protocol NAS stack. Work is focused on this goal.

At present, libevpl is usable for experimental purposes but is not yet stable.

## Documentation

API documentation will be provided once the APIs stabilize. In the meantime, see `src/core/evpl.h` for a preview of the public API.
