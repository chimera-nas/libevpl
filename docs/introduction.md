---
title: Introduction
layout: default
nav_order: 1
permalink: /intro
---

# Introduction to libevpl

Many techniques have been developed to improve network performance beyond what can be achieved with the traditional kerne

## The Challenge: 400Gbps+ Network Performance

As network speeds reach 400Gbps and beyond, efficiently harnessing this performance in distributed systems and applications presents significant challenges.

Traditional socket-based networking models struggle to fully utilize available bandwidth. Userspace-kernel memory copies, page pinning, context switching, and interrupt handling contribute to increased latency and inefficient CPU usage. Achieving optimal performance often requires extensive, specific tuning, making predictable real-world performance difficult.

To address this, various hardware offload techniques and kernel bypass solutions offer higher performance. However, each alternative networking stack comes with its own APIs, semantics, and hardware limitations, complicating development and limiting portability.

**libevpl aims to simplify this by providing a unified, high-performance network library that leverages a variety of backend protocol implementations.**

## Events and Polling: A Hybrid Approach

There are two general strategies for handling asynchronous operation completion:

- **Event-driven**: The kernel is informed of the events we're interested in, and the process sleeps until the kernel wakes it upon event occurrence. This is scalable and simple but incurs additional latency and is CPU-inefficient in fully loaded scenarios where there are always completed events to process.

- **Polling**: The process continuously checks memory buffers for completed events, consuming CPU even when no work is done. However, it introduces lower latency than event-driven models and can be more CPU-efficient in fully loaded scenarios.

libevpl supports a hybrid approach, automatically switching between event-driven and polling as appropriate. The name "libevpl" is a contraction of "event" and "poll."

## Key Features

- **Unified API**: A core API similar to the familiar sockets model, providing protocol-agnostic abstractions
- **Asynchronous Operations**: All operations are non-blocking with callback-based completion notification
- **Multiple Protocol Backends**: Supports kernel sockets, NVIDIA XLIO, RDMA CM, and io_uring with automatic backend selection
- **Zero-Copy I/O**: Optimized memory buffer management with zero-copy support where available
- **Memory Registration**: Automatic tracking of memory registration for RDMA and VFIO
- **Hybrid Event/Polling**: Automatic switching between event-driven and polling modes for optimal performance
- **Block I/O Support**: High-performance block device operations via io_uring and VFIO-NVMe

## Protocol Support

Currently supported protocols:

- **Kernel Sockets**: TCP and UDP via standard Linux sockets
- **NVIDIA XLIO**: TCP acceleration for Mellanox NICs
- **RDMA CM**: Reliable Connection (RC) and Unreliable Datagram (UD) queue pairs (RoCE V2)

Potential future additions:

- io_uring for TCP/UDP
- DPDK
- libfabric
- VPP

## Modules

Current modules:

- **core**: Provides a protocol-agnostic API similar to sockets
- **thread**: Creates threads that run event loops
- **threadpool**: Manages pools of threads running event loops
- **block**: High-performance block device I/O via io_uring and VFIO-NVMe
- **http**: HTTP client/server support
- **rpc2**: Support for ONC RPC2 protocol for NFS

Planned future modules:

- **ZMTP**: Message broker support, wire-compatible with ZMQ
- **numa**: Assistance in building NUMA-aware thread pools within libevpl

## Use Cases

libevpl is designed for applications that require maximum network and storage performance:

- **High-Performance NAS**: Foundation for Chimera, a high-performance multi-protocol NAS stack
- **Distributed Storage Systems**: iSCSI, NVMe-oF, NFS servers requiring high throughput
- **High-Frequency Trading**: Low-latency market data feeds and order execution
- **Real-Time Data Processing**: Stream processing, analytics, and data pipelines
- **Scientific Computing**: MPI-like communication patterns in HPC environments
- **Database Systems**: High-speed replication and distributed query engines

## Project Status

libevpl is primarily being developed as the foundation for Chimera, a high-performance multi-protocol NAS stack. Work is focused on this goal.

At present, libevpl is **usable for experimental purposes but is not yet stable**. APIs may change as development continues.

## Getting Started

To begin using libevpl:

1. Review the [Building & Installation](/build) guide to compile the library
2. Read the [Architecture & Concepts](/architecture) guide to understand core abstractions
3. Explore the [API Documentation](/api) for detailed function reference
4. Check out the [Examples](/examples) section for code samples

## License

libevpl is licensed under LGPL-2.1-only, making it suitable for both open source and commercial applications.
