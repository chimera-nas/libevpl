---
title: Home
layout: home
---

# libevpl Documentation

Welcome to the documentation for **libevpl**, a high-performance network and storage library designed for 400Gbps+ applications.

## What is libevpl?

libevpl is a unified, high-performance I/O library that provides:

- **Fast networking** - Support for kernel sockets, NVIDIA XLIO, and RDMA with 400Gbps+ capability
- **High-performance storage** - Asynchronous block I/O via io_uring and VFIO-NVMe
- **Protocol-agnostic API** - Write once, run on multiple backends
- **Hybrid event/polling** - Automatically switches between modes for optimal performance
- **Zero-copy I/O** - Minimize memory copies for maximum throughput

## Quick Links

### Getting Started
- **[Introduction](/intro)** - Learn what libevpl is and why to use it
- **[Building & Installation](/build)** - Get libevpl running on your system
- **[Getting Started Guide](/getting-started)** - Your first libevpl program
- **[Architecture & Concepts](/architecture)** - Understand core abstractions

### API Documentation
- **[API Reference](/api)** - Complete function reference
- **[Core API](/api/core)** - Event loops and initialization
- **[Binds & Connections](/api/binds)** - Network I/O operations
- **[Block I/O](/api/block)** - High-performance storage (io_uring, VFIO-NVMe)
- **[Memory Management](/api/memory)** - Zero-copy buffer management

### Advanced Topics
- **[Performance Benchmarks](/performance)** - See what libevpl can do
- **[Programming Guide](/programming_guide)** - Best practices (coming soon)
- **[Examples](/examples)** - Complete working code examples
- **[Protocol Backends](/protocols)** - Deep dive into backends (coming soon)

## Key Features

### Multiple Network Backends
- Kernel TCP/UDP sockets
- NVIDIA XLIO (Mellanox hardware acceleration)
- RDMA CM (Reliable Connection and Unreliable Datagram)
- Future: io_uring TCP, DPDK, libfabric

### High-Performance Storage
- io_uring for asynchronous block I/O
- VFIO-NVMe for ultra-low latency direct access
- Zero-copy scatter-gather I/O

### Event-Driven Architecture
- Single-threaded event loops per thread
- Timer and deferral support
- Thread-safe inter-thread communication (doorbells)
- Automatic hybrid event/polling mode

### Protocol Modules
- HTTP client and server
- ONC RPC2 for NFS
- Planned: ZMTP (ZeroMQ-compatible)

## Project Status

libevpl is currently under active development as the foundation for **Chimera**, a high-performance multi-protocol NAS stack.

**Current Status:** Experimental - APIs may change as development continues.

## License

libevpl is licensed under **LGPL-2.1-only**, making it suitable for both open source and commercial applications.

## Need Help?

- Browse the **[FAQ](/faq)** (coming soon)
- Check the **[API Reference](/api)** for detailed documentation
- Open an issue on GitHub for bugs or questions

---

*Ready to get started? Head over to the [Building & Installation](/build) guide!*
