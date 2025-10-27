---
title: Architecture
layout: default
nav_order: 4
permalink: /architecture
---

# Architecture & Concepts

This guide explains libevpl's core architecture, design principles, and key abstractions.

## Design Principles

### Protocol Agnostic API

libevpl provides a unified network and block I/O API that works across multiple backends (sockets, io_uring, XLIO, RDMA). Applications can switch between protocols without changing code, allowing you to leverage different acceleration stacks opportunistically without locking into specific hardware or writing redundant code paths.

### Asynchronous Only

All I/O operations are non-blocking and asynchronous. Completion is signaled via callbacks, allowing applications to handle large throughputs at low latency in a CPU-efficient manner.

### Zero-Copy Where Possible

libevpl minimizes memory copies through buffer management with reference counting and iovec-based scatter-gather I/O. Protocols that support zero-copy (RDMA, VFIO) can transfer data directly from application buffers. Memory registration for accelerated I/O APIs is handled automatically.

### Hybrid Event/Polling

The library automatically switches between event-driven (epoll/kqueue) and busy-polling modes based on load. Under light load, it sleeps waiting for events. Under heavy load, it polls for minimal latency.

## Core Abstractions

### Event Loop

The event loop (`struct evpl`) is the heart of libevpl. Each thread runs its own event loop that manages network connections, timers, deferred tasks, doorbells (inter-thread notifications), and block I/O operations.

**Key characteristics:**
- One event loop per thread
- Thread-safe communication via doorbells
- All application logic runs inside event callbacks

See [Core API](/api/core) for event loop management functions.

### Protocols

A protocol defines how data is transmitted. libevpl supports:

**Stream protocols** (connection-oriented, reliable):
- TCP via kernel sockets, io_uring, or NVIDIA XLIO
- RDMA Reliable Connected (RC)
- TLS over TCP (optionally kTLS)

**Reliable Datagram protocols:**
- RDMA RC can operate as reliable datagrams
- Other stream protocols can be used as reliable datagrams via application provided segment callback

**Unreliable Datagram protocols** (connectionless, unreliable):
- UDP via kernel sockets
- RDMA Unreliable Datagram (UD)

**Block protocols:**
- io_uring for kernel block I/O
- VFIO for direct userspace NVMe access

Protocol selection happens at connection time. See [Bind API](/api/binds) for protocol queries.

### Endpoints

An endpoint (`struct evpl_endpoint`) represents a network address and port. Endpoints support both numeric IP addresses and DNS hostnames, with automatic DNS resolution and caching.

Used for:
- Binding listeners to local addresses
- Specifying remote connection targets
- Receiving source addresses in datagrams

See [Endpoints API](/api/endpoints) for endpoint management.

### Binds

A bind (`struct evpl_bind`) represents a network connection or socket—the primary abstraction for network I/O operations.

**Types:**
- **Connected bind** - Bidirectional stream connection (e.g., TCP)
- **Datagram bind** - Unconnected datagram socket (e.g., UDP)

Binds are created via `evpl_connect()` for clients or accepted from listeners for servers.

See [Binds API](/api/binds) for I/O operations.

### Listeners

A listener (`struct evpl_listener`) accepts incoming connections. Multiple threads can attach to the same listener for automatic load distribution (currently round-robin, with NUMA-aware distribution planned).

See [Binds API](/api/binds) for listener management.

### Callbacks

libevpl uses two types of callbacks for network I/O:

**Notify callback** - Signals connection state changes and I/O completion:
- Connection established/closed
- Data received (stream or datagram)
- Send completed

**Segment callback** (optional) - Enables stream protocols to operate as reliable datagram protocols by identifying message boundaries in the stream. Not needed for true datagram protocols like RDMA RC.

See [Binds API](/api/binds) for callback details.

## Threading Model

### Single-Threaded Event Loops

Each event loop runs in a single thread, eliminating locking overhead and simplifying application logic.

### Thread Pools

For multi-threaded servers, use thread pools where each thread runs its own event loop. Listeners can be shared across threads for automatic connection distribution.

See [Threading API](/api/threading) for thread pool management.

### Inter-Thread Communication

**Doorbells** provide thread-safe signaling between event loops for work distribution, shutdown signaling, and cross-thread notifications. For same-thread deferred work, use **deferrals** instead.

See [Doorbells API](/api/doorbells) and [Deferrals API](/api/deferrals).

## Memory Management

libevpl uses a slab allocator for fixed-size buffers with reference counting and automatic registration for RDMA/VFIO. The iovec-based API enables zero-copy scatter-gather I/O where multiple iovecs can reference different parts of the same buffer.

See [Memory Management API](/api/memory) for buffer allocation.

## Timers and Deferrals

**Timers** schedule periodic callbacks at specified intervals. All timers are periodic and automatically reschedule after firing. For one-shot behavior, remove the timer in its callback.

**Deferrals** schedule work to run at the end of the current event loop iteration, useful for flush operations, breaking up long tasks, or avoiding deep recursion.

See [Timers API](/api/timers) and [Deferrals API](/api/deferrals).

## Configuration

Configuration happens at two levels:

**Global configuration** - Set once before creating event loops:
- Buffer sizes (default 2MB)
- Polling spin time (default 1ms)
- Protocol-specific parameters (RDMA, TLS, etc.)

**Thread-local configuration** - Per-event-loop settings applied at creation time.

See [Configuration API](/api/config) for all settings.

## Block I/O

libevpl supports high-performance asynchronous block device operations integrated with the event loop, allowing network and storage I/O to be handled together.

**Backends:**
- **io_uring** - Kernel-mediated async I/O for any block device
- **VFIO-NVMe** - Direct userspace NVMe access for ultra-low latency

See [Block I/O API](/api/block) for device operations.

## Module Architecture

libevpl is organized into modules:

- **Core** - Event loop, protocol abstraction, buffer management, network operations
- **Threading** - Thread creation, pools, and management
- **Block** - Block device abstraction, io_uring, VFIO-NVMe
- **HTTP** - HTTP/1.1 client and server
- **RPC2** - ONC RPC for NFS

See [API Reference](/api) for detailed module documentation.

## Next Steps

- Review the [API Reference](/api) for detailed function documentation
- Study the [Getting Started](/getting_started) guide for a practical introduction
- Explore the specific API sections for your use case
