---
title: Architecture
layout: default
nav_order: 3
permalink: /architecture
---

# Architecture & Concepts

This guide explores libevpl's architecture in depth, explaining the design principles and programming model that enable high-performance I/O across diverse hardware backends.

### The Event-Driven Model

In event-driven programming, application logic is structured as a collection of callback functions that execute in response to events:

- A new network connection arrives
- Data becomes available to read from a socket
- A write operation completes
- A timer expires
- Another thread signals work to be done

Rather than blocking threads waiting for I/O operations to complete, applications register callbacks with an event loop. The event loop monitors multiple I/O sources simultaneously and invokes the appropriate callbacks as events occur. This allows a single thread to efficiently handle thousands of concurrent connections without the memory overhead and context switching costs of thread-per-connection models.

### The Event Loop

The core of libevpl is the event loop (`struct evpl`), which manages all asynchronous operations within a single thread. Each thread that performs I/O operations runs its own independent event loop. Within that event loop, the application:

1. Initiates asynchronous operations (connect, send, receive, timer creation)
2. Registers callbacks to be invoked when those operations complete
3. Runs the event loop, which repeatedly checks for completed events and invokes callbacks
4. All application logic executes within these callbacks

This model eliminates the need for locking when accessing per-connection state, since all operations on a given connection happen sequentially within a single thread's event loop. Applications can maintain complex state machines without worrying about concurrent access from multiple threads.

For API details on event loop creation and management, see the [Core API](/api/core) documentation.

## Hybrid Event and Poll Modes

A fundamental challenge in high-performance I/O is choosing between two competing approaches for detecting event completion: system call-based event notification and busy polling.

### System Call Event Notification

Traditional event-driven programming uses system calls like `epoll_wait()` (Linux) or `kqueue()` (BSD/macOS) to detect I/O readiness. The application:

1. Registers interest in specific file descriptors and events
2. Calls the wait system call, which blocks the thread
3. The kernel puts the thread to sleep until one or more registered events occur
4. The kernel wakes the thread and returns information about which events are ready
5. The application processes those events and calls the wait system call again

This approach is energy efficient—sleeping threads consume minimal CPU resources. It scales well to thousands of connections since the kernel efficiently monitors them all. However, it has significant costs:

- **Context Switching**: Every wakeup requires a context switch from kernel to userspace
- **Latency**: The thread must be scheduled, which may take microseconds or more
- **System Call Overhead**: Each wait call crosses the kernel boundary, adding overhead
- **Batch Processing**: Events accumulate while the thread sleeps, requiring the kernel to wake the thread and transfer event information

For applications processing millions of requests per second, these costs become substantial.

### Poll Mode

Poll mode takes the opposite approach: instead of sleeping, the thread continuously checks hardware completion queues in a tight loop. For example, with RDMA:

1. The application posts a receive work request to the NIC
2. Instead of sleeping, it continuously reads a memory location that the NIC updates via DMA
3. When the NIC completes the operation, it writes to that memory location (and possibly rings a PCIe doorbell)
4. The application immediately sees the completion and processes it

No system calls are involved. No context switches occur. The application sees completions within nanoseconds of the hardware completing them. However:

- **CPU Consumption**: The thread consumes 100% of a CPU core even when idle
- **Energy Inefficiency**: Spinning threads consume significant power
- **Scalability Limits**: Each polling thread ties up a CPU core

### libevpl's Hybrid Approach

libevpl automatically combines both strategies, transitioning between them based on load. The name "libevpl" itself reflects this duality—a contraction of "event" and "poll."

When the system is lightly loaded:
- The event loop uses system call-based waiting (`epoll_wait`, `kqueue`)
- Threads sleep when no work is available, conserving CPU and energy
- Latency increases slightly but is acceptable for the load level

When the system becomes heavily loaded:
- The event loop detects that work is consistently available
- It switches to poll mode, continuously checking completion queues
- Latency drops to near-hardware levels
- CPU usage increases but is justified by the workload

The transition is automatic and transparent to the application. Configuration options control the threshold for switching modes (see [Configuration API](/api/config)).

This hybrid approach provides the best of both worlds: energy-efficient operation under light load and maximum performance under heavy load.

## Memory Registration and Zero-Copy I/O

High-performance I/O backends like RDMA and VFIO require memory registration—a process that enables hardware devices to directly access application memory without kernel involvement. Understanding this concept is crucial for efficient libevpl usage.

### Why Memory Registration Exists

Traditional kernel-based I/O involves copying data between userspace buffers and kernel buffers. When you call `send()` on a socket, the kernel copies your data into a kernel buffer, then the network hardware copies it from there. This double-copy wastes CPU cycles and memory bandwidth.

Kernel bypass technologies like RDMA eliminate these copies by allowing network hardware to directly read and write application memory. However, this creates a problem: how does the hardware safely access virtual memory that might be paged out, moved, or deallocated?

Memory registration solves this by:

1. **Pinning Pages**: Ensuring the memory cannot be swapped to disk or relocated
2. **Creating DMA Mappings**: Translating virtual addresses to physical addresses for the hardware
3. **Tracking Permissions**: Recording which memory regions are accessible for DMA operations
4. **IOMMU Programming**: Configuring the I/O memory management unit (when present) to allow device access

### The Cost of Memory Registration

Memory registration is expensive. It requires:

- Page table walks to find physical pages
- IOMMU programming to establish DMA mappings
- Kernel data structure updates to track pinned memory
- Synchronization to ensure consistency

A typical memory registration operation might take **hundreds of microseconds**—far longer than the actual I/O operation at 400Gbps speeds. Registering memory on every I/O operation would destroy performance.

### Pooled Memory Registration

libevpl addresses this by maintaining pools of pre-registered memory. Instead of registering memory for each I/O operation:

1. At initialization, libevpl allocates and registers large buffers
2. Applications request chunks of this pre-registered memory for I/O operations
3. After I/O completes, buffers are returned to the pool for reuse
4. The memory remains registered throughout the application's lifetime

This amortizes the registration cost across many I/O operations. The expensive registration happens once during initialization; individual I/O operations simply use already-registered memory.

See the [Memory Management API](/api/memory) for details on buffer allocation and management.

### Zero-Copy I/O

Pre-registered memory enables zero-copy I/O: data moves directly between application buffers and the network hardware without intermediate copies. When sending data:

1. The application allocates a buffer from libevpl's pre-registered pool
2. It fills the buffer with data to send
3. It submits the buffer to libevpl for transmission
4. The RDMA hardware or other acceleration engine reads directly from this buffer via DMA
5. When transmission completes, the buffer is returned to the pool

Similarly, when receiving data:

1. The application pre-posts buffers from the registered pool as receive buffers
2. The hardware writes incoming data directly into these buffers via DMA
3. When data arrives, libevpl invokes the application's callback with the buffer
4. The application processes the data in place
5. When done, it returns the buffer to the pool

No copies occur between the hardware and the application. This is zero-copy I/O.

libevpl's use of iovecs (scatter-gather arrays) further optimizes this. A single I/O operation can reference multiple non-contiguous buffers, allowing applications to avoid copying data into a single contiguous buffer for transmission.

### Memory Registration with Kernel Sockets

For backends that don't require registration (traditional kernel sockets), libevpl still uses the same buffer pool mechanism for consistency. The registration step is skipped, but the pooling still provides benefits:

- Reduced allocation overhead through reuse
- Consistent API across all backends
- Cache-friendly access patterns

This allows applications to use the same buffer management code regardless of which protocol backend is active.

## Protocol Backends

libevpl provides a protocol-agnostic API that works across multiple backends. At connection establishment time, the application specifies the protocol to be used.  While the application chooses the protocol, however, the actual logic in the application typically does not need per-protocol modifications.

Currently supported backends include:

- **Kernel Sockets**: TCP and UDP via standard BSD sockets API
- **io_uring**: For both block I/O and kernel sockets
- **NVIDIA XLIO**: TCP acceleration for Mellanox NICs (userspace TCP/IP stack)
- **RDMA CM**: Reliable Connection and Unreliable Datagram queue pairs over RoCE v2

Other acceleration frameworks will be added over time.

See [Bind API](/api/binds) for protocol querying and selection mechanisms.

## Connection Management and Steering

In multi-threaded servers, efficiently distributing incoming connections across threads is crucial for load balancing and NUMA awareness.

### Listeners and Thread Attachment

libevpl takes an explicit approach to connection steering through the listener attachment model:

1. A listener (`struct evpl_listener`) is created to accept incoming connections on a given address and port
2. Individual worker threads explicitly attach to the listener
3. When a new connection arrives, libevpl selects one of the attached threads
4. The new connection is accepted directly in that thread's event loop
5. All subsequent I/O for that connection happens in the same thread

This model provides several advantages:

**Control Over Placement**: In principle, applications can choose which threads attach to which listeners, enabling NUMA-aware designs where threads on a particular NUMA node accept connections that will access memory on that node.

**Load Balancing**: libevpl can distribute connections across threads based on current load (currently round-robin, with more sophisticated algorithms planned).

**Flexibility**: Different listeners can have different attachment policies. A server might have some listeners attached to all threads and others attached to specialized threads.

**No Socket Sharing**: Unlike SO_REUSEPORT, libevpl doesn't rely on kernel-level load balancing. The library has full visibility into which threads are busy and can make smarter steering decisions.  It also allows load balancing with backend SDKs that do not support SO_REUSEPORT or equivalent.

This is particularly important for RDMA connections, where the hardware resources (queue pairs) are naturally in proximity with specific CPU cores and memory domains.

See [Bind API](/api/binds) for listener management details.

## Embedding Application Logic in the Event Loop

Beyond basic I/O, libevpl provides several mechanisms for embedding application logic into the event-driven context.

### Timers

Timers allow application code to execute at periodic intervals. Common uses include:

- Connection keepalives
- Timeout detection
- Periodic statistics gathering
- Background maintenance tasks

All timers in libevpl are periodic—they automatically reschedule after firing. For one-shot behavior, the timer callback removes itself. Timers are managed by the event loop and fire with microsecond precision (actual precision depends on the system timer resolution and event loop load).

See [Timers API](/api/timers) for timer management functions.

### Deferrals

Deferrals schedule work to run at the end of the current event loop iteration. They are useful for:

- **Breaking Up Long Operations**: A callback doing expensive computation can split the work across multiple deferrals to avoid blocking other events
- **Flush Operations**: Batching multiple sends and flushing them in a deferral amortizes per-operation costs
- **Avoiding Deep Recursion**: A callback that might trigger more events can use a deferral to avoid deeply nested callback chains
- **Ordering Guarantees**: Ensuring certain logic runs after all current events are processed

Deferrals execute in the same thread that schedules them, so they don't require synchronization for accessing thread-local state.

See [Deferrals API](/api/deferrals) for deferral scheduling functions.

### Doorbells

Doorbells provide thread-safe communication between event loops running in different threads. They are essentially eventfd-based or pipe-based notifications that allow one thread to signal another that work is available:

1. Thread A needs Thread B to perform some work
2. Thread A queues the work item in a thread-safe queue
3. Thread A rings Thread B's doorbell
4. Thread B's event loop detects the doorbell ring
5. Thread B's doorbell callback dequeues and processes the work

Doorbells integrate into the event loop just like any other I/O event. If the receiving thread is sleeping in `epoll_wait()`, the doorbell wakes it. If the thread is polling, it sees the doorbell notification immediately.

Common uses include:

- Distributing work from a manager thread to worker threads
- Coordinating shutdown across thread pools
- Offloading expensive operations to dedicated threads
- Implementing cross-thread RPC mechanisms

Unlike deferrals, doorbells are thread-safe and can signal across threads. However, they have higher overhead due to the synchronization requirements.

See [Doorbells API](/api/doorbells) for doorbell management functions.

## Block I/O Integration

libevpl integrates block device I/O into the same event loop that handles network I/O, enabling applications that need both (like storage servers) to manage everything in one place.

Block I/O operations use the same event-driven model:

1. Submit read or write requests asynchronously
2. Continue processing network events
3. When the block operation completes, a callback is invoked
4. Process the results and continue

Backends include io_uring (for kernel-mediated async I/O) and VFIO-NVMe (for direct userspace NVMe access with even lower latency).

Like network I/O, block I/O uses pre-registered memory buffers from the same pools, enabling zero-copy operation where supported.

See [Block I/O API](/api/block) for block device operations.

## Threading Model

libevpl follows a strict single-threaded event loop model:

- Each thread that performs I/O runs exactly one event loop
- All operations on connections, timers, and other objects managed by that event loop must occur within that thread
- Multiple threads can run independent event loops
- Communication between threads happens via doorbells or other thread-safe mechanisms

This model eliminates the need for fine-grained locking within the event loop. Each event loop has exclusive access to its own state, allowing for lock-free operation within a single thread. Applications scale by running multiple threads, each with its own event loop, rather than by sharing a single event loop across threads.

For multi-threaded applications, libevpl provides thread pools where each thread runs an independent event loop. See [Threading API](/api/threading) for thread pool management.

## Configuration

libevpl's behavior is controlled through configuration settings at two levels:

**Global Configuration** - Set once before creating any event loops:
- Memory pool sizes and buffer allocation parameters
- Protocol-specific settings (RDMA parameters, TLS options)
- Polling behavior (spin time before sleeping, busy poll thresholds)

**Per-Event-Loop Configuration** - Applied when creating each event loop:
- Affinity settings (CPU pinning)
- Priority settings
- Event loop-specific parameters

See [Configuration API](/api/config) for all available settings.

## Design Principles Summary

libevpl's architecture embodies several key principles:

1. **Asynchronous Only**: All operations are non-blocking; completion is signaled via callbacks
2. **Protocol Agnostic**: A unified API works across diverse backends
3. **Zero-Copy Optimized**: Pre-registered memory pools enable direct hardware access
4. **Hybrid Event/Polling**: Automatic transitions based on load balance energy and performance
5. **Single-Threaded Event Loops**: Eliminates locking overhead within each thread
6. **Explicit Thread Attachment**: Applications control connection steering for NUMA awareness

These principles combine to enable portable, high-performance applications that leverage diverse acceleration technologies without exposing their complexity.

## Next Steps

Now that you understand libevpl's architecture:

- Explore the [API Reference](/api) for detailed function documentation
- Review [Getting Started](/getting_started) for a practical introduction
- Study the [Examples](/examples) to see these concepts in action
