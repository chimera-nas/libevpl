---
title: Introduction
layout: home
nav_order: 1
---

# Introduction to libevpl

## The Challenge: Harnessing Modern High-Speed I/O

Modern data centers are equipped with remarkably capable hardware: PCIe network adapters delivering 400Gbps and beyond, NVMe storage devices capable of millions of IOPS, and multi-core CPUs ready to handle massive workloads. Yet efficiently harnessing this performance in real-world applications remains surprisingly difficult.

Traditional kernel-based I/O models, designed when network speeds were measured in megabits and storage in thousands of operations per second, struggle to keep pace. Context switches, system call overhead, and memory copies consume precious CPU cycles.  The challenge today is not making optimal use of scarce network and storage resources.  The challenge today is to be capable of fully utilizing the abundance that the hardware provides.

## The Current Landscape: Power and Complexity

To address these limitations, the industry has developed numerous high-performance I/O frameworks and hardware acceleration technologies:

- **libibverbs** provides direct access to RDMA-capable network hardware, enabling kernel bypass and zero-copy transfers
- **io_uring** offers a modern asynchronous I/O interface, reducing system call overhead for both network and storage operations
- **VFIO** enables direct userspace access to PCIe devices like NVMe drives
- **NVIDIA XLIO** accelerates TCP/IP processing in userspace for Mellanox network adapters
- **DPDK** provides a low level hardware abstraction for various data plane devices
- **libfabric** provides an abstraction for fabric-like data planes, but treats traditional TCP-like workflows as second class citizens

Each of these technologies delivers impressive performance improvements for applications that can leverage them. However, they come with significant challenges:

1. **Disjoint Hardware Support**: Each framework supports different subsets of hardware. RDMA requires specific network adapters, XLIO works only with Mellanox NICs, VFIO requires IOMMU support. Choosing one path can lock you into specific hardware vendors.

2. **Steep Learning Curves**: Each SDK has its own programming model, APIs, and operational characteristics. Becoming proficient with even one of these systems requires substantial investment. Supporting multiple backends means learning them all.

3. **Limited Portability**: Applications written directly against these SDKs are difficult to port. Code written for libibverbs won't run on systems without RDMA hardware. XLIO applications require specific NICs. This fragments the ecosystem and limits where applications can deploy.

4. **Development Complexity**: Building applications that can opportunistically leverage available hardware acceleration while gracefully falling back to traditional approaches requires maintaining multiple code paths and substantial testing infrastructure.

## libevpl: A Unified Approach

libevpl aims to solve these challenges by providing a **single, protocol-agnostic event loop engine** with unified abstractions for network and block I/O. Rather than replacing these high-performance backends, libevpl integrates them behind a common API:

- Write code once against libevpl's event-driven API
- At runtime, select the best available backend based on the system's hardware and software capabilities
- The same application binary can run efficiently on systems with RDMA hardware, XLIO-accelerated networking, or traditional kernel sockets—without code changes
- Block I/O operations integrate seamlessly with network I/O, using io_uring or VFIO-NVMe as available

This approach delivers several key benefits:

**For Application Developers:**
- A high level API that guides developers towards making performant choices
- Write event-driven network and storage code once, run it across diverse hardware
- Focus on application logic rather than the intricacies of each acceleration framework
- Automatically benefit from hardware acceleration when available without code changes
- Develop and test on standard hardware, deploy to accelerated environments with confidence

**For the Ecosystem:**
- Lower barriers to adoption for high-performance hardware and SDKs
- Broader utilization of performance-enhancing technologies
- Easier migration between hardware platforms as requirements evolve
- Reduced vendor lock-in while still leveraging vendor-specific optimizations

## Who Should Use libevpl?

libevpl is designed for building high-performance distributed systems where network throughput, storage IOPS, or latency are critical constraints:

- **Storage Systems**: NAS servers, distributed filesystems, object stores requiring maximum throughput
- **Financial Services**: Low-latency trading systems, market data processing
- **Data Infrastructure**: High-speed data pipelines, stream processing, real-time analytics
- **Scientific Computing**: HPC applications requiring efficient communication and I/O
- **Database Systems**: Distributed databases, replication engines, query processing

If your application needs to efficiently handle hundreds of thousands of network connections, sustain multi-gigabit throughput, process millions of storage operations per second, or minimize latency to microseconds, libevpl provides the foundation to achieve these goals across diverse hardware platforms.

## Project Status

libevpl is actively developed as the foundational I/O layer for **Chimera**, a high-performance multi-protocol NAS stack. While the library is functional and usable for experimentation and development, **it is not yet stable**. APIs may evolve as development continues and new use cases emerge.

Contributions, feedback, and real-world usage reports are welcome and help guide the project's evolution.

## Getting Started

Ready to explore libevpl? Here's your path forward:

1. **[Building & Installation](/build)** - Get libevpl compiled and installed on your system
2. **[Architecture & Concepts](/architecture)** - Understand libevpl's design and core abstractions
3. **[API Documentation](/api)** - Dive into the detailed API reference
4. **[Examples](/examples)** - Study working code samples

## License

libevpl is licensed under **LGPL-2.1-only**, enabling use in both open source and commercial applications. You can link libevpl into proprietary software while keeping your application's code private.
