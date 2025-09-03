<!--
SPDX-FileCopyrightText: 2025 Ben Jarvis

SPDX-License-Identifier: Unlicense
-->

---
title: Introduction
layout: default
nav_order: 1
permalink: /intro
---

# Introduction to libevpl

libevpl is a high-performance, extensible library designed to facilitate efficient event-driven programming. It provides a robust framework for handling various network and block I/O operations, making it ideal for applications that require low-latency and high-throughput communication.

## Key Features

- **Protocol Support**: libevpl supports a wide range of protocols, including UDP, TCP, and RDMA, allowing for flexible communication strategies.
- **Framework Integration**: The library integrates with multiple frameworks such as RDMACM, XLIO, IO_URING, and VFIO, providing a versatile environment for different use cases.
- **Efficient I/O Operations**: With support for both stream and datagram communication, libevpl optimizes I/O operations to ensure minimal overhead and maximum performance.
- **Event Notification**: The library offers a comprehensive event notification system, enabling applications to respond promptly to network events.
- **Block Device Management**: libevpl includes functionality for managing block devices, supporting operations like read, write, and flush with asynchronous callbacks.

## Getting Started

To begin using libevpl, you will need to integrate it into your project and configure it according to your specific requirements. The library provides a set of initialization functions and configuration options to tailor its behavior to your needs.

For detailed instructions on installation and setup, please refer to the [Installation Guide](/installation).

## Use Cases

libevpl is suitable for a variety of applications, including:

- High-frequency trading systems
- Real-time data processing
- Networked storage solutions
- Distributed computing environments

By leveraging libevpl, developers can build scalable, efficient applications that meet the demands of modern networked environments.

For more information on how to use libevpl, explore the [API Documentation](/api) and [Examples](/examples) sections.
