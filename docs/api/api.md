---
title: API Reference
layout: default
nav_order: 6
has_children: true
permalink: /api
---

# API Reference

Complete API documentation for libevpl organized by functional area.

## Core APIs

- **[Core API](/api/core)** - Event loop management, initialization, and protocol queries
- **[Configuration API](/api/config)** - Global and thread-local configuration
- **[Binds & Connections](/api/binds)** - Creating connections, sending/receiving data
- **[Endpoints API](/api/endpoints)** - Network address and port management
- **[Memory API](/api/memory)** - Buffer allocation and management
- **[Timer API](/api/timers)** - Scheduled callbacks and timeouts
- **[Deferral API](/api/deferrals)** - Deferred task execution
- **[Doorbell API](/api/doorbells)** - Inter-thread notifications
- **[Threading API](/api/threading)** - Thread creation and thread pools
- **[Block I/O API](/api/block)** - High-performance storage operations (io_uring, VFIO-NVMe)
- **[RDMA API](/api/rdma)** - RDMA-specific functionality
- **[Logging API](/api/logging)** - Logging and diagnostics

## Protocol Modules

- **[HTTP API](/api/http)** - HTTP client and server
- **[RPC2 API](/api/rpc2)** - ONC RPC2 for NFS

## Quick Reference

### Including Headers

All core APIs are accessed through a single header:

```c
#include <evpl/evpl.h>
```

Protocols have their own additional header:

```
#include <evpl/evpl_http.h>
#include <evpl/evpl_rpc2.h>
```

## Error Handling

Most functions return:
- Pointers: `NULL` on failure
- Integers: `-1` or negative on error, `0` or positive on success
- void: No return value (errors signaled via callbacks)

Always check return values and handle errors appropriately.

## Thread Safety

- Each event loop is single-threaded
- Use async events for thread processing, don't block in the event loop.
- Use doorbells for inter-thread communication
- Listeners can be attached to multiple threads 

## See Also

- [Getting Started](/getting-started) - Quick tutorial
- [Architecture](/architecture) - Understanding core concepts
- [Programming Guide](/programming_guide) - Best practices
- [Examples](/examples) - Complete working code samples
