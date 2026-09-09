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

- **[Core API]({{ '/api/core' | relative_url }})** - Event loop management, initialization, and protocol queries
- **[Configuration API]({{ '/api/config' | relative_url }})** - Global and thread-local configuration
- **[Binds & Connections]({{ '/api/binds' | relative_url }})** - Creating connections, sending/receiving data
- **[Endpoints API]({{ '/api/endpoints' | relative_url }})** - Network address and port management
- **[Memory API]({{ '/api/memory' | relative_url }})** - Buffer allocation and management
- **[Timer API]({{ '/api/timers' | relative_url }})** - Scheduled callbacks and timeouts
- **[Deferral API]({{ '/api/deferrals' | relative_url }})** - Deferred task execution
- **[Doorbell API]({{ '/api/doorbells' | relative_url }})** - Inter-thread notifications
- **[Poll API]({{ '/api/polls' | relative_url }})** - Busy-poll callbacks for spin-mode work
- **[Threading API]({{ '/api/threading' | relative_url }})** - Thread creation and thread pools
- **[Block I/O API]({{ '/api/block' | relative_url }})** - High-performance storage operations (io_uring, VFIO-NVMe)
- **[RDMA API]({{ '/api/rdma' | relative_url }})** - RDMA-specific functionality
- **[Logging API]({{ '/api/logging' | relative_url }})** - Logging and diagnostics

## Protocol Modules

- **[HTTP API]({{ '/api/protocols/http' | relative_url }})** - HTTP client and server
- **[RPC2 API]({{ '/api/protocols/rpc2' | relative_url }})** - ONC RPC2 for NFS

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

- [Getting Started]({{ '/getting-started' | relative_url }}) - Quick tutorial
- [Architecture]({{ '/architecture' | relative_url }}) - Understanding core concepts
- [Programming Guide]({{ '/programming_guide' | relative_url }}) - Best practices
- [Examples]({{ '/examples' | relative_url }}) - Complete working code samples
