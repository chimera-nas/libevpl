---
title: Protocols
layout: default
parent: API Reference
nav_order: 14
permalink: /api/protocols
---

# Protocols

libevpl has built-in support for multiple network protocols. Each protocol has a unique identifier used when creating connections or listeners.

## Protocol Types

### Stream Protocols

Stream protocols provide reliable, ordered byte streams:

| Protocol ID | Description |
|-------------|-------------|
| `EVPL_STREAM_SOCKET_TCP` | Standard TCP sockets via the kernel |
| `EVPL_STREAM_SOCKET_TLS` | TLS-encrypted TCP connections |
| `EVPL_STREAM_IO_URING_TCP` | TCP using io_uring for improved performance |
| `EVPL_STREAM_RDMACM_RC` | RDMA Reliable Connection (RC) via RDMACM |

### Datagram Protocols

Datagram protocols provide message-oriented communication:

| Protocol ID | Description |
|-------------|-------------|
| `EVPL_DATAGRAM_SOCKET_UDP` | Standard UDP datagrams |
| `EVPL_DATAGRAM_RDMACM_UD` | RDMA Unreliable Datagram (UD) |
| `EVPL_DATAGRAM_TCP_RDMA` | RDMA emulation over TCP (see below) |

## TCP-RDMA Protocol

The `EVPL_DATAGRAM_TCP_RDMA` protocol provides RDMA semantics over standard TCP sockets. This enables development and testing of RDMA-based applications without requiring RDMA hardware.

Despite being implemented over TCP (a stream protocol), TCP-RDMA presents a datagram-style message interface because it emulates RDMA operations which are inherently message-based.

**Use cases:**
- Development without RDMA hardware
- CI/CD testing in virtualized environments
- Debugging RDMA protocols with standard network tools
- Cross-platform RDMA application support

See the [RDMA API documentation](/api/rdma) for details on using TCP-RDMA.

## Frameworks

Frameworks are the underlying I/O implementations that protocols use:

| Framework ID | Description |
|--------------|-------------|
| `EVPL_FRAMEWORK_SOCKET` | Standard kernel sockets (epoll/kqueue) |
| `EVPL_FRAMEWORK_RDMACM` | RDMA Connection Manager |
| `EVPL_FRAMEWORK_IO_URING` | Linux io_uring |
| `EVPL_FRAMEWORK_VFIO` | VFIO for userspace device access |
| `EVPL_FRAMEWORK_TLS` | TLS/SSL via OpenSSL |
| `EVPL_FRAMEWORK_TCP_RDMA` | TCP-based RDMA emulation |

## Protocol Selection

Use `evpl_protocol_lookup` to convert a protocol name string to its ID:

```c
enum evpl_protocol_id proto;
int rc = evpl_protocol_lookup(&proto, "STREAM_SOCKET_TCP");
if (rc == 0) {
    /* proto now contains EVPL_STREAM_SOCKET_TCP */
}
```

Common protocol name strings:
- `"STREAM_SOCKET_TCP"` - TCP
- `"STREAM_SOCKET_TLS"` - TLS over TCP
- `"DATAGRAM_SOCKET_UDP"` - UDP
- `"STREAM_RDMACM_RC"` - RDMA RC
- `"DATAGRAM_TCP_RDMA"` - TCP-RDMA emulation

## See Also

- [Core API](/api/core) - Event loop and initialization
- [Binds & Connections API](/api/binds) - Using protocols with connections
- [RDMA API](/api/rdma) - RDMA and TCP-RDMA operations
- [Configuration API](/api/config) - Protocol-specific settings
