---
title: RDMA
layout: default
parent: Core
nav_order: 11
permalink: /api/rdma
---

# RDMA

libevpl supports one-sided READ/WRITE RDMA operations, wherein the initiator reads from or writes to memory in a remote machine without software involvement on the remote system.

## Backends

libevpl provides two backends for RDMA operations:

- **Native RDMA** (`EVPL_STREAM_RDMACM_RC`) - Hardware-accelerated RDMA via RDMACM
- **TCP-RDMA** (`EVPL_DATAGRAM_TCP_RDMA`) - RDMA emulation over TCP for development and testing without RDMA hardware

## Functions

### `evpl_rdma_read`

```c
void evpl_rdma_read(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    void (*callback)(int status, void *private_data),
    void *private_data);
```

Read data from remote memory into local buffers.

**Parameters:**
- `evpl` - Event loop
- `bind` - RDMA connection
- `remote_key` - Memory key for remote buffer
- `remote_address` - Address of remote buffer
- `iov` - Local buffers to read into
- `niov` - Number of local buffers
- `callback` - Completion callback
- `private_data` - User context

---

### `evpl_rdma_write`

```c
void evpl_rdma_write(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    unsigned int flags,
    void (*callback)(int status, void *private_data),
    void *private_data);
```

Write data from local buffers to remote memory.

**Parameters:**
- `evpl` - Event loop
- `bind` - RDMA connection
- `remote_key` - Memory key for remote buffer
- `remote_address` - Address of remote buffer
- `iov` - Local buffers containing data to write
- `niov` - Number of local buffers
- `flags` - RDMA flags (see below)
- `callback` - Completion callback
- `private_data` - User context

**Flags:**
- `EVPL_RDMA_FLAG_TAKE_REF` - Transfer iovec ownership to libevpl

---

### `evpl_bind_is_rdma`

```c
int evpl_bind_is_rdma(struct evpl_bind *bind);
```

Check if a bind supports RDMA operations.

**Parameters:**
- `bind` - Connection to check

**Returns:** Non-zero if RDMA operations are supported, 0 otherwise

---

## See Also

- [Binds & Connections API](/api/binds) - RDMA connection setup
- [Memory API](/api/memory) - Buffer management
- [Protocols](/api/protocols) - Available protocols including TCP-RDMA
