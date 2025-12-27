---
title: RDMA
layout: default
parent: Core
nav_order: 11
permalink: /api/rdma
---

# RDMA

libevpl supports one-sided READ/WRITE RDMA operations, wherein the initiator reads from or writes to memory in a remote machine without software involvement on the remote system.

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

Read data from remote memory into local buffers (RDMA READ operation).

**Parameters:**
- `evpl` - Event loop
- `bind` - RDMA connection
- `remote_key` - Memory key for remote buffer
- `remote_address` - Address of remote buffer
- `iov` - Local buffers to read into
- `niov` - Number of local buffers
- `callback` - Completion callback
- `private_data` - User context

**Behavior:**
- Fetches data from remote memory into local iovecs
- Remote side does not participate (one-sided)
- Completes asynchronously via callback

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

Write data from local buffers to remote memory (RDMA WRITE operation).

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
- `EVPL_RDMA_FLAG_TAKE_REF` - Transfer ownership of a reference to the iovecs to libevpl. When set, libevpl takes ownership and will decrement the reference count when the RDMA write completes. When not set, libevpl adds its own reference and the caller retains ownership.

**Behavior:**
- Pushes data from local iovecs to remote memory
- Remote side CPU does not participate (one-sided)
- Completes asynchronously via callback

## See Also

- [Binds & Connections API](/api/binds) - RDMA connection setup
- [Memory API](/api/memory) - Buffer management and registration
- [Configuration API](/api/config) - RDMA-specific settings
- [Architecture](/architecture) - RDMA protocol overview
- [Performance](/performance) - RDMA benchmark results
