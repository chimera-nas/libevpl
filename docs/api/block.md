---
title: Block I/O
layout: default
parent: Core 
nav_order: 12 
permalink: /api/block
---

# Block I/O

Provides high-performance asynchronous access to block devices (NVMe SSDs, etc.) integrated with libevpl's event loop.


## Overview

libevpl's Block I/O subsystem offers:

- **Asynchronous operations** - Read, write, and flush integrate with the event loop
- **Zero-copy I/O** - Uses iovec-based scatter-gather
- **Multiple backends** - io_uring and VFIO-NVMe for maximum performance
- **High IOPS** - Optimized for NVMe SSDs (millions of IOPS)
- **Per-thread queues** - Lock-free operation within event loops

## Supported Backends

### io_uring

**Description:** Linux io_uring asynchronous I/O interface

**Availability:** Linux kernel 5.1+ with liburing

**Characteristics:**
- Kernel-mediated I/O
- Works with any block device
- Lower CPU overhead than traditional AIO
- Excellent for general-purpose storage

**Use cases:** General NVMe/SSD access, compatibility across devices

### VFIO-NVMe

**Description:** Direct userspace NVMe access via VFIO

**Availability:** Linux with VFIO and IOMMU support

**Characteristics:**
- Bypasses kernel completely
- Direct hardware access
- Ultra-low latency
- Requires device unbinding from kernel driver
- Requires root or appropriate VFIO permissions

**Use cases:** Ultra-low latency storage, maximum IOPS, dedicated storage devices

### SPDK bdev

**Description:** Access to any SPDK block device (bdev) of a host SPDK application

**Availability:** Builds with SPDK installed (`SPDK_ENABLED`); at runtime
requires `EVPL_CORE_MECH_SPDK` — the opening event loop must be an evpl thread
running as an spdk_thread inside an SPDK application that owns the bdev layer.

**Characteristics:**
- Full access to the host application's bdev stack (NVMe, malloc, RAID,
  logical volumes, crypto, ...)
- Userspace polled completions delivered by the bdev I/O channel on the
  owning spdk_thread
- evpl slab buffers are pre-registered with `spdk_mem_register`, so I/O is
  zero-copy DMA-safe
- The URI is the bdev name registered in the host application

**Use cases:** libevpl workloads embedded in an existing SPDK application that
need to share its storage stack

## Types

### `struct evpl_block_device`

Opaque structure representing an opened block device.

### `struct evpl_block_queue`

Opaque structure representing a per-thread I/O queue for a block device. Each event loop creates its own queue.

### `enum evpl_block_protocol_id`

Identifies block device backend:

| Protocol | Description |
|----------|-------------|
| `EVPL_BLOCK_PROTOCOL_IO_URING` | Linux io_uring |
| `EVPL_BLOCK_PROTOCOL_VFIO` | VFIO-NVMe direct access |
| `EVPL_BLOCK_PROTOCOL_LIBAIO` | Linux libaio |
| `EVPL_BLOCK_PROTOCOL_IO_URING_NVME` | io_uring NVMe passthrough (uring_cmd) |
| `EVPL_BLOCK_PROTOCOL_SPDK_BDEV` | SPDK bdev (requires the SPDK core mechanism) |

### `evpl_block_callback_t`

```c
typedef void (*evpl_block_callback_t)(
    struct evpl *evpl,
    int          status,
    void        *private_data);
```

Callback invoked when a block operation completes.

**Parameters:**
- `evpl` - Event loop
- `status` - 0 on success, positive errno on failure
- `private_data` - User-provided context

### `evpl_block_open_callback_t`

```c
typedef void (*evpl_block_open_callback_t)(
    struct evpl              *evpl,
    struct evpl_block_device *blockdev,
    int                       status,
    void                     *private_data);
```

Callback invoked when an asynchronous device open completes.

**Parameters:**
- `evpl` - Event loop
- `blockdev` - Opened device handle, or `NULL` on failure
- `status` - 0 on success, positive errno on failure
- `private_data` - User-provided context

## Functions

### Device Management

Device open and close are asynchronous operations that run in the context of
an event loop, like every other libevpl operation.  The completion callback
always fires from a later iteration of the opening loop — never inline from
the call itself — including for failures.

The opening event loop owns the device for lifecycle purposes:

- it must outlive the device,
- backend device events (such as hot-remove) are handled on its thread, and
- `evpl_block_close_device` must be called with this same event loop.

Queues may still be opened against the device from any event loop / thread.

#### `evpl_block_open_device`

```c
void evpl_block_open_device(
    struct evpl                *evpl,
    enum evpl_block_protocol_id protocol,
    const char                 *uri,
    evpl_block_open_callback_t  callback,
    void                       *private_data);
```

Open a block device asynchronously.  Each device should be opened once
globally for the whole process.

**Parameters:**
- `evpl` - Event loop that will own the device
- `protocol` - Backend protocol to use
- `uri` - Device identifier (protocol-specific)
- `callback` - Completion callback; receives the device handle or `NULL`
- `private_data` - User context

**URI Formats:**

**io_uring / libaio:**
- Device path: `/dev/nvme0n1`
- File path: `/tmp/testfile`

**io_uring NVMe passthrough:**
- NVMe namespace block device: `/dev/nvme0n1`

**VFIO-NVMe:**
- PCI address: `0000:01:00.0`

**SPDK bdev:**
- bdev name in the host SPDK application: `Malloc0`, `Nvme0n1`

---

#### `evpl_block_close_device`

```c
void evpl_block_close_device(
    struct evpl              *evpl,
    struct evpl_block_device *blockdev,
    evpl_block_callback_t     callback,
    void                     *private_data);
```

Close a block device asynchronously. All queues must be closed first, and the
call must be made on the event loop that opened the device.  The device handle
is invalid as soon as this is called; the callback (which may be `NULL`) fires
from a later loop iteration once the backend has released the device.

**Parameters:**
- `evpl` - Event loop that opened the device
- `blockdev` - Device to close
- `callback` - Completion callback, or `NULL`
- `private_data` - User context

---

#### `evpl_block_size`

```c
uint64_t evpl_block_size(struct evpl_block_device *blockdev);
```

Get the size of a block device in bytes.

**Parameters:**
- `blockdev` - Device to query

**Returns:** Device size in bytes

---

#### `evpl_block_max_request_size`

```c
uint64_t evpl_block_max_request_size(struct evpl_block_device *blockdev);
```

Get the maximum size for a single I/O request.

**Parameters:**
- `blockdev` - Device to query

**Returns:** Maximum request size in bytes

**Note:** Requests larger than this must be split into multiple operations.

---

### Queue Management

#### `evpl_block_open_queue`

```c
struct evpl_block_queue *evpl_block_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *blockdev);
```

Create a thread-specific I/O queue for a block device attached to an event loop.

**Parameters:**
- `evpl` - Event loop
- `blockdev` - Block device

**Returns:** Queue handle, or `NULL` on failure

**Thread Safety:** Each thread/event loop must create its own queue. Queues are not shared.

---

#### `evpl_block_close_queue`

```c
void evpl_block_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *queue);
```

Close an I/O queue. All pending operations must complete first.

**Parameters:**
- `evpl` - Event loop
- `queue` - Queue to close

---

### I/O Operations

#### `evpl_block_read`

```c
void evpl_block_read(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec       *iov,
    int                      niov,
    uint64_t                 offset,
    evpl_block_callback_t    callback,
    void                    *private_data);
```

Read data from a block device asynchronously.  Zero copy with supported backend.

**Parameters:**
- `evpl` - Event loop
- `queue` - I/O queue
- `iov` - Array of iovecs to read into
- `niov` - Number of iovecs
- `offset` - Byte offset in device
- `callback` - Completion callback
- `private_data` - User context

**Note:** Buffers must remain valid until callback is invoked. Use `evpl_iovec_addref()` if needed.

---

#### `evpl_block_write`

```c
void evpl_block_write(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int                      niov,
    uint64_t                 offset,
    int                      sync,
    evpl_block_callback_t    callback,
    void                    *private_data);
```

Write data to a block device asynchronously.  Zero copy with supported backend.

**Parameters:**
- `evpl` - Event loop
- `queue` - I/O queue
- `iov` - Array of iovecs containing data to write
- `niov` - Number of iovecs
- `offset` - Byte offset in device
- `sync` - 1 for durable write (FUA), 0 to allow non-durable
- `callback` - Completion callback
- `private_data` - User context

**Synchronous vs Asynchronous:**
- `sync=0`: Write may be cached, returns when accepted by device, may be lost on power event
- `sync=1`: Write is flushed to persistent media before being considered complete (Force Unit Access)

---

#### `evpl_block_flush`

```c
void evpl_block_flush(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    evpl_block_callback_t    callback,
    void                    *private_data);
```

Flush cached writes to persistent storage.  Only pertinent if non-FUA writes were previously issued.

For io_uring, performs a sync(), for VFIO-NVME performs an NVMe flush operation.

**Parameters:**
- `evpl` - Event loop
- `queue` - I/O queue
- `callback` - Completion callback
- `private_data` - User context

---

## Backend Comparison

| Feature | io_uring | VFIO-NVMe |
|---------|----------|-----------|
| **Latency** | Low  | Ultra-low |
| **IOPS** | Very High | Maximum |
| **CPU Usage** | Low | Very Low |
| **Setup** | Simple | Complex (device unbind) |
| **Permissions** | Standard | Root or VFIO setup |
| **Device Support** | All block devices | NVMe only |
| **Kernel Dependency** | Yes | No (userspace) |

## Choosing a Backend

### Use io_uring when:
- You need compatibility across different devices
- You want simple setup and configuration
- You're using standard filesystems or partitions
- You need kernel features (filesystem, encryption, etc.)

### Use VFIO-NVMe when:
- You need absolute minimum latency
- You can dedicate entire NVMe device to application
- You have proper IOMMU and VFIO configuration
- CPU efficiency is critical
- You're building custom storage stack (no filesystem)

## Performance Optimization

### Alignment

io_uring genereally requires page and block aligned I/O to allow DMA.

VFIO-NVMe alignment dependency varies device to device. All NVMe devices require
sector-aligned I/O, but many do not have any memory alignment requirement.

All else being equal, use page aligned memory when possible.

### Request Size

Larger requests generally improve throughput to a point. Check maximum request size and use large requests for optimal throughput.

### Queue Depth

Multiple outstanding requests improve IOPS to a point. Issue multiple requests in parallel for better performance.

## See Also

- [Memory API](/api/memory) - Buffer management for block I/O
- [Configuration API](/api/config) - Performance tuning
- [Core API](/api/core) - Event loop integration
- [Architecture](/architecture) - Understanding async I/O
