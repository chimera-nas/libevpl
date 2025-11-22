---
title: Configuration 
layout: default
parent: Core
nav_order: 2
permalink: /api/config
---

# Configuration

Provides functions for customizing libevpl's global and per-thread behavior.


## Overview

libevpl has two levels of configuration:

1. **Global configuration** - Set once before `evpl_init()`, affects all threads
2. **Thread configuration** - Set per-thread when creating event loops

## Types

### `struct evpl_global_config`

Opaque structure holding global configuration settings.

### `struct evpl_thread_config`

Opaque structure holding thread-local configuration settings.

## Global Configuration

Global settings must be configured before calling `evpl_init()`.

### `evpl_global_config_init`

```c
struct evpl_global_config *evpl_global_config_init(void);
```

Create a global configuration object with default values.

**Returns:** Configuration object, or `NULL` on failure

---

### `evpl_global_config_release`

```c
void evpl_global_config_release(struct evpl_global_config *config);
```

Release a global configuration object.  This only needs to be called if for
some reason the config was never provided to evpl_init(), as evpl_init()
will take ownership if called.

**Parameters:**
- `config` - Configuration to release

---

### Memory Settings

#### `evpl_global_config_set_buffer_size`

```c
void evpl_global_config_set_buffer_size(
    struct evpl_global_config *config,
    uint64_t                   size);
```

Set the size of network buffers allocated from the slab allocator.  Each evpl_iovec is created by taking a slice of
a buffer, so the maximum buffer size is also the maximum libevpl size.   Larger size buffer results in less trips
to the slab allocator which is a shared resource.  Smaller buffer sizes reduces minimum memory usage per thread.

**Parameters:**
- `config` - Configuration object
- `size` - Buffer size in bytes

**Default:** 2MB (2,097,152 bytes)

---

#### `evpl_global_config_set_huge_pages`

```c
void evpl_global_config_set_huge_pages(
    struct evpl_global_config *config,
    int                        huge_pages);
```

Enable or disable huge page allocation for buffers.  If huge pages are enabled and not available
libevpl will emit a warning and automatically fall back to normal memory.

**Parameters:**
- `config` - Configuration object
- `huge_pages` - 1 to enable, 0 to disable

**Default:** 0 (disabled)

---

#### `evpl_global_config_set_slab_size`

```c
void evpl_global_config_set_slab_size(
    struct evpl_global_config *config,
    uint64_t                   size);
```

Set the total size of the slab allocator used for buffer allocation.

**Parameters:**
- `config` - Configuration object
- `size` - Slab size in bytes

**Default:** 1GB (1,073,741,824 bytes)

---

#### `evpl_global_config_set_max_num_iovec`

```c
void evpl_global_config_set_max_num_iovec(
    struct evpl_global_config *config,
    unsigned int               max);
```

Set the maximum number of iovecs that can be used in a single operation.

**Parameters:**
- `config` - Configuration object
- `max` - Maximum number of iovecs

**Default:** 128

---

### Ring Buffer Settings

#### `evpl_global_config_set_iovec_ring_size`

```c
void evpl_global_config_set_iovec_ring_size(
    struct evpl_global_config *config,
    unsigned int               size);
```

Set the size of the iovec ring buffer.

**Parameters:**
- `config` - Configuration object
- `size` - Ring size (must be power of 2)

**Default:** 1024

---

#### `evpl_global_config_set_dgram_ring_size`

```c
void evpl_global_config_set_dgram_ring_size(
    struct evpl_global_config *config,
    unsigned int               size);
```

Set the size of the datagram ring buffer.

**Parameters:**
- `config` - Configuration object
- `size` - Ring size (must be power of 2)

**Default:** 256

---

#### `evpl_global_config_set_rdma_request_ring_size`

```c
void evpl_global_config_set_rdma_request_ring_size(
    struct evpl_global_config *config,
    unsigned int               size);
```

Set the size of the RDMA request ring buffer.

**Parameters:**
- `config` - Configuration object
- `size` - Ring size (must be power of 2)

**Default:** 64

---

### Polling Behavior

#### `evpl_global_config_set_spin_ns`

```c
void evpl_global_config_set_spin_ns(
    struct evpl_global_config *config,
    uint64_t                   ns);
```

Sets the amount of time that libevpl will spin-poll on the CPU after receiving some form
of event/work.  If more work quickly arrives, this avoids the CPU cost and latency jitter
of the thread sleeping and subsequently being rescheduled.  On the other hand, the CPU being
used while spinning is wasted.  Smaller setting will improve power efficiency, larger
setting will improve performance up to a point, especially with hardware accelerated backends
that don't need to make system calls to perform work (io_uring, XLIO, RDMA, ...).

**Parameters:**
- `config` - Configuration object
- `ns` - Nanoseconds to spin

**Default:** 1ms (1,000,000 nanoseconds)

**Behavior:**
- `0` - Event-driven only (sleep immediately)
- `> 0` - Poll for this duration before sleeping

---

#### `evpl_global_config_set_hf_time_mode`

```c
void evpl_global_config_set_hf_time_mode(
    struct evpl_global_config *config,
    unsigned int               mode);
```

Set the method used for obtaining timestamps at high frequency.

0 -- Use OS provided high-precision clock API, eg clock_gettime()
1 -- Use built-in TSC based time measurement, may be unreliable depending on hardware
2 -- Use TSC based time measurement only if /proc/cpuinfo exists and indicates nonstop_tsc support, otherwise use OS method

**Parameters:**
- `config` - Configuration object
- `mode` - Time mode: 0 = disabled, 1 = TSC (Time Stamp Counter), 2 = auto-detect

**Default:** 2 (auto-detect)

**Behavior:**
- `0` - Disable high-frequency timing
- `1` - Use TSC (requires nonstop_tsc CPU feature)
- `2` - Auto-detect: check for nonstop_tsc support and enable if available

---

#### `evpl_global_config_set_max_pending`

```c
void evpl_global_config_set_max_pending(
    struct evpl_global_config *config,
    unsigned int               max);
```

Set the maximum number of pending connections for listening sockets.

**Parameters:**
- `config` - Configuration object
- `max` - Maximum pending connections

**Default:** 16

---

#### `evpl_global_config_set_max_poll_fd`

```c
void evpl_global_config_set_max_poll_fd(
    struct evpl_global_config *config,
    unsigned int               max);
```

Set the maximum number of file descriptors to poll in a single operation.

**Parameters:**
- `config` - Configuration object
- `max` - Maximum file descriptors per poll

**Default:** 16

---

### Protocol-Specific Settings

#### `evpl_global_config_set_max_datagram_size`

```c
void evpl_global_config_set_max_datagram_size(
    struct evpl_global_config *config,
    unsigned int               size);
```

Set the maximum size for datagram protocols (UDP, RDMA UD).

**Parameters:**
- `config` - Configuration object
- `size` - Maximum datagram size in bytes

**Default:** 65536 bytes

---

#### `evpl_global_config_set_max_datagram_batch`

```c
void evpl_global_config_set_max_datagram_batch(
    struct evpl_global_config *config,
    unsigned int               batch);
```

Set the maximum number of datagrams to process in a single batch.

**Parameters:**
- `config` - Configuration object
- `batch` - Maximum batch size

**Default:** 16

---

#### `evpl_global_config_set_resolve_timeout_ms`

```c
void evpl_global_config_set_resolve_timeout_ms(
    struct evpl_global_config *config,
    unsigned int               timeout_ms);
```

Set the timeout for address resolution operations.

**Parameters:**
- `config` - Configuration object
- `timeout_ms` - Timeout in milliseconds

**Default:** 5000 ms

---

### Backend Settings

#### `evpl_global_config_set_io_uring_enabled`

```c
void evpl_global_config_set_io_uring_enabled(
    struct evpl_global_config *config,
    int                        enabled);
```

Enable or disable io_uring backend. If disabled, libevpl will fall back to epoll.

**Parameters:**
- `config` - Configuration object
- `enabled` - 1 to enable, 0 to disable

**Default:** 1 (enabled)

---

#### `evpl_global_config_set_xlio_enabled`

```c
void evpl_global_config_set_xlio_enabled(
    struct evpl_global_config *config,
    int                        enabled);
```

Enable or disable XLIO (Accelio) backend for network acceleration.

**Parameters:**
- `config` - Configuration object
- `enabled` - 1 to enable, 0 to disable

**Default:** 1 (enabled)

---

#### `evpl_global_config_set_vfio_enabled`

```c
void evpl_global_config_set_vfio_enabled(
    struct evpl_global_config *config,
    int                        enabled);
```

Enable or disable VFIO for direct device access.

**Parameters:**
- `config` - Configuration object
- `enabled` - 1 to enable, 0 to disable

**Default:** 1 (enabled)

---

### RDMA Configuration

#### `evpl_global_config_set_rdmacm_tos`

```c
void evpl_global_config_set_rdmacm_tos(
    struct evpl_global_config *config,
    uint8_t                    tos);
```

Set the Type of Service (ToS) field for RDMA connections (QoS).

Default of 0 means don't set it at all, will inherit kernel default.

**Parameters:**
- `config` - Configuration object
- `tos` - ToS value (0-255)

**Default:** 0

---

#### `evpl_global_config_set_rdmacm_datagram_size_override`

```c
void evpl_global_config_set_rdmacm_datagram_size_override(
    struct evpl_global_config *config,
    unsigned int               size);
```

Override the default datagram size for RDMA UD protocols other than
what is specified above.

UDP packets typically must be <=64KB.  RDMA UD datagrams need to be
<= RoCE MTU, which can be up to 4096b.

**Parameters:**
- `config` - Configuration object
- `size` - Datagram size in bytes

**Default:** Automatically determined from MTU

---

#### `evpl_global_config_set_rdmacm_srq_prefill`

```c
void evpl_global_config_set_rdmacm_srq_prefill(
    struct evpl_global_config *config,
    int                        prefill);
```

libevpl unconditionally uses shared receive queues (SRQ) for RDMA.

If true, the shared receive queue is synchronously filled with receive requests on thread start.   This reduces tail latency on cold start but adds a measurable delay to startup time.  If false, receive requests are posted ASAP after the thread has started.

**Parameters:**
- `config` - Configuration object
- `prefill` - 1 to enable, 0 to disable

**Default:** 0 (disabled)

---

#### `evpl_global_config_set_rdmacm_enabled`

```c
void evpl_global_config_set_rdmacm_enabled(
    struct evpl_global_config *config,
    int                        enabled);
```

Enable or disable RDMA CM (Connection Manager) support.

**Parameters:**
- `config` - Configuration object
- `enabled` - 1 to enable, 0 to disable

**Default:** 1 (enabled)

---

#### `evpl_global_config_set_rdmacm_max_sge`

```c
void evpl_global_config_set_rdmacm_max_sge(
    struct evpl_global_config *config,
    unsigned int               max_sge);
```

Set the maximum number of scatter-gather elements (SGE) per RDMA work request.

**Parameters:**
- `config` - Configuration object
- `max_sge` - Maximum SGE count

**Default:** 31

---

#### `evpl_global_config_set_rdmacm_cq_size`

```c
void evpl_global_config_set_rdmacm_cq_size(
    struct evpl_global_config *config,
    unsigned int               size);
```

Set the size of RDMA completion queues.

**Parameters:**
- `config` - Configuration object
- `size` - Completion queue size

**Default:** 8192

---

#### `evpl_global_config_set_rdmacm_sq_size`

```c
void evpl_global_config_set_rdmacm_sq_size(
    struct evpl_global_config *config,
    unsigned int               size);
```

Set the size of RDMA send queues.

**Parameters:**
- `config` - Configuration object
- `size` - Send queue size

**Default:** 256

---

#### `evpl_global_config_set_rdmacm_srq_size`

```c
void evpl_global_config_set_rdmacm_srq_size(
    struct evpl_global_config *config,
    unsigned int               size);
```

Set the size of RDMA shared receive queues.

**Parameters:**
- `config` - Configuration object
- `size` - Shared receive queue size

**Default:** 8192

---

#### `evpl_global_config_set_rdmacm_srq_min`

```c
void evpl_global_config_set_rdmacm_srq_min(
    struct evpl_global_config *config,
    unsigned int               min);
```

Set the minimum number of entries in RDMA shared receive queues.

**Parameters:**
- `config` - Configuration object
- `min` - Minimum SRQ entries

**Default:** 256

---

#### `evpl_global_config_set_rdmacm_max_inline`

```c
void evpl_global_config_set_rdmacm_max_inline(
    struct evpl_global_config *config,
    unsigned int               max_inline);
```

Set the maximum inline data size for RDMA operations. Inline data is sent directly in the work request without a separate memory registration.

**Parameters:**
- `config` - Configuration object
- `max_inline` - Maximum inline size in bytes

**Default:** 250 bytes

---

#### `evpl_global_config_set_rdmacm_srq_batch`

```c
void evpl_global_config_set_rdmacm_srq_batch(
    struct evpl_global_config *config,
    unsigned int               batch);
```

Set the batch size for posting receive requests to shared receive queues.

**Parameters:**
- `config` - Configuration object
- `batch` - Batch size

**Default:** 16

---

#### `evpl_global_config_set_rdmacm_retry_count`

```c
void evpl_global_config_set_rdmacm_retry_count(
    struct evpl_global_config *config,
    unsigned int               retry_count);
```

Set the RDMA retry count for connection attempts.

**Parameters:**
- `config` - Configuration object
- `retry_count` - Number of retries

**Default:** 4

---

#### `evpl_global_config_set_rdmacm_rnr_retry_count`

```c
void evpl_global_config_set_rdmacm_rnr_retry_count(
    struct evpl_global_config *config,
    unsigned int               retry_count);
```

Set the RDMA receiver-not-ready (RNR) retry count.

**Parameters:**
- `config` - Configuration object
- `retry_count` - Number of RNR retries

**Default:** 4

---

### TLS Configuration

#### `evpl_global_config_set_tls_cert`

```c
void evpl_global_config_set_tls_cert(
    struct evpl_global_config *config,
    const char                *cert_file);
```

Set the TLS certificate file path.

**Parameters:**
- `config` - Configuration object
- `cert_file` - Path to PEM-encoded certificate

---

#### `evpl_global_config_set_tls_key`

```c
void evpl_global_config_set_tls_key(
    struct evpl_global_config *config,
    const char                *key_file);
```

Set the TLS private key file path.

**Parameters:**
- `config` - Configuration object
- `key_file` - Path to PEM-encoded private key

---

#### `evpl_global_config_set_tls_ca`

```c
void evpl_global_config_set_tls_ca(
    struct evpl_global_config *config,
    const char                *ca_file);
```

Set the TLS Certificate Authority file path (for client certificate verification).

**Parameters:**
- `config` - Configuration object
- `ca_file` - Path to CA bundle

---

#### `evpl_global_config_set_tls_cipher_list`

```c
void evpl_global_config_set_tls_cipher_list(
    struct evpl_global_config *config,
    const char                *cipher_list);
```

Set the TLS cipher suite list.

**Parameters:**
- `config` - Configuration object
- `cipher_list` - OpenSSL-style cipher string

---

#### `evpl_global_config_set_tls_verify_peer`

```c
void evpl_global_config_set_tls_verify_peer(
    struct evpl_global_config *config,
    int                        verify);
```

Enable or disable TLS peer certificate verification.

**Parameters:**
- `config` - Configuration object
- `verify` - 1 to enable, 0 to disable

**Default:** 1 (enabled)

---

#### `evpl_global_config_set_tls_ktls_enabled`

```c
void evpl_global_config_set_tls_ktls_enabled(
    struct evpl_global_config *config,
    int                        enabled);
```

Enable or disable kernel TLS (kTLS) offload.

If enabled and not available, libevpl will automatically fall back to normal operation.

**Parameters:**
- `config` - Configuration object
- `enabled` - 1 to enable, 0 to disable

**Default:** 1 (enabled)

---

## Thread Configuration

Thread settings are specified when creating an event loop.

### `evpl_thread_config_init`

```c
struct evpl_thread_config *evpl_thread_config_init(void);
```

Create a thread configuration object with default values.

**Returns:** Configuration object, or `NULL` on failure

---

### `evpl_thread_config_release`

```c
void evpl_thread_config_release(struct evpl_thread_config *config);
```

Release a thread configuration object.  This is only needed if the config was never provided to evpl_create(), as
evpl_create() takes ownership of the config.

**Parameters:**
- `config` - Configuration to release

---

#### `evpl_thread_config_set_poll_mode`

```c
void evpl_thread_config_set_poll_mode(
    struct evpl_thread_config *config,
    int                        poll_mode);
```

Set the polling mode for the event loop. When enabled, the event loop will actively poll for events rather than waiting for system notifications.

**Parameters:**
- `config` - Configuration object
- `poll_mode` - 1 to enable polling mode, 0 to disable

**Default:** 1 (enabled)

---

#### `evpl_thread_config_set_poll_iterations`

```c
void evpl_thread_config_set_poll_iterations(
    struct evpl_thread_config *config,
    int                        iterations);
```

Set the number of polling iterations before checking for events.

**Parameters:**
- `config` - Configuration object
- `iterations` - Number of poll iterations

**Default:** 1000

---

#### `evpl_thread_config_set_wait_ms`

```c
void evpl_thread_config_set_wait_ms(
    struct evpl_thread_config *config,
    int                        wait_ms);
```

Set the wait timeout in milliseconds when no events are available. A value of -1 means wait indefinitely.

**Parameters:**
- `config` - Configuration object
- `wait_ms` - Wait timeout in milliseconds, or -1 for infinite wait

**Default:** -1 (infinite wait)

---

## Default Values

| Setting | Default | Notes |
|---------|---------|-------|
| Buffer size | 2MB | Fixed size |
| Slab size | 1GB | Total allocator size |
| Max iovecs | 128 | Per operation |
| Spin time | 1ms | Hybrid polling/event mode |
| Poll iterations | 1000 | Per poll cycle |
| Wait timeout | Infinite | -1 means wait indefinitely |
| HF time mode | Auto-detect | TSC if available |
| Max pending | 16 | Listen backlog |
| Max poll FD | 16 | Per poll operation |
| Huge pages | Disabled | Requires kernel support |
| Max datagram size | 64KB | Fixed size |
| Max datagram batch | 16 | Per batch |
| Resolve timeout | 5000ms | Address resolution |
| Iovec ring size | 1024 | Power of 2 |
| Datagram ring size | 256 | Power of 2 |
| RDMA request ring size | 64 | Power of 2 |
| io_uring | Enabled | Fallback to epoll if unavailable |
| XLIO | Enabled | Network acceleration |
| VFIO | Enabled | Direct device access |
| RDMA CM | Enabled | Connection manager |
| RDMA max SGE | 31 | Scatter-gather elements |
| RDMA CQ size | 8192 | Completion queue |
| RDMA SQ size | 256 | Send queue |
| RDMA SRQ size | 8192 | Shared receive queue |
| RDMA SRQ min | 256 | Minimum SRQ entries |
| RDMA max inline | 250 bytes | Inline data size |
| RDMA SRQ batch | 16 | Receive request batch |
| RDMA retry count | 4 | Connection retries |
| RDMA RNR retry count | 4 | Receiver-not-ready retries |
| TLS verify peer | Enabled | Security best practice |
| kTLS | Enabled | Requires kernel 4.13+ |
| RDMA SRQ prefill | Disabled | Performance vs init time trade-off |

## See Also

- [Core API](/api/core) - Initialization and event loops
- [Architecture](/architecture) - Understanding hybrid event/polling
- [Performance](/performance) - Benchmark results
- [Programming Guide](/programming_guide) - Performance tuning
