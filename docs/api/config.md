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

**Default:** Protocol-dependent

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

## Default Values

| Setting | Default | Notes |
|---------|---------|-------|
| Buffer size | 2MB | Fixed size |
| Spin time | 1ms | Hybrid polling/event mode |
| Huge pages | Disabled | Requires kernel support |
| Max datagram size | 64KB | Fixed size |
| TLS verify peer | Enabled | Security best practice |
| kTLS | Enabled | Requires kernel 4.13+ |
| RDMA SRQ prefill | Disabled | Performance vs init time trade-off |

## See Also

- [Core API](/api/core) - Initialization and event loops
- [Architecture](/architecture) - Understanding hybrid event/polling
- [Performance](/performance) - Benchmark results
- [Programming Guide](/programming_guide) - Performance tuning
