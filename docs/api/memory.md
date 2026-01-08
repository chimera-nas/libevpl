---
title: Memory Management
layout: default
parent: Core
nav_order: 4
permalink: /api/memory
---

# Memory Management

libevpl provides a high-performance memory management system optimized for I/O operations. Memory is allocated from large slabs and managed via reference-counted iovecs.

## Allocation Flags

The `flags` parameter to `evpl_iovec_alloc` controls the type of allocation:

- **`0` (LOCAL)** - Default. Uses non-atomic reference counting. Use when the iovec will only be accessed from a single thread.

- **`EVPL_IOVEC_FLAG_SHARED`** - Uses atomic reference counting. Use when the iovec may be accessed from multiple threads.

## Functions

### Buffer Allocation

#### `evpl_iovec_alloc`

```c
int evpl_iovec_alloc(
    struct evpl       *evpl,
    unsigned int       length,
    unsigned int       alignment,
    unsigned int       max_iovecs,
    unsigned int       flags,
    struct evpl_iovec *r_iovec);
```

Allocate one or more iovecs to hold the requested length of data.

**Parameters:**
- `evpl` - Event loop
- `length` - Total bytes to allocate
- `alignment` - Memory alignment requirement in bytes, 0 if none
- `max_iovecs` - Maximum number of iovecs to return
- `flags` - Allocation flags (0 for local, EVPL_IOVEC_FLAG_SHARED for multi-threaded)
- `r_iovec` - [OUT] Array to receive allocated iovecs

**Returns:** Number of iovecs allocated (1 to `max_iovecs`), or -1 on error

---

#### `evpl_iovec_reserve`

```c
int evpl_iovec_reserve(
    struct evpl       *evpl,
    unsigned int       length,
    unsigned int       alignment,
    unsigned int       max_vec,
    struct evpl_iovec *r_iovec);
```

Reserve iovecs for two-phase allocation. Use when the final data size is unknown at allocation time.

**Parameters:**
- `evpl` - Event loop
- `length` - Maximum bytes to reserve
- `alignment` - Alignment requirement
- `max_vec` - Maximum iovecs
- `r_iovec` - [OUT] Reserved iovecs

**Returns:** Number of iovecs reserved, or -1 on error

**Usage:** Call `evpl_iovec_reserve()`, fill with data, then call `evpl_iovec_commit()` to finalize.

---

#### `evpl_iovec_commit`

```c
void evpl_iovec_commit(
    struct evpl       *evpl,
    unsigned int       alignment,
    struct evpl_iovec *iovecs,
    int                niovs);
```

Finalize a two-phase allocation after filling data into reserved iovecs.

**Parameters:**
- `evpl` - Event loop
- `alignment` - Alignment used in reserve
- `iovecs` - Array of reserved iovecs (with `length` fields updated)
- `niovs` - Number of iovecs

---

### Reference Counting

#### `evpl_iovec_release`

```c
static inline void evpl_iovec_release(
    struct evpl       *evpl,
    struct evpl_iovec *iovec);
```

Release a reference to an iovec.

**Parameters:**
- `evpl` - Event loop context (may be NULL during shutdown)
- `iovec` - iovec to release

---

#### `evpl_iovecs_release`

```c
static inline void evpl_iovecs_release(
    struct evpl       *evpl,
    struct evpl_iovec *iov,
    int                niov);
```

Release references to multiple iovecs.

**Parameters:**
- `evpl` - Event loop context
- `iov` - Array of iovecs to release
- `niov` - Number of iovecs

---

#### `evpl_iovec_clone`

```c
static inline void evpl_iovec_clone(
    struct evpl_iovec *dst,
    struct evpl_iovec *src);
```

Clone an iovec, creating a new reference to the same underlying buffer.

**Parameters:**
- `dst` - Destination iovec to initialize
- `src` - Source iovec to clone

---

#### `evpl_iovec_clone_segment`

```c
static inline void evpl_iovec_clone_segment(
    struct evpl_iovec       *dst,
    const struct evpl_iovec *src,
    unsigned int             offset,
    unsigned int             length);
```

Clone a portion of an iovec.

**Parameters:**
- `dst` - Destination iovec to initialize
- `src` - Source iovec
- `offset` - Offset from the start of src's data
- `length` - Length of the segment

---

#### `evpl_iovec_move`

```c
static inline void evpl_iovec_move(
    struct evpl_iovec *dst,
    struct evpl_iovec *src);
```

Move ownership of an iovec from source to destination. The source iovec should not be used after this call.

**Parameters:**
- `dst` - Destination iovec
- `src` - Source iovec (invalid after call)

---

#### `evpl_iovec_move_segment`

```c
static inline void evpl_iovec_move_segment(
    struct evpl_iovec *dst,
    struct evpl_iovec *src,
    unsigned int       offset,
    unsigned int       length);
```

Move ownership of a segment of an iovec.

**Parameters:**
- `dst` - Destination iovec
- `src` - Source iovec (invalid after call)
- `offset` - Offset from the start of src's data
- `length` - Length of the segment

---

### Accessor Functions

#### `evpl_iovec_data`

```c
static inline void *evpl_iovec_data(const struct evpl_iovec *iovec);
```

Get the data pointer from an iovec.

**Returns:** Pointer to buffer data

---

#### `evpl_iovec_length`

```c
static inline unsigned int evpl_iovec_length(const struct evpl_iovec *iovec);
```

Get the length of valid data in an iovec.

**Returns:** Length in bytes

---

#### `evpl_iovec_set_length`

```c
static inline void evpl_iovec_set_length(
    struct evpl_iovec *iovec,
    unsigned int       length);
```

Set the length of valid data in an iovec.

**Parameters:**
- `iovec` - iovec to modify
- `length` - New length

---

## Iovec Tracing Mode

libevpl includes a debugging mode to detect memory management bugs such as use-after-free and double-release.

Enable at compile time:

```bash
cmake -DEVPL_IOVEC_TRACE=1 ...
```

When enabled, iovec operations are validated and will abort with a descriptive error message if a bug is detected. Use only during development due to performance overhead.

---

## See Also

- [Binds & Connections API](/api/binds) - Using iovecs with send/receive
- [Architecture](/architecture) - Memory management overview
