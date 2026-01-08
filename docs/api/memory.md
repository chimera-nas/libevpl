---
title: Memory Management
layout: default
parent: Core
nav_order: 4
permalink: /api/memory
---

# Memory Management

Memory is managed in a three-tier system in libevpl.

First, memory is allocated from the OS in large slabs, by default 1GiB.   Slabs are shared process wide and must be protected by locks.  Slabs are never returned to the OS.   Each slab is decomposed into fixed size buffers, default 2MB.

Individual evpl threads allocate buffers from the shared slab allocator.   Once a thread allocates a buffer, it keeps it until it terminates and recycles it internally when it becomes unreferenced.  Buffers have a reference count to allow them to be reused when no longer needed.

Individual evpl_iovec I/O vectors are allocated by a thread from its pool of allocated buffers.   Each evpl_iovec holds a reference count on the associated buffer. 

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

If alignment is non-zero, libevpl will guarantee that each vector address is aligned to this amount (eg 64 or 4096b).

max_iovecs indicates the maximum number of iovecs the application is prepared to accept.  If 1, a guaranteed contiguous allocation is performed, but memory may be wasted in the associated buffer to achieve that.   Allowing for more iovecs allows more efficient use of buffers.

Each iovec will represent a chunk of a buffer, with buffers having a default 2MB length.   It must be possible for libevpl to allocate the requested memory in the requested number of iovecs.   E.g., a 4MB allocation into 1 iovec is not possible with default 2MB buffer size.  Similarly. an allocation of 2MB with default 2MB buffer size will never require more than two iovecs.

The `flags` parameter controls the type of allocation:
- `0` (default) - Local allocation, uses non-atomic reference counting. Use this when the iovec will only be accessed from a single thread.
- `EVPL_IOVEC_FLAG_SHARED` - Shared allocation, uses atomic reference counting. Use this when the iovec may be accessed from multiple threads.

**Parameters:**
- `evpl` - Event loop
- `length` - Total bytes to allocate
- `alignment` - Memory alignment requirement in bytes, 0 if none
- `max_iovecs` - Maximum number of iovecs to return
- `flags` - Allocation flags (0 for local, EVPL_IOVEC_FLAG_SHARED for multi-threaded)
- `r_iovec` - [OUT] Array to receive allocated iovecs

**Returns:** Number of iovecs allocated (1 to `max_iovecs`), or -1 on error

**Behavior:**
- The function guarantees the full `length` is allocated across the returned iovecs
- May use multiple iovecs if contiguous memory is unavailable
- Returns -1 only if `max_iovecs` is insufficient to hold the requested `length`
- Each iovec's `length` field indicates how many bytes that iovec provides

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

In some cases, we don't know how much memory we need for an operation in advance.  For instance, if we are marshalling a network message into its byte-serialization to send over a network, we may not know the length of the serialization until after we've completed it.   In this case, rather than serialize into scratch memory and then copy the result into libevpl iovecs, it is more performant to serialize directly into libevpl_iovec.

The two-phase evpl_iovec_reserve + evpl_iovec_commit API allows us to do this.

First, we must have an upper bound on how much space the serialization could possibly consume.  We call evpl_iovec_reserve() to allocate evpl_iovecs in this amount of memory.  If the serialization logic cannot tolerate serializing into vectored memory, we can force a single iovec with max_vec=1.

Then, once we've finished serializing and we know the length consumed, we make a second call to evpl_iovec_commit() to notify libevpl of how much memory we actually consumed.  libevpl will then trim our allocation to the indicated size, leaving the unused memory available for the next allocation request.

It is critical to perform the reserve and commit operations sequentially without returning control to libevpl and without performing any other libevpl operations that might allocate memory independently.

**Parameters:**
- `evpl` - Event loop
- `length` - Bytes to reserve
- `alignment` - Alignment requirement
- `max_vec` - Maximum iovecs
- `r_iovec` - [OUT] Reserved iovecs

**Returns:** Number of iovecs reserved, or -1 on error

**Usage:** Call `evpl_iovec_reserve()` to get writable buffers, fill them with data, then call `evpl_iovec_commit()` to finalize.

---

#### `evpl_iovec_commit`

```c
void evpl_iovec_commit(
    struct evpl       *evpl,
    unsigned int       alignment,
    struct evpl_iovec *iovecs,
    int                niovs);
```

Second half of two-phase iovec allocation.   Application must have immediately previously called evpl_iovec_alloc() and populated the associated iovectors with data.

**Parameters:**
- `evpl` - Event loop
- `alignment` - Alignment used in reserve
- `iovecs` - Array of reserved iovecs
- `niovs` - Number of iovecs

**Note:** Call this after filling data into reserved iovecs. The `length` field should be updated to reflect actual data written.

---

### Reference Counting

#### `evpl_iovec_release`

```c
void evpl_iovec_release(struct evpl_iovec *iovec);
```

Release a reference to an iovec. When the reference count reaches zero, the underlying buffer is freed.

**Parameters:**
- `iovec` - iovec to release

---

#### `evpl_iovec_addref`

```c
void evpl_iovec_addref(struct evpl_iovec *iovec);
```

Add a reference to an iovec. Useful when application desires to keep a reference to iovecs after passing them to a function which takes ownership.

**Parameters:**
- `iovec` - iovec to reference

---

### Accessor Functions

#### `evpl_iovec_data`

```c
static inline void *evpl_iovec_data(const struct evpl_iovec *iovec);
```

Get the data pointer from an iovec.

**Parameters:**
- `iovec` - iovec to query

**Returns:** Pointer to buffer data

---

#### `evpl_iovec_length`

```c
static inline unsigned int evpl_iovec_length(const struct evpl_iovec *iovec);
```

Get the length of valid data in an iovec.

**Parameters:**
- `iovec` - iovec to query

**Returns:** Length in bytes

---

#### `evpl_iovec_set_length`

```c
static inline void evpl_iovec_set_length(
    struct evpl_iovec *iovec,
    unsigned int       length);
```

Set the length of valid data in an iovec.  Generally only safe to reduce length, not increase it.

**Parameters:**
- `iovec` - iovec to modify
- `length` - New length

---

## See Also

- [Binds & Connections API](/api/binds) - Using iovecs with send/receive
- [Architecture](/architecture) - Memory management overview
- [Programming Guide](/programming_guide) - Best practices for buffer management
