---
title: Memory Management
layout: default
nav_order: 3
parent: API
permalink: /api/memory
---

A key feature of libevpl is the ability to perform network and block operations using efficient hardware acceleration and without memory copies.   

Many accelerated APIs require memory to be **registered** with the hardware before it can be used.  This registration operation is expensive and therefore should not be performed in the hot path.   To facilitate this, libevpl represents memory in a vectorized fashion using the following data structure:

```c
struct evpl_iovec
{
    void            *data;
    unsigned int     length;
    unsigned int     __private1; /* do not touch */
    unsigned long    __private2; /* do not touch */
};
```

The private fields are used internally by libevpl to track the memory registration state.  They should not be modified by the application.

The libevpl APIs for sending and receiving data will generally accept and present data in the form of these iovecs.

Memory may be allocated as follows:

```c
int evpl_iovec_alloc(
    struct evpl *evpl,
    unsigned int length,
    unsigned int alignment,
    unsigned int max_iovecs,
    struct evpl_iovec *r_iovec);
```

for example:

```c
struct evpl_iovec iovec[8];

int niov = evpl_iovec_alloc(evpl, 128*1024, 4096, 8, iovec);
```

Here we are allocating 128KB of memory, guaranteed to be page aligned, and represented by up to 8 iovecs.  The returned niov value indicates the number of iovecs actually allocated.

Internally, libevpl manages memory using buffers, and an iovec is a slice of a buffer.  Therefore, an iovec may not be larger than the evpl buffer size, which by default is 1MB.   max_iovecs must be large enough to account for this.   If we do not care about alignment, we can specify zero for alignment.   

Each iovec represents a reference to the underlying memory.   Generally speaking, if the libevpl API presents an iovec to the application, it is handing off a reference.   If the application provides an iovec to the API, it is also handing over a reference.

If needed, additional references can be created by calling:

```c
evpl_iovec_addref(struct evpl_iovec *iovec);
```

This could be used, for example, if the application wishes to repeatedly reuse the same buffer data for multiple send operations.

References may be released as follows:

```c
evpl_iovec_release(struct evpl_iovec *iovec);
```

When the last reference is released, the memory will be freed and recycled internally.   References are tracked using an atomic variable so that they can be safely exchanged between threads.






