---
title: Threads 
layout: default
parent: API Reference
nav_order: 10
permalink: /api/threading
---

# Threading

libevpl provides an optional abstraction for creating individual threads or pool of threads that execute evpl event loops.

Usage of this component is optional, but it can help to put guard rails against improper event-driven coding.

## Overview

libevpl uses a single-threaded event loop model - each thread runs its own independent event loop. The Threading API simplifies creating and managing multiple worker threads:

- **Worker threads** - Individual threads running event loops
- **Thread pools** - Collections of worker threads
- **Lifecycle callbacks** - Initialize and cleanup per-thread resources
- **Shared listeners** - Multiple threads can share the same listener for load distribution

## Functions

### Single Thread Management

#### `evpl_thread_create`

```c

typedef void *(*evpl_thread_init_callback_t)(
    struct evpl *evpl,
    void        *private_data);

typedef void (*evpl_thread_shutdown_callback_t)(
    struct evpl *evpl,
    void        *private_data);

struct evpl_thread *evpl_thread_create(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data);
```

Create and start a worker thread that runs an event loop.

The init callback will be made from inside the thread after it has been created.

The shutdown callback will be made from inside the thread before it exits.

All application code is meant to run inside event handlers directly or indirectly instigated by the init callback.

**Parameters:**
- `config` - Thread configuration (or `NULL` for defaults)
- `init_function` - Initialization callback
- `shutdown_function` - Shutdown callback
- `private_data` - User context

**Returns:** Thread handle, or `NULL` on failure

#### `evpl_thread_destroy`

```c
void evpl_thread_destroy(struct evpl_thread *thread);
```

Native callers outside reactor callbacks can stop a worker and wait for exit.
An SPDK-thread caller cannot block and this function requests detached shutdown;
use `evpl_thread_destroy_async()` when completion matters. Reactor callbacks
without a current SPDK thread must also use the explicit async API.

**Parameters:**
- `thread` - Thread to destroy

---

### Thread Pool Management

#### `evpl_threadpool_create`

```c
struct evpl_threadpool *evpl_threadpool_create(
    struct evpl_thread_config      *config,
    int                             nthreads,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data);
```

Create a pool of worker threads, each behaving the same as the single example above.

**Parameters:**
- `config` - Thread configuration (or `NULL` for defaults)
- `nthreads` - Number of threads to create
- `init_function` - Initialization callback (called in each thread)
- `shutdown_function` - Shutdown callback (called in each thread)
- `private_data` - User context (same value passed to all threads)

**Returns:** Thread pool handle, or `NULL` on failure

---

#### `evpl_threadpool_destroy`

```c
void evpl_threadpool_destroy(struct evpl_threadpool *threadpool);
```

Stop all threads in a pool. Native callers wait; SPDK callers must use
`evpl_threadpool_destroy_async()` to observe completed guest cleanup.

**Parameters:**
- `threadpool` - Thread pool to destroy
### SPDK and mixed execution

See [SPDK embedding](/api/spdk) for per-context backend selection, borrowed host
threads, nonblocking listener/worker lifecycle, and explicit global cleanup.
`evpl_thread_create_async()` never waits; the init callback signals readiness.
Thread and pool configurations are consumed by creation, matching `evpl_create()`.
Async completion callbacks run on the completing SPDK worker or a native join
helper. They do not promise that the host scheduler has reaped the SPDK thread.
