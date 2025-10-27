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

Stop a worker thread and wait for it to exit.   Can be called from any thread.

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

Stop all threads in a pool and wait for them to exit.

**Parameters:**
- `threadpool` - Thread pool to destroy