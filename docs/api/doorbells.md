---
title: Doorbells
layout: default
parent: Core
nav_order: 7
permalink: /api/doorbells
---

# Doorbells

Provides thread-safe inter-thread communication for waking event loops and passing notifications between threads.

For performing asynchronous work within a single thread, use deferrals instead.


## Overview

Doorbells solve the problem of communicating between threads in a multi-threaded server:

- **Thread-safe signaling**: Wake another thread's event loop
- **Non-blocking**: Caller doesn't wait for receiver to process
- **Eventfd-based**: Efficient kernel mechanism (Linux)
- **Integrates with event loop**: Delivered as events

**Use cases:**
- Work distribution across threads
- Shutdown signaling
- Cross-thread notifications

## Functions

### `evpl_add_doorbell`

```c
void evpl_add_doorbell(
    struct evpl             *evpl,
    struct evpl_doorbell    *doorbell,
    evpl_doorbell_callback_t callback);
```

Attach a doorbell to an event loop.

**Parameters:**
- `evpl` - Event loop to attach to (the receiver)
- `doorbell` - Doorbell structure (user-allocated)
- `callback` - Function to call when doorbell is rung

**Thread Safety:** Must be called from the thread that owns `evpl`.

---

### `evpl_remove_doorbell`

```c
void evpl_remove_doorbell(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell);
```

Detach a doorbell from an event loop.

**Parameters:**
- `evpl` - Event loop
- `doorbell` - Doorbell to remove

**Thread Safety:** Must be called from the thread that owns `evpl`.

---

### `evpl_ring_doorbell`

```c
void evpl_ring_doorbell(struct evpl_doorbell *doorbell);
```

Ring a doorbell, waking the target thread.

**Parameters:**
- `doorbell` - Doorbell to ring

**Thread Safety:** **Safe to call from any thread.** This is the key function for inter-thread communication.

**Behavior:**
- Wakes the target event loop if it's sleeping
- Callback is invoked in the target thread during its next event loop iteration
- Multiple rings before callback runs are coalesced into one notification

---

### `evpl_doorbell_fd`

```c
int evpl_doorbell_fd(struct evpl_doorbell *doorbell);
```

Get the file descriptor associated with a doorbell (for advanced use cases).

**Parameters:**
- `doorbell` - Doorbell to query

**Returns:** File descriptor (eventfd on Linux)

**Note:** Most applications don't need this. Used for integrating with external event loops.

---


## See Also

- [Threading API](/api/threading) - Thread pools and worker threads
- [Deferrals API](/api/deferrals) - Same-thread deferred execution
- [Core API](/api/core) - Event loop management
- [Architecture](/architecture) - Threading model
- [Programming Guide](/programming_guide) - Multi-threading patterns
