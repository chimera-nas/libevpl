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
- **Native wakeups**: eventfd on Linux, a pipe on macOS, and IOCP packets on Windows
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

Detach and revoke the receiver. Outstanding sender handles remain valid, but
subsequent signals return `ECANCELED`. Queued notifications can be discarded.
Removal may run inside the callback, and receiver storage may be freed once
removal returns. Loop destruction also removes receivers; their storage must
survive until removal or loop destruction returns.

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

**Thread Safety:** Safe to call from another thread only while the caller guarantees that the receiver remains attached and alive. Use owned sender handles when producers can outlive the receiver.

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

**Returns:** A POSIX readiness descriptor (eventfd on Linux). On Windows, returns `-1` and sets `errno` to `ENOTSUP`. Use `evpl_doorbell_signal()` to wake an IOCP loop.

**Note:** Most applications don't need this. Used for integrating with external event loops.

---


## Owned sender handles

```c
struct evpl_doorbell_sender *evpl_doorbell_sender(struct evpl_doorbell *receiver);
void evpl_doorbell_sender_retain(struct evpl_doorbell_sender *sender);
void evpl_doorbell_sender_release(struct evpl_doorbell_sender *sender);
int evpl_doorbell_signal(struct evpl_doorbell_sender *sender);
```

Acquire a sender on the receiver's loop thread before sharing it. Each
independent owner holds a reference and releases it when finished. Retain,
release, and signal are thread-safe while the caller owns a reference.

Signal returns zero on success, `ECANCELED` after receiver removal, or another
error code. Signals coalesce; success acknowledges a wakeup request, not that
application work was consumed. The callback runs on the receiver's loop thread.

A sender retains only the doorbell control object. It does not retain the loop,
receiver storage, or an application work queue. Coordinate work-queue shutdown
separately, and publish queued work before signaling.

## See Also

- [Threading API]({{ '/api/threading' | relative_url }}) - Thread pools and worker threads
- [Deferrals API]({{ '/api/deferrals' | relative_url }}) - Same-thread deferred execution
- [Core API]({{ '/api/core' | relative_url }}) - Event loop management
- [Architecture]({{ '/architecture' | relative_url }}) - Threading model
- [Programming Guide]({{ '/programming_guide' | relative_url }}) - Multi-threading patterns
