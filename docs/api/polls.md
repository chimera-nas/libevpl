---
title: Polls
layout: default
parent: Core
nav_order: 8
permalink: /api/polls
---

# Polls

Provides per-thread poll callbacks that run while the event loop is in poll
(busy-spin) mode, plus optional enter/exit hooks to set up or tear down
state when the thread transitions between polling and event-driven waiting.

For background on libevpl's hybrid event/poll model, see the
[Architecture](/architecture) page.

## Overview

When an event loop is in poll mode it spins on the CPU instead of sleeping
in `epoll_wait()`/`kqueue()`, calling each registered poll callback every
iteration. The thread enters poll mode automatically when there is recent
activity (events, doorbells, etc.) and exits after `spin_ns` of idleness,
falling back to system-call-based waiting.

**Use cases:**
- Draining a lock-protected work queue without paying a syscall on every
  request when traffic is bursty.
- Polling completion queues for backends that do not generate epoll events
  (RDMA CQ, io_uring CQE, VFIO-NVMe, libaio, XLIO).
- Pinning a worker thread on-CPU for a configured duration after the last
  request, in anticipation of more work.

**Relation to doorbells:** a doorbell ring counts as activity, so it
re-enters poll mode automatically. Combining a doorbell (for the wake) with
a poll callback (for the spin-mode drain) gives a thread that wakes on
demand and then briefly polls before sleeping again.

## Functions

### `evpl_add_poll`

```c
struct evpl_poll *
evpl_add_poll(
    struct evpl               *evpl,
    evpl_poll_enter_callback_t enter_callback,
    evpl_poll_exit_callback_t  exit_callback,
    evpl_poll_callback_t       callback,
    void                      *private_data);
```

Register a poll callback on the event loop.

**Parameters:**
- `evpl` - Event loop to attach to.
- `enter_callback` - Optional. Invoked once when the event loop transitions
  from event-driven waiting into poll mode. Pass `NULL` if not needed.
- `exit_callback` - Optional. Invoked once when the event loop transitions
  out of poll mode and back to event-driven waiting. Pass `NULL` if not
  needed.
- `callback` - Required. Invoked on every poll iteration while the thread
  is in poll mode.
- `private_data` - Opaque pointer passed back to each callback.

**Returns:** Handle for the registration, used with `evpl_remove_poll`.

**Thread Safety:** Must be called from the thread that owns `evpl`.

**Behavior notes:**
- Poll callbacks must be fast and non-blocking — they run on every spin
  iteration.
- Registering a poll callback does not by itself force the thread into
  poll mode; that decision is governed by activity and the global
  `poll_mode` / `spin_ns` / `poll_iterations` thread config.

---

### `evpl_remove_poll`

```c
void
evpl_remove_poll(
    struct evpl      *evpl,
    struct evpl_poll *poll);
```

Detach a previously registered poll callback.

**Parameters:**
- `evpl` - Event loop the poll was attached to.
- `poll` - Handle returned by `evpl_add_poll`.

**Thread Safety:** Must be called from the thread that owns `evpl`.

---

## Callback Signatures

```c
typedef void (*evpl_poll_enter_callback_t)(
    struct evpl *evpl,
    void        *private_data);

typedef void (*evpl_poll_exit_callback_t)(
    struct evpl *evpl,
    void        *private_data);

typedef void (*evpl_poll_callback_t)(
    struct evpl *evpl,
    void        *private_data);
```

All callbacks receive the owning event loop and the `private_data` pointer
supplied at registration. None of them return a value; they run on the
thread that owns `evpl`.

---

## See Also

- [Configuration API](/api/config) - `poll_mode`, `spin_ns`, `poll_iterations`
- [Doorbell API](/api/doorbells) - Inter-thread wakeups (often paired with polls)
- [Architecture](/architecture) - Hybrid event/poll model
