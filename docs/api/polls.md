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
- Keeping a thread on-CPU for as long as it has work outstanding that can
  only be reaped by polling (see [`evpl_poll_pin`](#evpl_poll_pin)).

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

### `evpl_poll_pin`

```c
void
evpl_poll_pin(
    struct evpl *evpl);
```

Pin the calling thread into poll mode. While the (refcounted) pin count is
non-zero the event loop will not fall back to event-driven waiting after
`spin_ns` of idleness — it keeps spinning and calling poll callbacks.

Use this when the thread has work outstanding that can **only** be observed
by polling — for example a request handed to another thread whose completion
this thread reaps from a polled ring (RDMA CQ, io_uring CQE, VFIO-NVMe). If
the loop were allowed to sleep in `epoll_wait()`, that completion would never
wake it and the work would stall.

**Parameters:**
- `evpl` - Event loop to pin.

**Thread Safety:** Must be called from the thread that owns `evpl`.

**Behavior notes:**
- Refcounted, so multiple independent sources of outstanding work on one
  thread compose correctly. Each `evpl_poll_pin` must be balanced by exactly
  one `evpl_poll_unpin`.
- Pinning forces poll mode regardless of activity; it does not register a
  poll callback. Pair it with `evpl_add_poll` to actually drain the polled
  resource each iteration.

---

### `evpl_poll_unpin`

```c
void
evpl_poll_unpin(
    struct evpl *evpl);
```

Release one poll-mode pin taken with `evpl_poll_pin`. When the pin count
returns to zero the loop is again free to fall back to event-driven waiting
after `spin_ns` of idleness.

**Parameters:**
- `evpl` - Event loop to unpin.

**Thread Safety:** Must be called from the thread that owns `evpl`.

---

### `evpl_activity`

```c
void
evpl_activity(
    struct evpl *evpl);
```

Mark that the loop did useful work this iteration. This resets the idleness
timer that governs the fall-back from poll mode to event-driven waiting, so
a poll-mode thread does not drop out of poll mode after `spin_ns` of
*apparent* inactivity when it is in fact making progress.

Call it after a poll callback services a polled resource (e.g. drains entries
from a ring). Sources that already feed the event loop — sockets, doorbells,
timers — record activity on their own; `evpl_activity` is for work discovered
by polling that the loop would otherwise not see as activity.

**Parameters:**
- `evpl` - Event loop that did work.

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
