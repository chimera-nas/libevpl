---
title: Timers
layout: default
parent: Core
nav_order: 5
permalink: /api/timers
---

# Timers

Provides scheduled callback execution integrated with the event loop.

## Types

### `struct evpl_timer`

Structure representing a timer (user-allocated, must remain valid while in use):

```c
struct evpl_timer {
    evpl_timer_callback_t callback;   // Callback function
    uint64_t              interval;   // Interval (periodic) or delay (one-shot), microseconds
    struct timespec       deadline;   // Next expiration time
    int                   oneshot;    // Non-zero if the timer fires only once
};
```

### `evpl_timer_callback_t`

```c
typedef void (*evpl_timer_callback_t)(
    struct evpl       *evpl,
    struct evpl_timer *timer);
```

Callback invoked when a timer expires.

**Parameters:**
- `evpl` - Event loop
- `timer` - The expired timer

## Functions

### `evpl_add_timer`

```c
void evpl_add_timer(
    struct evpl          *evpl,
    struct evpl_timer    *timer,
    evpl_timer_callback_t callback,
    uint64_t              interval_us);
```

Add a periodic timer to the event loop.

**Parameters:**
- `evpl` - Event loop
- `timer` - Timer structure (user-allocated, must remain valid)
- `callback` - Function to call when timer expires
- `interval_us` - Interval in microseconds (must be > 0)

**Behavior:**
- Timers fire repeatedly at the specified interval
- The timer is automatically re-scheduled after each callback invocation
- To stop a timer, call `evpl_remove_timer()` from within the callback or elsewhere
- Because the timer is re-armed immediately after the callback returns, the
  callback must **not** free the timer. For fire-once semantics use
  `evpl_add_oneshot_timer()` instead.

---

### `evpl_add_oneshot_timer`

```c
void evpl_add_oneshot_timer(
    struct evpl          *evpl,
    struct evpl_timer    *timer,
    evpl_timer_callback_t callback,
    uint64_t              delay_us);
```

Add a one-shot timer that fires exactly once.

**Parameters:**
- `evpl` - Event loop
- `timer` - Timer structure (user-allocated, must remain valid until it fires or is removed)
- `callback` - Function to call when the timer expires
- `delay_us` - Delay before firing, in microseconds

**Behavior:**
- Fires once, `delay_us` microseconds after being added, and is then removed
  from the event loop automatically (it is not re-armed)
- The timer is removed from the timer set **before** the callback runs, so the
  callback may safely free the timer or re-arm it (via `evpl_add_timer()` or
  `evpl_add_oneshot_timer()`)
- Calling `evpl_remove_timer()` on a one-shot that has already fired is a
  harmless no-op; calling it before the timer fires cancels it

---

### `evpl_remove_timer`

```c
void evpl_remove_timer(
    struct evpl       *evpl,
    struct evpl_timer *timer);
```

Remove a timer from the event loop.

**Parameters:**
- `evpl` - Event loop
- `timer` - Timer to remove

**Note:** Safe to call even if the timer is not currently active.

---

## See Also

- [Deferrals API](/api/deferrals) - Same-iteration task scheduling
- [Doorbells API](/api/doorbells) - Cross-thread notifications
- [Core API](/api/core) - Event loop management
- [Architecture](/architecture) - Understanding event loops
