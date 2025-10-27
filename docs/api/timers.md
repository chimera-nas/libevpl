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
    uint64_t              interval;   // Interval in microseconds
    struct timespec       deadline;   // Next expiration time
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

Add a timer to the event loop.

**Parameters:**
- `evpl` - Event loop
- `timer` - Timer structure (user-allocated, must remain valid)
- `callback` - Function to call when timer expires
- `interval_us` - Interval in microseconds (must be > 0)

**Behavior:**
- Timers fire repeatedly at the specified interval
- The timer is automatically re-scheduled after each callback invocation
- To stop a timer, call `evpl_remove_timer()` from within the callback or elsewhere
- For one-shot behavior, remove the timer in its callback

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
