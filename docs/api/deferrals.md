---
title: Deferrals
layout: default
parent: Core
nav_order: 6
permalink: /api/deferrals
---

# Deferrals

Provides a mechanism to schedule callbacks for execution at the end of the current event loop iteration, before it might block waiting for more activity.

All operations on a deferral must be performed by the thread that owns the associated evpl context. A deferral is a mechanism for a thread to schedule work for itself to do later. For cross-thread communication, use [doorbells](/api/doorbells) instead.

## Overview

Deferrals are useful for:
- **Coalescing operations** - Batch multiple flush requests into one
- **Avoiding deep recursion** - Break up recursive callback chains
- **Deferred cleanup** - Schedule resource cleanup after processing

Unlike timers, deferrals fire after all events in the current iteration are processed, but before the event loop blocks waiting for new events.

## Types

**User allocation:** Deferrals are user-allocated structures that must remain valid while in use.

### `deferral_callback_t`

```c
typedef void (*deferral_callback_t)(
    struct evpl *evpl,
    void        *private_data);
```

Callback invoked when a deferral fires.

**Parameters:**
- `evpl` - Event loop
- `private_data` - User-provided context

## Functions

### `evpl_deferral_init`

```c
void evpl_deferral_init(
    struct evpl_deferral *deferral,
    deferral_callback_t   callback,
    void                 *private_data);
```

Initialize a deferral structure.

**Parameters:**
- `deferral` - Deferral structure to initialize
- `callback` - Function to call when deferral fires
- `private_data` - User context passed to callback

**Note:** Must be called before using a deferral.

---

### `evpl_defer`

```c
void evpl_defer(
    struct evpl          *evpl,
    struct evpl_deferral *deferral);
```

Schedule a deferral to fire at the end of the current event loop iteration.

**Parameters:**
- `evpl` - Event loop
- `deferral` - Deferral to schedule

**Behavior:**
- Callback is invoked at the end of the event loop iteration
- Multiple calls to `evpl_defer()` with the same deferral in one iteration coalesce into a single callback
- Safe to call redundantly - coalescing makes this cheap

---


## See Also

- [Timers API](/api/timers) - Scheduled callbacks
- [Doorbells API](/api/doorbells) - Cross-thread communication
- [Core API](/api/core) - Event loop management
- [Architecture](/architecture) - Understanding event loops
