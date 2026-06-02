---
title: Core
layout: default
parent: API Reference
nav_order: 1
permalink: /api/core
---

# Core

Provides fundamental functions for initializing libevpl, creating and managing event loops, and querying protocol information.

### Initialization

#### `evpl_init`

```c
void evpl_init(struct evpl_global_config *global_config);
```

Initialize libevpl globally. Must be called once before creating any event loops, typically at program startup.

Takes ownership of global_config, if provided.

**Parameters:**
- `global_config` - Global configuration (or `NULL` for defaults)

---

### Event Loop Management

#### `evpl_create`

```c
struct evpl *evpl_create(struct evpl_thread_config *config);
```

Create a new event loop context for the current thread.

All evpl operations on an 'evpl' context must be called from the same thread.

**Parameters:**
- `config` - Thread-specific configuration (copied, not owned), or `NULL` for defaults

**Note:** The config parameter, if provided, is copied into the event loop. You can safely free or reuse the config structure after calling this function.

**Returns:** Event loop handle, or `NULL` on failure

**Thread Safety:** Each thread creates its own event loop.

#### `evpl_destroy`

```c
void evpl_destroy(struct evpl *evpl);
```

Destroy an event loop and free all resources. 

**Parameters:**
- `evpl` - Event loop to destroy

**Thread Safety:** Must be called from the same thread that created the event loop.

#### `evpl_continue`

```c
void evpl_continue(struct evpl *evpl);
```

Process one iteration of the event loop.  Useful if other processing wants to be done outside of the event loop, but out-of-loop logic is not idiomatic.

**Parameters:**
- `evpl` - Event loop to iterate

#### `evpl_run`

```c
void evpl_run(struct evpl *evpl);
```

Run the event loop indefinitely until `evpl_stop()` is called. Equivalent to an infinite loop calling `evpl_continue()`.

**Parameters:**
- `evpl` - Event loop to run

#### `evpl_stop`

```c
void evpl_stop(struct evpl *evpl);
```

Stop a running event loop. Causes `evpl_run()` to return.  

**Parameters:**
- `evpl` - Event loop to stop

**Thread Safety:** Can be called from any thread

#### `evpl_set_loop_hooks`

```c
typedef void (*evpl_loop_callback_t)(struct evpl *evpl, void *private_data);

struct evpl_loop_hooks {
    evpl_loop_callback_t iteration_end; /* end of every evpl_continue() pass */
    evpl_loop_callback_t pre_wait;      /* before the core wait (may block)  */
    evpl_loop_callback_t post_wait;     /* after the core wait returns       */
    void                *private_data;
};

void evpl_set_loop_hooks(struct evpl *evpl, const struct evpl_loop_hooks *hooks);
```

Install (or replace) a set of callbacks that `evpl_continue()` invokes at fixed points in each iteration of the loop, so an application can interleave per-iteration bookkeeping with the loop without taking it over. Passing `NULL` clears any previously installed hooks.

The hooks are copied into the event loop. Each member is optional — a `NULL` member is skipped — so there is no cost unless a hook is set, and applications that never call this function are unaffected.

| Hook | Invoked |
| --- | --- |
| `iteration_end` | At the end of every `evpl_continue()` pass. |
| `pre_wait` | Immediately before the (possibly blocking) core wait. |
| `post_wait` | Immediately after the core wait returns. |

**Parameters:**
- `evpl` - Event loop to install the hooks on
- `hooks` - Hook set to install (copied), or `NULL` to clear

**Thread Safety:** Must be called from the same thread that owns the event loop.

**Example — userspace-RCU (QSBR):** a reader thread maps `iteration_end` to `rcu_quiescent_state()` and brackets the core wait with `pre_wait` → `rcu_thread_offline()` and `post_wait` → `rcu_thread_online()`, so a thread asleep in the wait announces no quiescent states yet does not hold up RCU grace periods for other threads.

---

### Metrics

libevpl maintains its own [Prometheus](https://prometheus.io/) metrics (for
example, allocator slab and buffer counters and gauges named `evpl_allocator_*`)
on an internal registry. These are registered automatically during
initialization — no caller setup is required.

#### `evpl_metrics_scrape`

```c
int evpl_metrics_scrape(char *buffer, int buffer_size);
```

Serialize libevpl's metrics into `buffer` in the Prometheus text exposition
format (version 0.0.4). Triggers libevpl initialization if it has not happened
yet, so it is safe to call before `evpl_init()`.

Embedders typically expose these alongside their own metrics by calling this
function and appending the result to their own exposition output (the
`evpl_*` metric names are disjoint from typical application names, so the
concatenation remains a valid single page).

**Parameters:**
- `buffer` - Destination buffer for the serialized metrics
- `buffer_size` - Capacity of `buffer` in bytes

**Returns:** Number of bytes written, or `-1` if the buffer was too small

**Thread Safety:** Can be called from any thread

---

## See Also

- [Configuration API](/api/config) - Global and thread-local configuration
- [Binds & Connections API](/api/binds) - Creating and managing connections
- [Threading API](/api/threading) - Thread pools and thread management
- [Architecture Guide](/architecture) - Understanding event loops and protocols
