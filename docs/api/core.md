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

---


---

## See Also

- [Configuration API](/api/config) - Global and thread-local configuration
- [Binds & Connections API](/api/binds) - Creating and managing connections
- [Threading API](/api/threading) - Thread pools and thread management
- [Architecture Guide](/architecture) - Understanding event loops and protocols
