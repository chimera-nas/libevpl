---
layout: default
title: SPDK embedding
permalink: /api/spdk
---

# SPDK embedding (Linux)

libevpl can run inside an existing SPDK application. The host initializes SPDK,
loads the bdev and socket modules it needs, and owns reactor scheduling and
shutdown. libevpl does not replace the host scheduler or poll an SPDK thread
itself. SPDK 25.09 or newer with shared libraries and CMake 3.24 or newer are
required. The tested socket
implementation is POSIX; other implementations must be loaded and supported by
the host before selecting them with `evpl_global_config_set_spdk_sock_impl()`.

## Selecting an execution backend

The global `core_mech` is a default. `evpl_thread_config_set_core_mech()` overrides
it for one context or worker. `EVPL_CORE_MECH_INHERIT` preserves that default;
`EVPL_CORE_MECH_DEFAULT` explicitly chooses the native platform backend. Native
and SPDK contexts may coexist. Ordinary native execution does not initialize
SPDK or change its slab alignment just because SPDK was compiled in.

Call `evpl_create()` on an existing SPDK thread with an SPDK context configuration
to attach libevpl there. The context borrows the host thread:

```c
/* Run in a message or callback on the application's existing SPDK thread. */
struct evpl_thread_config *cfg = evpl_thread_config_init();
evpl_thread_config_set_core_mech(cfg, EVPL_CORE_MECH_SPDK);
struct evpl *guest = evpl_create(cfg); /* consumes cfg */
```

An application using SPDK reactors attaches to a logical SPDK thread scheduled
by those reactors. Pollers and I/O channels belong to that logical thread;
there is no separate reactor-level evpl context. The host may migrate the
thread between reactors, provided execution remains serialized. LOCAL buffers
follow the logical thread, not its current OS thread. Other enabled providers
may impose their own affinity restrictions; honor those when scheduling.

`evpl_thread_create_async()` with an SPDK configuration instead creates an owned
logical SPDK worker. The host must schedule newly created SPDK threads. The init
callback is the readiness notification. CPU masks constrain allowed placement;
they do not create reactors. This API does not create an OS thread that drives
SPDK. The application continues to own the runtime.

Configurations are consumed by context, thread, listener, and thread-pool
creation. A pool copies its configuration for each worker before consuming the
template. For a listener that needs a different backend from the global default,
use `evpl_listener_create_config()` explicitly.

## Progress and ownership

Each guest registers a nonblocking SPDK poller. In interrupt mode it registers
its epoll descriptor and a timerfd for deadlines. Native fd/timer machinery is
shared, but reactor sleeping and placement belong to SPDK. Socket progress has
its own SPDK poller and is independent of the native `poll_mode` preference.

All context operations run on the owning logical thread. Use the host's
`spdk_thread_send_msg()` to enter it from another thread. Deferrals, timers, and
fd readiness changes automatically wake an idle guest. `evpl_kick()` remains
available as an explicit wakeup. Do not call `evpl_run()` or `evpl_stop()` on an
externally driven context.

## Nonblocking lifecycle

Use `evpl_listen_async()` from reactor code. Its callback runs on the listener
worker; validation failures may complete inline. Endpoint resolution still uses
the existing resolver, so prepare/cache endpoints before latency-sensitive work.
The synchronous `evpl_listen()` rejects calls on an SPDK thread with
`EWOULDBLOCK`. Other synchronous listen errors retain the existing -1 result.

Use `evpl_destroy_async(guest, done, arg)` on the owner thread to detach a borrowed
context. Stop initiating application work first and close application-owned block
queues/devices. Destruction closes binds and drains outstanding block operations
and deferrals while yielding to the host. Completion runs after libevpl resources
are released; the borrowed SPDK thread remains alive. Do not use the context after
completion. Synchronous `evpl_destroy()` is only valid for an already quiescent
SPDK context outside an evpl callback. Native `evpl_destroy_async()` is a synchronous
convenience and must likewise be called outside a running callback.

`evpl_thread_destroy_async()`, `evpl_threadpool_destroy_async()`, and
`evpl_listener_destroy_async()` consume their handles. They notify completion after
guest cleanup. SPDK callbacks run on the completing worker; native callbacks run
on a join helper. Marshal to the desired application thread as necessary.
Completion does not imply that the host scheduler has reaped an exited SPDK
worker. Never block a reactor waiting for a worker on that reactor. Use explicit
async APIs even in reactor callbacks that have no current `spdk_thread`.

A worker's shutdown callback is a cleanup hook, not final completion. Async block
closes started there are drained before guest destruction completes. Queues retain
metrics/device state while their outstanding operations finish; device close waits
for all queues to be closed. Buffer lifetimes still extend through I/O completion.

Finally, after all contexts and application-held buffers are gone, call
`evpl_cleanup()` **before** `spdk_env_fini()` or `spdk_app_fini()`. This final,
process-wide operation unregisters slab memory and is idempotent, including the
later atexit fallback. Serialize it with all libevpl users and do not use libevpl
afterward. It never finalizes the host's SPDK runtime.

## Block devices and validation

SPDK device events are delivered on the opener thread through
`evpl_block_set_event_callback()`. Resize publishes size atomically. Removal
rejects subsequent submissions and retries with `ENODEV`; in-flight I/O may also
fail. Close queues on their owner threads and then close the device on its opener.
Do not open new queues once closure starts.

Requests support at most 64 iovecs and at most the configured buffer size,
including alignment-induced bounce. Devices with metadata or unsupported geometry
are rejected. Sync writes and flushes fail with `ENOTSUP` if a write cache cannot
be flushed; a device without a write cache may complete flush as a no-op.

CI requires SPDK in the devcontainer and tests ordinary native configurations too.
SPDK coverage includes a real application host, polling and interrupt modes,
borrowed/owned lifecycle, migration, configured workers, multi-reactor device
events, bounce/retry fault injection, and durability capability failures. ASan and
LeakSanitizer remain enabled in Debug. Physical NVMe DMA and socket implementations
other than POSIX still require hardware/provider-specific validation.
