// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once
#include "evpl/evpl_export.h"

#include <time.h>
#include <stdint.h>

#ifndef EVPL_INCLUDED
#error "Do not include evpl_core.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

enum evpl_framework_id {
    EVPL_FRAMEWORK_RDMACM    = 0,
    EVPL_FRAMEWORK_XLIO      = 1,
    EVPL_FRAMEWORK_IO_URING  = 2,
    EVPL_FRAMEWORK_VFIO      = 3,
    EVPL_FRAMEWORK_TLS       = 4,
    EVPL_FRAMEWORK_TCP_RDMA  = 5,
    EVPL_FRAMEWORK_LIBAIO    = 6,
    EVPL_FRAMEWORK_INPROC    = 7,
    EVPL_FRAMEWORK_LIBFABRIC = 8,
    EVPL_FRAMEWORK_SPDK      = 9,
    EVPL_NUM_FRAMEWORK       = 10
};

enum evpl_protocol_id {
    EVPL_DATAGRAM_SOCKET_UDP    = 0,
    EVPL_DATAGRAM_RDMACM_RC     = 1,
    EVPL_DATAGRAM_RDMACM_UD     = 2,
    EVPL_STREAM_SOCKET_TCP      = 3,
    EVPL_STREAM_XLIO_TCP        = 4,
    EVPL_STREAM_IO_URING_TCP    = 5,
    EVPL_STREAM_RDMACM_RC       = 6,
    EVPL_STREAM_SOCKET_TLS      = 7,
    EVPL_DATAGRAM_TCP_RDMA      = 8,
    EVPL_STREAM_SOCKET_UNIX     = 9,
    EVPL_STREAM_INPROC          = 10,
    EVPL_DATAGRAM_INPROC        = 11,
    EVPL_STREAM_LIBFABRIC_MSG   = 12,
    EVPL_DATAGRAM_LIBFABRIC_MSG = 13,
    EVPL_DATAGRAM_LIBFABRIC_RDM = 14,
    EVPL_STREAM_SPDK_TCP        = 15,
    EVPL_NUM_PROTO              = 16
};

enum evpl_block_protocol_id {
    EVPL_BLOCK_PROTOCOL_IO_URING      = 0,
    EVPL_BLOCK_PROTOCOL_VFIO          = 1,
    EVPL_BLOCK_PROTOCOL_LIBAIO        = 2,
    EVPL_BLOCK_PROTOCOL_IO_URING_NVME = 3,
    EVPL_BLOCK_PROTOCOL_PREAD         = 4,
    EVPL_BLOCK_PROTOCOL_SPDK_BDEV     = 5,
    EVPL_NUM_BLOCK_PROTOCOL           = 6
};

struct evpl;
struct evpl_global_config;
struct evpl_thread_config;

/* Final process cleanup, after all contexts and application-held buffers
 * have been released and before host SPDK environment teardown. Idempotent;
 * do not use libevpl again afterward. Host must serialize this with all users. */
EVPL_API void evpl_cleanup(
    void);

typedef void (*evpl_completion_t)(
    void *private_data);

/* Destroy on the owner thread. SPDK teardown yields to the host until I/O
 * and deferrals drain; callback runs after guest resources are gone, without
 * exiting a borrowed SPDK thread. Native destruction completes synchronously.
 * After requesting destruction, only already-outstanding cleanup may use evpl. */
EVPL_API void evpl_destroy_async(
    struct evpl      *evpl,
    evpl_completion_t callback,
    void             *private_data);

EVPL_API void evpl_init(
    struct evpl_global_config *global_config);

/* Serialize libevpl's own metrics into buffer in Prometheus text
 * exposition format (version 0.0.4).  Returns the number of bytes
 * written, or -1 if the buffer was too small.  Safe to call from any
 * thread; triggers evpl initialization if it has not happened yet.
 */
EVPL_API int evpl_metrics_scrape(
    char *buffer,
    int   buffer_size);

EVPL_API struct evpl * evpl_create(
    struct evpl_thread_config *config);

EVPL_API void
evpl_get_hf_monotonic_time(
    struct evpl     *evpl,
    struct timespec *ts);

/*
 * Move the virtual clock forward by ns nanoseconds, and read it.
 *
 * Only meaningful when evpl_global_config_set_virtual_clock() was set before
 * evpl_init(); calling either otherwise is a hard error rather than a silent
 * no-op, because a test that believed it was advancing time and was not would
 * pass for the wrong reason.
 *
 * Advancing does not itself run anything: it makes deadlines due, and the
 * next evpl_continue() on a thread dispatches whatever became due on it.
 */
EVPL_API void
evpl_virtual_clock_advance(
    uint64_t ns);

EVPL_API uint64_t
evpl_virtual_clock_now(
    void);

EVPL_API void evpl_destroy(
    struct evpl *evpl);

/*
 * Run exactly one iteration of the event loop.  Returns an approximate count
 * of work items handled this pass (timers fired, events dispatched, deferrals
 * run, poll-callback activity); 0 means the pass was idle.  External loops
 * embedding evpl (e.g. an SPDK reactor poller) use the return value to report
 * busy/idle to their own scheduler.
 */
EVPL_API int evpl_continue(
    struct evpl *evpl);

EVPL_API void evpl_run(
    struct evpl *evpl);

/*
 * Wake this evpl so its next pump re-evaluates pending work.  Required when
 * code sharing the thread outside of an evpl callback (e.g. another SPDK
 * poller on the same spdk_thread) mutates evpl state such as queuing a send;
 * without it an external host loop may sleep without knowing the evpl has
 * work.  Safe from any thread; idempotent.
 */
EVPL_API void evpl_kick(
    struct evpl *evpl);

typedef void (*evpl_loop_callback_t)(
    struct evpl *evpl,
    void        *private_data);

/*
 * Per-thread event-loop hooks, invoked by evpl_continue() at fixed points so an
 * application can interleave per-iteration bookkeeping with the loop.  All
 * members are optional (NULL is skipped), so there is no cost unless set.
 *
 * The motivating use is userspace-RCU in QSBR mode: iteration_end maps to
 * rcu_quiescent_state(), and pre_wait/post_wait bracket the (possibly blocking)
 * core wait with rcu_thread_offline()/rcu_thread_online() so a thread asleep in
 * the wait does not hold up grace periods.
 */
struct evpl_loop_hooks {
    evpl_loop_callback_t iteration_end; /* end of every evpl_continue() pass   */
    evpl_loop_callback_t pre_wait;      /* before the core wait (may block)    */
    evpl_loop_callback_t post_wait;     /* after the core wait returns         */
    void                *private_data;
};

/* Install (replace, or clear with NULL) this thread's loop hooks. */
EVPL_API void evpl_set_loop_hooks(
    struct evpl                  *evpl,
    const struct evpl_loop_hooks *hooks);

EVPL_API void evpl_stop(
    struct evpl *evpl);

EVPL_API int evpl_protocol_lookup(
    enum evpl_protocol_id *id,
    const char            *name);

/* 1 iff the protocol is registered and available in this build/config.  An
 * unavailable protocol reports 0 from every predicate below, so this is how a
 * caller distinguishes "not a stream" from "not built". */
EVPL_API int evpl_protocol_available(
    enum evpl_protocol_id protocol);

EVPL_API int evpl_protocol_is_stream(
    enum evpl_protocol_id protocol);

/* 1 iff the protocol names peers by a local socket path rather than by
 * network address and port, and therefore requires an endpoint created by
 * evpl_endpoint_create_local(). */
EVPL_API int evpl_protocol_is_local(
    enum evpl_protocol_id protocol);

/* 1 iff the protocol reaches a peer thread inside this process rather than any
 * kernel transport, and therefore requires an endpoint created by
 * evpl_endpoint_create_inproc().  Such a name is private to the process: two
 * processes may use the same one without colliding. */
EVPL_API int evpl_protocol_is_inproc(
    enum evpl_protocol_id protocol);

