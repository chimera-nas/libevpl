// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <time.h>

#ifndef EVPL_INCLUDED
#error "Do not include evpl_core.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

enum evpl_framework_id {
    EVPL_FRAMEWORK_RDMACM   = 0,
    EVPL_FRAMEWORK_XLIO     = 1,
    EVPL_FRAMEWORK_IO_URING = 2,
    EVPL_FRAMEWORK_VFIO     = 3,
    EVPL_FRAMEWORK_TLS      = 4,
    EVPL_FRAMEWORK_TCP_RDMA = 5,
    EVPL_FRAMEWORK_LIBAIO   = 6,
    EVPL_NUM_FRAMEWORK      = 7
};

enum evpl_protocol_id {
    EVPL_DATAGRAM_SOCKET_UDP = 0,
    EVPL_DATAGRAM_RDMACM_RC  = 1,
    EVPL_DATAGRAM_RDMACM_UD  = 2,
    EVPL_STREAM_SOCKET_TCP   = 3,
    EVPL_STREAM_XLIO_TCP     = 4,
    EVPL_STREAM_IO_URING_TCP = 5,
    EVPL_STREAM_RDMACM_RC    = 6,
    EVPL_STREAM_SOCKET_TLS   = 7,
    EVPL_DATAGRAM_TCP_RDMA   = 8,
    EVPL_NUM_PROTO           = 9
};

enum evpl_block_protocol_id {
    EVPL_BLOCK_PROTOCOL_IO_URING      = 0,
    EVPL_BLOCK_PROTOCOL_VFIO          = 1,
    EVPL_BLOCK_PROTOCOL_LIBAIO        = 2,
    EVPL_BLOCK_PROTOCOL_IO_URING_NVME = 3,
    EVPL_NUM_BLOCK_PROTOCOL           = 4
};

struct evpl;
struct evpl_global_config;
struct evpl_thread_config;

void evpl_init(
    struct evpl_global_config *global_config);

/* Serialize libevpl's own metrics into buffer in Prometheus text
 * exposition format (version 0.0.4).  Returns the number of bytes
 * written, or -1 if the buffer was too small.  Safe to call from any
 * thread; triggers evpl initialization if it has not happened yet.
 */
int evpl_metrics_scrape(
    char *buffer,
    int   buffer_size);

struct evpl * evpl_create(
    struct evpl_thread_config *config);

void
evpl_get_hf_monotonic_time(
    struct evpl     *evpl,
    struct timespec *ts);

void evpl_destroy(
    struct evpl *evpl);

void evpl_continue(
    struct evpl *evpl);

void evpl_run(
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
void evpl_set_loop_hooks(
    struct evpl                  *evpl,
    const struct evpl_loop_hooks *hooks);

void evpl_stop(
    struct evpl *evpl);

int evpl_protocol_lookup(
    enum evpl_protocol_id *id,
    const char            *name);

int evpl_protocol_is_stream(
    enum evpl_protocol_id protocol);

struct evpl_config *
evpl_config(
    struct evpl *evpl);
