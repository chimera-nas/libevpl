// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <pthread.h>

#define EVPL_INTERNAL 1

#include "evpl/evpl.h"
#include "protocol.h"
#include "allocator.h"
#include "stopwatch.h"

struct evpl_allocator;

struct evpl_shared {
    pthread_mutex_t              lock;
    struct evpl_global_config   *config;
    struct evpl_numa_config     *numa_config;
    struct evpl_endpoint        *endpoints;

    /* Process-wide TSC clock backing evpl_get_hf_monotonic_time(). The base
     * stopwatch + CLOCK_MONOTONIC anchor are captured once at init; absolute
     * monotonic time is anchor + elapsed-ticks-since-base. Read-only after
     * init, so the time path takes no locks.
     */
    struct stopwatch_context     hf_stopwatch;
    struct stopwatch             hf_base_sw;
    struct timespec              hf_base_time;

    struct prometheus_metrics   *metrics;
    struct prometheus_histogram *block_latency;
    struct prometheus_histogram *block_request_size;
    struct prometheus_gauge     *block_queue_depth;
    struct prometheus_gauge     *rpc2_queue_depth;
    struct evpl_allocator       *allocator;
    struct evpl_framework       *framework[EVPL_NUM_FRAMEWORK];
    void                        *framework_private[EVPL_NUM_FRAMEWORK];
    struct evpl_protocol        *protocol[EVPL_NUM_PROTO];
    struct evpl_block_protocol  *block_protocol[EVPL_NUM_BLOCK_PROTOCOL];
};

extern struct evpl_shared *evpl_shared;

/* Monotonic time in raw stopwatch ticks since init (TSC cycles where the
 * stopwatch could use the TSC, otherwise nanoseconds). Cheap and lock-free:
 * a single unfenced rdtsc and subtract on the TSC path. This is the unit the
 * event loop keeps deadlines and grace periods in so the hot path never calls
 * clock_gettime or converts to nanoseconds.
 */
static inline uint64_t
evpl_now_ticks(void)
{
    return stopwatch_read_ticks(&evpl_shared->hf_stopwatch, &evpl_shared->hf_base_sw);
} /* evpl_now_ticks */

static inline uint64_t
evpl_ns_to_ticks(uint64_t ns)
{
    return stopwatch_ns_to_ticks(&evpl_shared->hf_stopwatch, ns);
} /* evpl_ns_to_ticks */

static inline uint64_t
evpl_ticks_to_ns(uint64_t ticks)
{
    return stopwatch_ticks_to_ns(&evpl_shared->hf_stopwatch, ticks);
} /* evpl_ticks_to_ns */

struct prometheus_gauge_series * evpl_rpc2_queue_depth_create_series(
    const char *role,
    const char *thread);

void evpl_rpc2_queue_depth_destroy_series(
    struct prometheus_gauge_series *series);


static inline void
evpl_attach_framework_shared(enum evpl_framework_id framework_id)
{
    struct evpl_framework *framework = evpl_shared->framework[framework_id];

    pthread_mutex_lock(&evpl_shared->lock);

    if (!evpl_shared->framework_private[framework->id]) {

        evpl_shared->framework_private[framework->id] = framework->init();

        if (evpl_shared->framework_private[framework->id]) {
            evpl_allocator_reregister(evpl_shared->allocator);
        }
    }

    pthread_mutex_unlock(&evpl_shared->lock);
} /* evpl_attach_framework_shared */
