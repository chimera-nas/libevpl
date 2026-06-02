// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE 1

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/eventfd.h>
#include <utlist.h>
#include <signal.h>

#ifdef __x86_64__
#include <x86intrin.h>
#endif /* ifdef __x86_64__ */


#include "core/evpl.h"
#include "core/event_fn.h"
#include "core/poll.h"
#include "evpl/evpl.h"
#include "core/evpl_shared.h"
#include "core/protocol.h"
#include "core/allocator.h"
#include "core/bind.h"
#include "core/endpoint.h"
#include "core/timer.h"
#include "core/protocol.h"
#include "core/timing.h"
#include "core/numa.h"

#ifdef HAVE_IO_URING
#include "io_uring/io_uring.h"
#endif /* ifdef HAVE_IO_URING */

#ifdef HAVE_RDMACM
#include "rdmacm/rdmacm.h"
#endif /* ifdef HAVE_RDMACM */

#ifdef HAVE_VFIO
#include "vfio/vfio.h"
#endif /* ifdef HAVE_VFIO */

#ifdef HAVE_XLIO
#include "xlio/xlio.h"
#endif /* ifdef HAVE_XLIO */

#ifdef HAVE_LIBAIO
#include "libaio/libaio.h"
#endif /* ifdef HAVE_LIBAIO */

#include "socket/udp.h"
#include "socket/tcp.h"
#include "socket/tcp_rdma.h"
#include "tls/tls.h"

pthread_once_t      evpl_shared_once = PTHREAD_ONCE_INIT;
struct evpl_shared *evpl_shared      = NULL;

static void
evpl_shared_init(struct evpl_global_config *config)
{
    evpl_shared = evpl_zalloc(sizeof(*evpl_shared));

    pthread_mutex_init(&evpl_shared->lock, NULL);

    if (!config) {
        config = evpl_global_config_init();
    }

    evpl_shared->config = config;

    if (evpl_shared->config->hf_time_mode == 2) {
        /* Deetect if nonstop_tsc is supported, enable iff so */

        /* Assume the worst until proven otherwise*/
        evpl_shared->config->hf_time_mode = 0;

        FILE *cpuinfo = fopen("/proc/cpuinfo", "r");

        if (cpuinfo) {
            char line[160];
            while (fgets(line, sizeof(line), cpuinfo)) {
                if (strstr(line, "nonstop_tsc")) {
                    evpl_shared->config->hf_time_mode = 1;
                    break;
                }
            }

            fclose(cpuinfo);
        }
    }

    signal(SIGPIPE, SIG_IGN);

    evpl_shared->numa_config = evpl_numa_discover();

    /* Registry for libevpl's own metrics.  Created before the allocator
     * so the allocator can self-register its counters/gauges on it.
     * Exposed to embedders via evpl_metrics_scrape().
     */
    evpl_shared->metrics = prometheus_metrics_create(NULL, NULL, 0);

    /* Initialize the process-wide TSC clock and anchor it to wall-clock
     * monotonic time. Captured adjacently so the anchor is tight.
     */
    stopwatch_context_init(&evpl_shared->hf_stopwatch);
    clock_gettime(CLOCK_MONOTONIC, &evpl_shared->hf_base_time);
    stopwatch_start(&evpl_shared->hf_stopwatch, &evpl_shared->hf_base_sw);

    /* Block I/O metric definitions.  Per-device series (labelled by
     * device and type) are created lazily when a device is opened; the
     * histograms use base-2 buckets, so 32 buckets cover up to ~2.1s of
     * latency and ~2GiB of request size.
     */
    evpl_shared->block_latency = prometheus_metrics_create_histogram_time(
        evpl_shared->metrics, "evpl_block_latency_nanoseconds",
        "Block I/O request latency in nanoseconds", 34);

    evpl_shared->block_request_size = prometheus_metrics_create_histogram_exponential(
        evpl_shared->metrics, "evpl_block_request_bytes",
        "Block I/O request size in bytes", 32);

    evpl_shared->block_queue_depth = prometheus_metrics_create_gauge(
        evpl_shared->metrics, "evpl_block_queue_depth",
        "Outstanding block I/O requests");

    /* RPC2 in-flight request gauge.  Per-thread series (labelled by role
     * server/client and a thread id) are created when an rpc2 thread is
     * initialized; the I/O path mutates each instance lock-free on its
     * own thread.
     */
    evpl_shared->rpc2_queue_depth = prometheus_metrics_create_gauge(
        evpl_shared->metrics, "evpl_rpc2_queue_depth",
        "Outstanding RPC2 requests");

    evpl_shared->allocator = evpl_allocator_create();

    evpl_protocol_init(evpl_shared, EVPL_DATAGRAM_SOCKET_UDP,
                       &evpl_socket_udp);

    evpl_protocol_init(evpl_shared, EVPL_STREAM_SOCKET_TCP,
                       &evpl_socket_tcp);

    evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_TLS,
                        &evpl_framework_tls);

    evpl_protocol_init(evpl_shared, EVPL_STREAM_SOCKET_TLS,
                       &evpl_socket_tls);

    evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_TCP_RDMA,
                        &evpl_framework_tcp_rdma);

    evpl_protocol_init(evpl_shared, EVPL_DATAGRAM_TCP_RDMA,
                       &evpl_tcp_rdma_datagram);

#ifdef HAVE_IO_URING
    if (config->io_uring_enabled) {
        evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_IO_URING, &
                            evpl_framework_io_uring);

        evpl_block_protocol_init(evpl_shared, EVPL_BLOCK_PROTOCOL_IO_URING,
                                 &evpl_block_protocol_io_uring);

#ifdef HAVE_IO_URING_NVME
        evpl_block_protocol_init(evpl_shared, EVPL_BLOCK_PROTOCOL_IO_URING_NVME,
                                 &evpl_block_protocol_io_uring_nvme);
#endif /* ifdef HAVE_IO_URING_NVME */

        evpl_protocol_init(evpl_shared, EVPL_STREAM_IO_URING_TCP,
                           &evpl_io_uring_tcp);
    }
#endif /* ifdef HAVE_IO_URING */

#ifdef HAVE_RDMACM
    if (config->rdmacm_enabled) {
        evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_RDMACM, &
                            evpl_framework_rdmacm);
        evpl_protocol_init(evpl_shared, EVPL_DATAGRAM_RDMACM_RC,
                           &evpl_rdmacm_rc_datagram);
        evpl_protocol_init(evpl_shared, EVPL_STREAM_RDMACM_RC,
                           &evpl_rdmacm_rc_stream);
        evpl_protocol_init(evpl_shared, EVPL_DATAGRAM_RDMACM_UD,
                           &evpl_rdmacm_ud_datagram);
    }
#endif /* ifdef HAVE_RDMACM */

#ifdef HAVE_VFIO
    if (config->vfio_enabled) {
        evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_VFIO, &
                            evpl_framework_vfio);
        evpl_block_protocol_init(evpl_shared, EVPL_BLOCK_PROTOCOL_VFIO, &
                                 evpl_block_protocol_vfio);
    }
#endif /* ifdef HAVE_VFIO */

#ifdef HAVE_LIBAIO
    if (config->libaio_enabled) {
        evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_LIBAIO, &
                            evpl_framework_libaio);

        evpl_block_protocol_init(evpl_shared, EVPL_BLOCK_PROTOCOL_LIBAIO,
                                 &evpl_block_protocol_libaio);
    }
#endif /* ifdef HAVE_LIBAIO */

#ifdef HAVE_XLIO

    if (config->xlio_enabled) {
        evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_XLIO, &
                            evpl_framework_xlio);
        evpl_protocol_init(evpl_shared, EVPL_STREAM_XLIO_TCP, &evpl_xlio_tcp);
    }

#endif /* ifdef HAVE_XLIO */

} /* evpl_shared_init */

void
evpl_cleanup()
{
    struct evpl_endpoint *endpoint;
    unsigned int          i;

    while (evpl_shared->endpoints) {
        endpoint = evpl_shared->endpoints;
        evpl_endpoint_close(endpoint);
    }

    evpl_allocator_destroy(evpl_shared->allocator);

    /* Destroyed after the allocator so any teardown-time gauge updates
     * still target live instances.  Cascades free of all counters,
     * gauges, series and instances registered on it.
     */
    prometheus_metrics_destroy(evpl_shared->metrics);

    for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {
        if (evpl_shared->framework_private[i]) {
            evpl_shared->framework[i]->cleanup(evpl_shared->framework_private[i]
                                               );
        }
    }

    evpl_numa_config_release(evpl_shared->numa_config);

    evpl_global_config_release(evpl_shared->config);

    evpl_free(evpl_shared);
    evpl_shared = NULL;
} /* evpl_cleanup */

SYMBOL_EXPORT void
evpl_init(struct evpl_global_config *config)
{
    evpl_core_abort_if(evpl_shared, "evpl_init: evpl_shared already initialized");

    evpl_shared_init(config);
    atexit(evpl_cleanup);
} /* evpl_init_auto */

static void
evpl_init_once(void)
{
    if (!evpl_shared) {
        /*
         *  User has not called evpl_init() before evpl_create(),
         * so we will initialize ourselves and cleanup atexit()
         */

        evpl_shared_init(NULL);
        atexit(evpl_cleanup);
    }
} /* evpl_init_once */

void
__evpl_init(void)
{
    pthread_once(&evpl_shared_once, evpl_init_once);
} /* __evpl_init */

SYMBOL_EXPORT int
evpl_metrics_scrape(
    char *buffer,
    int   buffer_size)
{
    __evpl_init();

    return prometheus_metrics_scrape(evpl_shared->metrics, buffer, buffer_size);
} /* evpl_metrics_scrape */

SYMBOL_EXPORT struct prometheus_gauge_series *
evpl_rpc2_queue_depth_create_series(
    const char *role,
    const char *thread)
{
    __evpl_init();

    return prometheus_gauge_create_series(
        evpl_shared->rpc2_queue_depth,
        (const char *[]) { "role", "thread" },
        (const char *[]) { role, thread }, 2);
} /* evpl_rpc2_queue_depth_create_series */

SYMBOL_EXPORT void
evpl_rpc2_queue_depth_destroy_series(struct prometheus_gauge_series *series)
{
    prometheus_gauge_destroy_series(evpl_shared->rpc2_queue_depth, series);
} /* evpl_rpc2_queue_depth_destroy_series */

static inline struct evpl_global_config *
evpl_get_config(void)
{
    struct evpl_global_config *config;

    pthread_mutex_lock(&evpl_shared->lock);
    evpl_shared->config->refcnt++;
    config = evpl_shared->config;
    pthread_mutex_unlock(&evpl_shared->lock);

    return config;
} /* evpl_get_config */

static void
evpl_ipc_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_connect_request *request;
    struct evpl_bind            *new_bind;
    uint64_t                     value;
    ssize_t                      rc;

    do {
        rc = read(event->fd, &value, sizeof(value));
    } while (rc < 0 && errno == EINTR);

    if (rc != sizeof(value)) {
        evpl_event_mark_unreadable(evpl, event);
        return;
    }

    pthread_mutex_lock(&evpl->lock);

    while (evpl->connect_requests) {

        request = evpl->connect_requests;
        DL_DELETE(evpl->connect_requests, request);

        new_bind = evpl_bind_prepare(evpl,
                                     request->protocol,
                                     request->local_address,
                                     request->remote_address);

        request->attach_callback(evpl,
                                 new_bind,
                                 &new_bind->notify_callback,
                                 &new_bind->segment_callback,
                                 &new_bind->private_data,
                                 request->private_data);

        request->protocol->attach(evpl, new_bind, request->accepted);

        evpl_free(request);
    }

    pthread_mutex_unlock(&evpl->lock);

} /* evpl_stop_callback */

SYMBOL_EXPORT struct evpl *
evpl_create(struct evpl_thread_config *config)
{
    struct evpl *evpl;

    __evpl_init();

    evpl = evpl_zalloc(sizeof(*evpl));

    pthread_mutex_init(&evpl->lock, NULL);

    evpl->poll     = evpl_calloc(256, sizeof(struct evpl_poll));
    evpl->max_poll = 256;

    evpl->active_events     = evpl_calloc(256, sizeof(struct evpl_event *));
    evpl->max_active_events = 256;

    evpl->active_deferrals = evpl_calloc(256, sizeof(struct
                                                     evpl_deferral *));
    evpl->max_active_deferrals = 256;

    evpl->max_timers = 256;
    evpl->num_timers = 0;
    evpl->timers     = evpl_calloc(evpl->max_timers, sizeof(struct evpl_timer *));

    if (config) {
        evpl->config = *config;
        evpl_thread_config_release(config);
    } else {
        evpl->config = evpl_shared->config->thread_default;
    }

    /* Precompute the poll-mode spin grace period in ticks so the event loop
     * compares it without converting on every iteration. */
    evpl->spin_ticks = evpl_ns_to_ticks(evpl->config.spin_ns);

    evpl_core_init(&evpl->core, 64);

    evpl->running = 1;
    evpl->eventfd = eventfd(0, EFD_NONBLOCK);

    evpl_core_abort_if(evpl->eventfd < 0,
                       "evpl_create: eventfd failed");

    evpl_add_event(evpl, &evpl->run_event, evpl->eventfd,
                   evpl_ipc_callback, NULL, NULL);

    evpl_event_read_interest(evpl, &evpl->run_event);

    return evpl;
} /* evpl_init */

SYMBOL_EXPORT FORCE_INLINE void
evpl_continue(struct evpl *evpl)
{
    struct evpl_event    *event;
    struct evpl_bind     *bind;
    struct evpl_deferral *deferral;
    struct evpl_poll     *poll;
    struct evpl_timer    *timer;
    int                   i, n;
    int                   msecs = evpl->config.wait_ms;
    uint64_t              elapsed;
    int64_t               remain;
    uint64_t              now_ticks;

    if (evpl->poll_mode && evpl->poll_iterations < evpl->config.poll_iterations) {

        for (i = 0; i < evpl->num_poll; ++i) {
            poll = &evpl->poll[i];
            poll->callback(evpl, poll->private_data);
        }

        evpl->poll_iterations++;

    } else {

        now_ticks = evpl_now_ticks();

        if (evpl->num_timers) {

            do {
                timer = evpl->timers[0];

                remain = (int64_t) (timer->deadline - now_ticks);

                if (remain > 0) {
                    /* Timer not yet due; convert the remaining ticks to the
                     * millisecond wait only here, off the busy path. */
                    remain = (int64_t) (evpl_ticks_to_ns((uint64_t) remain) / 1000000);

                    if (remain < msecs || msecs == -1) {
                        msecs = remain;
                        break;
                    }
                }

                if (timer->oneshot) {
                    /* Remove before the callback: a one-shot fires once and
                     * the callback is permitted to free or re-arm the timer. */
                    evpl_pop_timer(evpl);
                    timer->callback(evpl, timer);
                } else {
                    timer->callback(evpl, timer);
                    evpl_pop_timer(evpl);
                    evpl_timer_insert(evpl, timer);
                }

            } while (evpl->num_timers);
        }

        if (evpl->config.poll_mode && evpl->num_poll) {

            if (evpl->activity != evpl->last_activity) {
                evpl->last_activity       = evpl->activity;
                evpl->last_activity_ticks = now_ticks;
                elapsed                   = 0;
            } else {
                elapsed = now_ticks - evpl->last_activity_ticks;
            }
        } else {
            elapsed = 0;
        }

        if (!evpl->force_poll_mode && !evpl->poll_pin_count &&
            elapsed > evpl->spin_ticks) {
            if (evpl->poll_mode) {
                for (i = 0; i < evpl->num_poll; ++i) {
                    poll = &evpl->poll[i];
                    if (poll->exit_callback) {
                        poll->exit_callback(evpl, poll->private_data);
                    }
                }

                evpl->poll_mode = 0;
            }
        } else {

            if (evpl->config.poll_mode && evpl->num_poll && !evpl->poll_mode) {
                for (i = 0; i < evpl->num_poll; ++i) {
                    poll = &evpl->poll[i];
                    if (poll->enter_callback) {
                        poll->enter_callback(evpl, poll->private_data);
                    }
                }

                evpl->poll_mode       = 1;
                evpl->poll_iterations = 0;
            }
        }

        if (evpl->poll_mode || (evpl->config.poll_mode && evpl->activity != evpl->last_activity) ||
            evpl->num_active_events || evpl->num_active_deferrals || evpl->pending_close_binds) {
            msecs = 0;
        }

        if (evpl->loop_hooks.pre_wait) {
            evpl->loop_hooks.pre_wait(evpl, evpl->loop_hooks.private_data);
        }

        n = evpl_core_wait(&evpl->core, msecs);

        if (evpl->loop_hooks.post_wait) {
            evpl->loop_hooks.post_wait(evpl, evpl->loop_hooks.private_data);
        }

        if (evpl->pending_close_binds && n == 0) {
            struct evpl_bind *next;

            bind = evpl->pending_close_binds;
            while (bind) {
                next = bind->next;
                /* A protocol with an asynchronous teardown (RDMA) keeps the
                 * bind parked here until its disconnect event arrives; do not
                 * finalize it yet or its private state would be freed while
                 * the protocol still references it. */
                if (!(bind->flags & EVPL_BIND_CLOSE_DEFERRED)) {
                    bind->protocol->close(evpl, bind);
                    evpl_bind_destroy(evpl, bind);
                }
                bind = next;
            }
        }

        evpl->poll_iterations = 0;
    } /* evpl_continue */

    for (i = 0; i < evpl->num_active_events;) {
        event = evpl->active_events[i];

        if ((event->flags & EVPL_READ_READY) == EVPL_READ_READY) {
            event->read_callback(evpl, event);
        }

        if ((event->flags & EVPL_WRITE_READY) ==
            EVPL_WRITE_READY) {
            event->write_callback(evpl, event);
        }

        if ((event->flags & EVPL_ERROR) == EVPL_ERROR) {
            event->error_callback(evpl, event);
        }

        if ((event->flags & EVPL_READ_READY) != EVPL_READ_READY &&
            (event->flags & EVPL_WRITE_READY) != EVPL_WRITE_READY) {

            event->flags &= ~EVPL_ACTIVE;

            if (i + 1 < evpl->num_active_events) {
                evpl->active_events[i] =
                    evpl->active_events[evpl->num_active_events - 1];
            }
            --evpl->num_active_events;
        } else {
            i++;
        }
    }

    while (evpl->num_active_deferrals) {
        deferral = evpl->active_deferrals[0];
        --evpl->num_active_deferrals;
        if (evpl->num_active_deferrals > 0) {
            evpl->active_deferrals[0] =
                evpl->active_deferrals[evpl->num_active_deferrals];
        }

        deferral->armed = 0;

        deferral->callback(evpl, deferral->private_data);
    }

    if (evpl->loop_hooks.iteration_end) {
        evpl->loop_hooks.iteration_end(evpl, evpl->loop_hooks.private_data);
    }

} /* evpl_continue */

SYMBOL_EXPORT void
evpl_get_hf_monotonic_time(
    struct evpl     *evpl,
    struct timespec *ts)
{
    (void) evpl;

    /* Back the high-frequency clock with the shared stopwatch: absolute
     * monotonic time = wall-clock anchor + elapsed ticks since the base
     * stopwatch was started at init. Falls back to clock_gettime when the
     * stopwatch could not use the TSC or hf_time_mode is disabled.
     */
    if (evpl_shared->config->hf_time_mode > 0 &&
        evpl_shared->hf_stopwatch.use_tsc) {
        uint64_t delta_ns = stopwatch_elapsed_ns(&evpl_shared->hf_stopwatch,
                                                 &evpl_shared->hf_base_sw);

        uint64_t nsec = evpl_shared->hf_base_time.tv_nsec + (delta_ns % NS_PER_S);

        ts->tv_sec = evpl_shared->hf_base_time.tv_sec + (delta_ns / NS_PER_S);

        if (nsec >= NS_PER_S) {
            ts->tv_sec++;
            nsec -= NS_PER_S;
        }

        ts->tv_nsec = nsec;
    } else {
        clock_gettime(CLOCK_MONOTONIC, ts);
    }
} /* evpl_get_hf_monotonic_time */


SYMBOL_EXPORT void
evpl_run(struct evpl *evpl)
{
    while (evpl->running) {
        evpl_continue(evpl);
    }
} /* evpl_run */

SYMBOL_EXPORT void
evpl_set_loop_hooks(
    struct evpl                  *evpl,
    const struct evpl_loop_hooks *hooks)
{
    if (hooks) {
        evpl->loop_hooks = *hooks;
    } else {
        memset(&evpl->loop_hooks, 0, sizeof(evpl->loop_hooks));
    }
} /* evpl_set_loop_hooks */

SYMBOL_EXPORT void
evpl_stop(struct evpl *evpl)
{
    uint64_t value = 1;
    ssize_t  len;
    int      err;

    evpl_core_assert(evpl->running);

    evpl->running = 0;

    __sync_synchronize();

    do {
        len = write(evpl->eventfd, &value, sizeof(value));
    } while (len < 0 && errno == EINTR);

    err = errno;

    evpl_core_abort_if(len != sizeof(value),
                       "evpl_stop: write to eventfd %d failed: len=%zd errno=%d (%s)",
                       evpl->eventfd, len, err, strerror(err));
} /* evpl_stop */


void
evpl_destroy_close_bind(struct evpl *evpl)
{
    struct evpl_bind *bind;

    /* Push any open binds into pending close state */
    DL_FOREACH(evpl->binds, bind)
    {
        evpl_close(evpl, bind);
    }

    /* Pump events until we have no pending close binds */
    while (evpl->binds || evpl->pending_close_binds) {
        evpl_continue(evpl);
    }

} /* evpl_destroy_close_bind */

SYMBOL_EXPORT void
evpl_destroy(struct evpl *evpl)
{
    struct evpl_framework *framework;
    struct evpl_bind      *bind;
    struct evpl_buffer    *buffer;
    int                    i;

    evpl_destroy_close_bind(evpl);

    while (evpl->free_binds) {
        bind = evpl->free_binds;
        DL_DELETE(evpl->free_binds, bind);

        evpl_iovec_ring_free(&bind->iovec_send);
        evpl_iovec_ring_free(&bind->iovec_recv);
        evpl_iovec_ring_free(&bind->iovec_rdma_read);
        evpl_iovec_ring_free(&bind->iovec_send_framed);
        evpl_dgram_ring_free(&bind->dgram_read);
        evpl_dgram_ring_free(&bind->dgram_send);
        evpl_free(bind);
    }

    for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {
        framework = evpl_shared->framework[i];

        if (!framework || !framework->destroy || !evpl->framework_private[i]) {
            continue;
        }

        framework->destroy(evpl, evpl->framework_private[i]);
    }

    if (evpl->current_buffer) {
        evpl_buffer_release(evpl, evpl->current_buffer);
    }

    if (evpl->shared_buffer) {
        evpl_buffer_release(evpl, evpl->shared_buffer);
    }

    if (evpl->datagram_buffer) {
        evpl_buffer_release(evpl, evpl->datagram_buffer);
    }

    /* Return all thread-local free buffers to the global allocator */
    while (evpl->free_local_buffers) {
        buffer = evpl->free_local_buffers;
        LL_DELETE(evpl->free_local_buffers, buffer);
        evpl_allocator_free(evpl_shared->allocator, buffer);
    }

    while (evpl->free_shared_buffers) {
        buffer = evpl->free_shared_buffers;
        LL_DELETE(evpl->free_shared_buffers, buffer);
        evpl_allocator_free(evpl_shared->allocator, buffer);
    }

    evpl_core_destroy(&evpl->core);

    close(evpl->eventfd);

    evpl_free(evpl->active_events);
    evpl_free(evpl->active_deferrals);
    evpl_free(evpl->timers);
    evpl_free(evpl->poll);

    evpl_free(evpl);
} /* evpl_destroy */

void
evpl_attach_framework(
    struct evpl           *evpl,
    enum evpl_framework_id framework_id)
{
    struct evpl_framework *framework = evpl_shared->framework[framework_id];

    evpl_attach_framework_shared(framework_id);

    if (evpl_shared->framework_private[framework->id] && !evpl->framework_private[framework->id]) {
        evpl->framework_private[framework->id] =
            framework->create(evpl, evpl_shared->framework_private[framework->id
                              ]);
    }
} /* evpl_attach_framework */

void *
evpl_framework_private(
    struct evpl *evpl,
    int          id)
{
    return evpl->framework_private[id];
} /* evpl_framework_private */

void
evpl_add_event(
    struct evpl                *evpl,
    struct evpl_event          *event,
    int                         fd,
    evpl_event_read_callback_t  read_callback,
    evpl_event_write_callback_t write_callback,
    evpl_event_error_callback_t error_callback)
{
    event->owner          = evpl;
    event->fd             = fd;
    event->flags          = 0;
    event->read_callback  = read_callback;
    event->write_callback = write_callback;
    event->error_callback = error_callback;

    evpl_core_add(&evpl->core, event);

    evpl->num_events++;
} /* evpl_add_event */

void
evpl_event_update_callbacks(
    struct evpl                *evpl,
    struct evpl_event          *event,
    evpl_event_read_callback_t  read_callback,
    evpl_event_write_callback_t write_callback,
    evpl_event_error_callback_t error_callback)
{
    event->read_callback  = read_callback;
    event->write_callback = write_callback;
    event->error_callback = error_callback;
} /* evpl_event_update_callbacks */
void
evpl_remove_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    evpl_core_remove(&evpl->core, event);
    evpl->num_events--;
} /* evpl_remove_event */

SYMBOL_EXPORT int
evpl_protocol_lookup(
    enum evpl_protocol_id *id,
    const char            *name)
{
    struct evpl_protocol *proto;
    int                   i;

    evpl_init_once();

    for (i = 0; i < EVPL_NUM_PROTO; ++i) {
        proto = evpl_shared->protocol[i];

        if (proto && strcmp(proto->name, name) == 0) {
            *id = proto->id;
            return 0;
        }
    }

    return -1;
} /* evpl_protocol_lookup */

SYMBOL_EXPORT uint64_t
evpl_get_slab_size(void)
{
    __evpl_init();
    return evpl_shared->config->slab_size;
} /* evpl_get_slab_size */

SYMBOL_EXPORT void *
evpl_slab_alloc(void **slab_private)
{
    __evpl_init();

    return evpl_allocator_alloc_slab(evpl_shared->allocator, slab_private);
}      /* evpl_slab_alloc */
