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

#include "socket/udp.h"
#include "socket/tcp.h"
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

    evpl_shared->numa_config = evpl_numa_discover();

    evpl_shared->allocator = evpl_allocator_create();

    evpl_protocol_init(evpl_shared, EVPL_DATAGRAM_SOCKET_UDP,
                       &evpl_socket_udp);

    evpl_protocol_init(evpl_shared, EVPL_STREAM_SOCKET_TCP,
                       &evpl_socket_tcp);

    evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_TLS,
                        &evpl_framework_tls);

    evpl_protocol_init(evpl_shared, EVPL_STREAM_SOCKET_TLS,
                       &evpl_socket_tls);

#ifdef HAVE_IO_URING
    if (config->io_uring_enabled) {
        evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_IO_URING, &
                            evpl_framework_io_uring);

        evpl_block_protocol_init(evpl_shared, EVPL_BLOCK_PROTOCOL_IO_URING,
                                 &evpl_block_protocol_io_uring);

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

    rc = read(event->fd, &value, sizeof(value));

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
    } else {
        evpl->config = evpl_shared->config->thread_default;
    }

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

SYMBOL_EXPORT void
evpl_continue(struct evpl *evpl)
{
    struct evpl_event    *event;
    struct evpl_bind     *bind;
    struct evpl_deferral *deferral;
    struct evpl_poll     *poll;
    struct evpl_timer    *timer;
    int                   i, n;
    int                   msecs = evpl->config.wait_ms;
    struct timespec       now;
    uint64_t              elapsed;
    int64_t               remain;

    clock_gettime(CLOCK_MONOTONIC, &now);

    if (evpl->num_timers) {

        do {
            timer = evpl->timers[0];

            remain = evpl_ts_interval(&timer->deadline, &now);

            if (remain > 0) {
                remain /= 1000000;

                if (remain < msecs || msecs == -1) {
                    msecs = remain;
                    break;
                }
            }

            timer->callback(evpl, timer);

            evpl_pop_timer(evpl);

            evpl_timer_insert(evpl, timer);

        } while (evpl->num_timers);
    }

    if (evpl->config.poll_mode && evpl->num_poll) {

        if (evpl->activity != evpl->last_activity) {
            evpl->last_activity    = evpl->activity;
            evpl->last_activity_ts = now;
            elapsed                = 0;
        } else {
            elapsed = evpl_ts_interval(&now, &evpl->last_activity_ts);
        }


        if (!evpl->force_poll_mode && elapsed > evpl->config.spin_ns) {
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

            if (!evpl->poll_mode) {
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
    }

    if (evpl->poll_mode || evpl->activity != evpl->last_activity ||
        evpl->num_active_events || evpl->num_active_deferrals || evpl->pending_close_binds) {
        msecs = 0;
    }

    if (evpl->poll_mode && evpl->poll_iterations < evpl->config.poll_iterations) {
        for (i = 0; i < evpl->num_poll; ++i) {
            poll = &evpl->poll[i];
            poll->callback(evpl, poll->private_data);
        }

        evpl->poll_iterations++;

    } else {

        n = evpl_core_wait(&evpl->core, msecs);

        if (evpl->pending_close_binds && n == 0) {
            while (evpl->pending_close_binds) {
                bind = evpl->pending_close_binds;
                bind->protocol->close(evpl, bind);
                evpl_bind_destroy(evpl, bind);
            }
        }

        evpl->poll_iterations = 0;
    }

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

} /* evpl_continue */

SYMBOL_EXPORT void
evpl_run(struct evpl *evpl)
{
    while (evpl->running) {
        evpl_continue(evpl);
    }
} /* evpl_run */

SYMBOL_EXPORT void
evpl_stop(struct evpl *evpl)
{
    uint64_t value = 1;
    ssize_t  len;

    evpl_core_assert(evpl->running);

    evpl->running = 0;

    __sync_synchronize();

    len = write(evpl->eventfd, &value, sizeof(value));

    evpl_core_abort_if(len != sizeof(value),
                       "evpl_stop: write to eventfd failed");
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
    int                    i;

    evpl_destroy_close_bind(evpl);

    while (evpl->free_binds) {
        bind = evpl->free_binds;
        DL_DELETE(evpl->free_binds, bind);

        evpl_iovec_ring_free(&bind->iovec_send);
        evpl_iovec_ring_free(&bind->iovec_recv);
        evpl_rdma_request_ring_free(&bind->rdma_rw);
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
        evpl_buffer_release(evpl->current_buffer);
    }

    if (evpl->datagram_buffer) {
        evpl_buffer_release(evpl->datagram_buffer);
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

SYMBOL_EXPORT void *
evpl_slab_alloc(void)
{
    return evpl_allocator_alloc_slab(evpl_shared->allocator);

}      /* evpl_slab_alloc */

