// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

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

#include "uthash/utlist.h"

#include "core/internal.h"

#include "evpl/evpl.h"
#include "core/evpl_shared.h"
#include "core/protocol.h"
#include "core/buffer.h"
#include "core/bind.h"
#include "core/endpoint.h"

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

pthread_once_t      evpl_shared_once = PTHREAD_ONCE_INIT;
struct evpl_shared *evpl_shared      = NULL;

static void
evpl_framework_init(
    struct evpl_shared    *evpl_shared,
    unsigned int           id,
    struct evpl_framework *framework)
{
    evpl_shared->framework[id] = framework;

} /* evpl_framework_init */

static void
evpl_protocol_init(
    struct evpl_shared   *evpl_shared,
    unsigned int          id,
    struct evpl_protocol *protocol)
{
    evpl_shared->protocol[id] = protocol;
} /* evpl_protocol_init */

static void
evpl_block_protocol_init(
    struct evpl_shared         *evpl_shared,
    unsigned int                id,
    struct evpl_block_protocol *protocol)
{
    evpl_shared->block_protocol[id] = protocol;
} /* evpl_block_protocol_init */

static void
evpl_shared_init(struct evpl_global_config *config)
{
    evpl_shared = evpl_zalloc(sizeof(*evpl_shared));

    pthread_mutex_init(&evpl_shared->lock, NULL);

    if (!config) {
        config = evpl_global_config_init();
    }

    evpl_shared->config = config;

    evpl_shared->allocator = evpl_allocator_create();

    evpl_protocol_init(evpl_shared, EVPL_DATAGRAM_SOCKET_UDP,
                       &evpl_socket_udp);

    evpl_protocol_init(evpl_shared, EVPL_STREAM_SOCKET_TCP,
                       &evpl_socket_tcp);

#ifdef HAVE_IO_URING
    if (config->io_uring_enabled) {
        evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_IO_URING, &
                            evpl_framework_io_uring);

        evpl_block_protocol_init(evpl_shared, EVPL_BLOCK_PROTOCOL_IO_URING,
                                 &evpl_block_protocol_io_uring);
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

extern evpl_log_fn EvplLog;
void
evpl_set_log_fn(evpl_log_fn log_fn)
{
    EvplLog = log_fn;
} /* evpl_set_log_fn */

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

    evpl_global_config_release(evpl_shared->config);

    evpl_free(evpl_shared);
    evpl_shared = NULL;
} /* evpl_cleanup */

void
evpl_init(struct evpl_global_config *config)
{
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

void
evpl_global_config_release(struct evpl_global_config *config)
{

    if (!evpl_shared) {
        evpl_free(config);
        return;
    }

    pthread_mutex_lock(&evpl_shared->lock);

    evpl_core_abort_if(config->refcnt == 0,
                       "config refcnt %d", config->refcnt);

    config->refcnt--;

    if (config->refcnt == 0) {
        evpl_free(config);
    }

    pthread_mutex_unlock(&evpl_shared->lock);
} /* evpl_release_config */

static void
evpl_ipc_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_connect_request *request;
    struct evpl_bind            *new_bind;
    struct evpl_notify           notify;
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

        notify.notify_type   = EVPL_NOTIFY_CONNECTED;
        notify.notify_status = 0;

        new_bind->notify_callback(evpl, new_bind, &notify,
                                  new_bind->private_data);

        evpl_free(request);
    }

    pthread_mutex_unlock(&evpl->lock);

} /* evpl_stop_callback */

struct evpl *
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


static void
evpl_timer_heap_up(
    struct evpl *evpl,
    int          i)
{
    struct evpl_timer *tmp;

    while (i > 0) {
        int parent = (i - 1) / 2;

        if (evpl_ts_compare(&evpl->timers[parent]->deadline, &evpl->timers[i]->deadline) < 0) {
            break;
        }

        tmp                  = evpl->timers[i];
        evpl->timers[i]      = evpl->timers[parent];
        evpl->timers[parent] = tmp;
        i                    = parent;
    }

} /* evpl_timer_heap_up */

static int
evpl_timer_heap_down(
    struct evpl *evpl,
    int          i)
{
    int                min_child, child;
    struct evpl_timer *tmp;

    while (1) {
        min_child = -1;

        child = 2 * i + 1;
        if (child < evpl->num_timers) {
            min_child = child;
        }

        child = 2 * i + 2;
        if (child < evpl->num_timers &&
            evpl_ts_compare(&evpl->timers[child]->deadline, &evpl->timers[min_child]->deadline) < 0) {
            min_child = child;
        }

        if (min_child == -1 ||
            evpl_ts_compare(&evpl->timers[i]->deadline, &evpl->timers[min_child]->deadline) < 0) {
            break;
        }

        tmp                     = evpl->timers[i];
        evpl->timers[i]         = evpl->timers[min_child];
        evpl->timers[min_child] = tmp;
        i                       = min_child;
    }

    return i;
} /* evpl_timer_heap_down */



static inline void
evpl_pop_timer(struct evpl *evpl)
{

    if (evpl->num_timers > 1) {
        evpl->timers[0] = evpl->timers[evpl->num_timers - 1];
    }
    evpl->num_timers--;

    evpl_timer_heap_down(evpl, 0);

} /* evpl_pop_timer */


static void
evpl_timer_insert(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    int i;

    clock_gettime(CLOCK_MONOTONIC, &timer->deadline);
    timer->deadline.tv_sec  += timer->interval / 1000000;
    timer->deadline.tv_nsec += (timer->interval % 1000000) * 1000;

    evpl->timers[evpl->num_timers] = timer;

    i = evpl->num_timers++;

    evpl_timer_heap_up(evpl, i);
} /* evpl_timer_insert */

void
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

    if (evpl->num_poll) {

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

            msecs = 0;
        }
    }

    if (evpl->pending_close_binds || evpl->num_active_events || evpl->num_active_deferrals) {
        msecs = 0;
    }

    if (evpl->poll_mode && evpl->poll_iterations < 100) {
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

} /* evpl_wait */

void
evpl_run(struct evpl *evpl)
{
    while (evpl->running) {
        evpl_continue(evpl);
    }
} /* evpl_run */

void
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

static void
evpl_listener_accept(
    struct evpl         *evpl,
    struct evpl_bind    *listen_bind,
    struct evpl_address *remote_address,
    void                *accepted,
    void                *private_data)
{
    struct evpl_listener         *listener = private_data;
    struct evpl_listener_binding *binding;
    struct evpl_connect_request  *request;
    uint64_t                      one = 1;
    int                           rc;

    pthread_mutex_lock(&listener->lock);

    binding = &listener->attached[listener->rotor];

    listener->rotor++;

    if (listener->rotor >= listener->num_attached) {
        listener->rotor = 0;
    }

    request = evpl_zalloc(sizeof(struct evpl_connect_request));

    request->local_address   = listen_bind->local;
    request->remote_address  = remote_address;
    request->protocol        = listen_bind->protocol;
    request->attach_callback = binding->attach_callback;
    request->accepted        = accepted;
    request->private_data    = binding->private_data;

    evpl_address_incref(request->local_address);

    pthread_mutex_lock(&binding->evpl->lock);
    DL_APPEND(binding->evpl->connect_requests, request);
    pthread_mutex_unlock(&binding->evpl->lock);

    rc = write(binding->evpl->eventfd, &one, sizeof(one));

    evpl_core_abort_if(rc != sizeof(one),
                       "evpl_listener_accept: write failed");

    pthread_mutex_unlock(&listener->lock);
} /* evpl_listener_accept */

static void
evpl_listener_callback(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    struct evpl_listener       *listener = container_of(doorbell, struct evpl_listener, doorbell);
    struct evpl_listen_request *request;
    struct evpl_bind           *bind, **new_binds;

    pthread_mutex_lock(&listener->lock);

    while (listener->requests) {
        request = listener->requests;
        DL_DELETE(listener->requests, request);

        bind = evpl_bind_prepare(evpl,
                                 evpl_shared->protocol[request->protocol_id],
                                 request->address,
                                 NULL);

        evpl_core_abort_if(!bind->protocol->listen,
                           "evpl_listen called with non-connection oriented protocol");

        bind->accept_callback = evpl_listener_accept;
        bind->private_data    = listener;

        bind->protocol->listen(evpl, bind);

        if (listener->num_binds >= listener->max_binds) {
            listener->max_binds *= 2;

            new_binds = evpl_calloc(listener->max_binds, sizeof(struct evpl_bind *));

            memcpy(new_binds, listener->binds, listener->num_binds * sizeof(struct evpl_bind *));

            evpl_free(listener->binds);

            listener->binds = new_binds;
        }

        listener->binds[listener->num_binds++] = bind;

        pthread_mutex_lock(&request->lock);
        request->complete = 1;
        pthread_cond_signal(&request->cond);
        pthread_mutex_unlock(&request->lock);
    }

    pthread_mutex_unlock(&listener->lock);

} /* evpl_listener_callback */

static void *
evpl_listener_init(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_listener *listener = private_data;

    evpl_add_doorbell(evpl, &listener->doorbell, evpl_listener_callback);

    __sync_synchronize();

    listener->running = 1;

    return listener;

} /* evpl_listener_init */

struct evpl_listener *
evpl_listener_create(void)
{
    struct evpl_listener *listener;

    __evpl_init();

    listener = evpl_zalloc(sizeof(*listener));

    pthread_mutex_init(&listener->lock, NULL);

    listener->thread = evpl_thread_create(NULL, evpl_listener_init, NULL, listener);

    listener->max_binds = 64;
    listener->binds     = evpl_calloc(listener->max_binds, sizeof(struct evpl_bind *));

    listener->max_attached = 64;
    listener->attached     = evpl_calloc(listener->max_attached, sizeof(struct evpl_listener_binding));

    while (!listener->running) {
        __sync_synchronize();
    }

    return listener;
} /* evpl_listener_create */

void
evpl_listener_destroy(struct evpl_listener *listener)
{

    evpl_core_abort_if(listener->num_attached,
                       "evpl_listener_destroy called with attached evpl contexts");

    pthread_mutex_destroy(&listener->lock);
    evpl_free(listener->binds);
    evpl_free(listener->attached);
    evpl_free(listener);
} /* evpl_listener_destroy */

void
evpl_listener_attach(
    struct evpl           *evpl,
    struct evpl_listener  *listener,
    evpl_attach_callback_t attach_callback,
    void                  *private_data)
{
    struct evpl_listener_binding *binding, *new_attached;

    pthread_mutex_lock(&listener->lock);

    if (listener->num_attached >= listener->max_attached) {
        listener->max_attached *= 2;

        new_attached = evpl_zalloc(sizeof(struct evpl_listener_binding) * listener->max_attached);

        memcpy(new_attached, listener->attached, listener->num_attached * sizeof(struct evpl_listener_binding));

        evpl_free(listener->attached);

        listener->attached = new_attached;
    }

    binding = &listener->attached[listener->num_attached++];

    binding->evpl            = evpl;
    binding->attach_callback = attach_callback;
    binding->private_data    = private_data;

    pthread_mutex_unlock(&listener->lock);
} /* evpl_listener_attach */

void
evpl_listener_detach(
    struct evpl          *evpl,
    struct evpl_listener *listener)
{
    pthread_mutex_lock(&listener->lock);

    for (int i = 0; i < listener->num_attached; i++) {
        if (listener->attached[i].evpl == evpl) {
            if (i + 1 < listener->num_attached) {
                listener->attached[i] = listener->attached[listener->num_attached - 1];
            }
            listener->num_attached--;
            break;
        }
    }

    pthread_mutex_unlock(&listener->lock);
} /* evpl_listener_detach */

void
evpl_listen(
    struct evpl_listener *listener,
    enum evpl_protocol_id protocol_id,
    struct evpl_endpoint *endpoint)
{
    struct evpl_listen_request *request;

    request = evpl_zalloc(sizeof(*request));

    pthread_mutex_init(&request->lock, NULL);
    pthread_cond_init(&request->cond, NULL);

    request->protocol_id = protocol_id;
    request->address     = evpl_endpoint_resolve(endpoint);

    pthread_mutex_lock(&listener->lock);
    DL_APPEND(listener->requests, request);
    pthread_mutex_unlock(&listener->lock);

    evpl_ring_doorbell(&listener->doorbell);

    pthread_mutex_lock(&request->lock);

    while (!request->complete) {
        pthread_cond_wait(&request->cond, &request->lock);
    }

    pthread_mutex_unlock(&request->lock);

    evpl_free(request);

} /* evpl_listen */

struct evpl_endpoint *
evpl_endpoint_create(
    const char *address,
    int         port)
{
    struct evpl_endpoint *ep;

    __evpl_init();

    ep = evpl_zalloc(sizeof(*ep));

    ep->port = port;
    strncpy(ep->address, address, sizeof(ep->address) - 1);

    pthread_rwlock_init(&ep->lock, NULL);

    pthread_mutex_lock(&evpl_shared->lock);
    DL_APPEND(evpl_shared->endpoints, ep);
    pthread_mutex_unlock(&evpl_shared->lock);

    return ep;
} /* evpl_endpoint_create */

void
evpl_endpoint_close(struct evpl_endpoint *endpoint)
{
    pthread_rwlock_wrlock(&endpoint->lock);

    pthread_mutex_lock(&evpl_shared->lock);
    DL_DELETE(evpl_shared->endpoints, endpoint);
    pthread_mutex_unlock(&evpl_shared->lock);

    if (endpoint->resolved_addr) {
        evpl_address_release(endpoint->resolved_addr);
    }

    pthread_rwlock_unlock(&endpoint->lock);

    evpl_free(endpoint);
} /* evpl_endpoint_close */

struct evpl_address *
evpl_endpoint_resolve(struct evpl_endpoint *endpoint)
{
    char                 port_str[8];
    struct addrinfo      hints, *ai, *p, **pp;
    struct evpl_address *addr;
    struct timespec      now;
    uint64_t             age_ms;
    int                  rc, i, n;

    clock_gettime(CLOCK_MONOTONIC, &now);

    pthread_rwlock_rdlock(&endpoint->lock);

    if (likely(endpoint->resolved_addr)) {
        age_ms = (now.tv_sec - endpoint->last_resolved.tv_sec) * 1000 +
            (now.tv_nsec - endpoint->last_resolved.tv_nsec) / 1000000;

        if (likely(age_ms <= evpl_shared->config->resolve_timeout_ms)) {
            addr = endpoint->resolved_addr;
            evpl_address_incref(addr);
            pthread_rwlock_unlock(&endpoint->lock);
            return addr;
        }
    }

    pthread_rwlock_unlock(&endpoint->lock);
    pthread_rwlock_wrlock(&endpoint->lock);

    if (endpoint->resolved_addr) {
        evpl_address_release(endpoint->resolved_addr);
    }

    snprintf(port_str, sizeof(port_str), "%d", endpoint->port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = 0; // SOCK_DGRAM;
    hints.ai_flags    = 0;

    rc = getaddrinfo(endpoint->address, port_str, &hints, &ai);

    if (unlikely(rc < 0)) {
        pthread_rwlock_unlock(&endpoint->lock);
        return NULL;
    }

    n = 0;

    for (p = ai; p != NULL; p = p->ai_next) {
        n++;
    }

    if (n) {
        pp = alloca(n * sizeof(struct addrinfo *));

        for (p = ai, i = 0; p != NULL; p = p->ai_next, i++) {
            pp[i] = p;
        }

        p = pp[rand() % n];

        addr = evpl_address_init(p->ai_addr, p->ai_addrlen);

        endpoint->resolved_addr = addr;
        endpoint->last_resolved = now;

        evpl_address_incref(addr);

    } else {
        addr = NULL;
    }

    pthread_rwlock_unlock(&endpoint->lock);

    freeaddrinfo(ai);

    return addr;
} /* evpl_endpoint_resolve */

struct evpl_bind *
evpl_connect(
    struct evpl            *evpl,
    enum evpl_protocol_id   protocol_id,
    struct evpl_endpoint   *local_endpoint,
    struct evpl_endpoint   *remote_endpoint,
    evpl_notify_callback_t  notify_callback,
    evpl_segment_callback_t segment_callback,
    void                   *private_data)
{
    struct evpl_bind     *bind;
    struct evpl_protocol *protocol = evpl_shared->protocol[protocol_id];

    evpl_core_abort_if(!protocol->connect,
                       "Called evpl_connect with non-connection oriented protocol");

    bind = evpl_bind_prepare(evpl, protocol,
                             local_endpoint ? evpl_endpoint_resolve(local_endpoint) : NULL,
                             evpl_endpoint_resolve(remote_endpoint));
    bind->notify_callback  = notify_callback;
    bind->segment_callback = segment_callback;
    bind->private_data     = private_data;

    bind->protocol->connect(evpl, bind);

    return bind;
} /* evpl_connect */

struct evpl_bind *
evpl_bind(
    struct evpl           *evpl,
    enum evpl_protocol_id  protocol_id,
    struct evpl_endpoint  *endpoint,
    evpl_notify_callback_t callback,
    void                  *private_data)
{
    struct evpl_bind     *bind;
    struct evpl_protocol *protocol = evpl_shared->protocol[protocol_id];

    evpl_core_abort_if(!protocol->bind,
                       "Called evpl_bind with connection oriented protocol");

    bind = evpl_bind_prepare(evpl, protocol, evpl_endpoint_resolve(endpoint), NULL);

    bind->notify_callback  = callback;
    bind->segment_callback = NULL;
    bind->private_data     = private_data;

    bind->protocol->bind(evpl, bind);

    return bind;
} /* evpl_bind */

void
evpl_destroy(struct evpl *evpl)
{
    struct evpl_framework *framework;
    struct evpl_bind      *bind;
    int                    i;

    /* Push any open binds into pending close state */
    while (evpl->binds) {
        bind = evpl->binds;
        bind->protocol->pending_close(evpl, bind);
        bind->flags |= EVPL_BIND_PENDING_CLOSED;
        DL_DELETE(evpl->binds, bind);
        DL_APPEND(evpl->pending_close_binds, bind);
    }

    /* Pump events until we have no pending close binds */
    while (evpl->pending_close_binds) {
        evpl_continue(evpl);
    }

    while (evpl->free_binds) {
        bind = evpl->free_binds;
        DL_DELETE(evpl->free_binds, bind);

        evpl_iovec_ring_free(&bind->iovec_send);
        evpl_iovec_ring_free(&bind->iovec_recv);
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

static void
evpl_bind_close_deferral(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_bind *bind = private_data;

    evpl_core_abort_if(bind->flags & EVPL_BIND_CLOSED,
                       "bind %p already closed", bind);

    evpl_core_abort_if(!(bind->flags & EVPL_BIND_PENDING_CLOSED),
                       "bind %p in close deferral but not pending close ", bind)
    ;

    DL_DELETE(evpl->binds, bind);
    DL_APPEND(evpl->pending_close_binds, bind);
    bind->protocol->pending_close(evpl, bind);
} /* evpl_bind_close_deferral */

static void
evpl_bind_flush_deferral(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_bind *conn = private_data;

    if (unlikely(evpl->running == 0)) {
        return;
    }

    if (conn->protocol->flush) {
        conn->protocol->flush(evpl, conn);
    }
} /* evpl_bind_flush_deferral */

void
evpl_attach_framework_shared(enum evpl_framework_id framework_id)
{
    struct evpl_framework *framework = evpl_shared->framework[framework_id];

    pthread_mutex_lock(&evpl_shared->lock);

    if (!evpl_shared->framework_private[framework->id]) {

        evpl_shared->framework_private[framework->id] = framework->init();

        evpl_allocator_reregister(evpl_shared->allocator);
    }

    pthread_mutex_unlock(&evpl_shared->lock);
} /* evpl_attach_framework_shared */

void
evpl_attach_framework(
    struct evpl           *evpl,
    enum evpl_framework_id framework_id)
{
    struct evpl_framework *framework = evpl_shared->framework[framework_id];

    evpl_attach_framework_shared(framework_id);

    if (!evpl->framework_private[framework->id]) {
        evpl->framework_private[framework->id] =
            framework->create(evpl, evpl_shared->framework_private[framework->id
                              ]);
    }
} /* evpl_attach_framework */

struct evpl_bind *
evpl_bind_prepare(
    struct evpl          *evpl,
    struct evpl_protocol *protocol,
    struct evpl_address  *local,
    struct evpl_address  *remote)
{
    struct evpl_framework *framework = protocol->framework;
    struct evpl_bind      *bind;

    if (framework) {
        evpl_attach_framework(evpl, framework->id);
    }

    if (evpl->free_binds) {
        bind = evpl->free_binds;
        DL_DELETE(evpl->free_binds, bind);
    } else {

        bind = evpl_zalloc(sizeof(*bind) + EVPL_MAX_PRIVATE);

        evpl_iovec_ring_alloc(
            &bind->iovec_send,
            evpl_shared->config->iovec_ring_size,
            evpl_shared->config->page_size);

        evpl_dgram_ring_alloc(
            &bind->dgram_send,
            evpl_shared->config->dgram_ring_size,
            evpl_shared->config->page_size);

        evpl_iovec_ring_alloc(
            &bind->iovec_recv,
            evpl_shared->config->iovec_ring_size,
            evpl_shared->config->page_size);

        evpl_deferral_init(&bind->close_deferral,
                           evpl_bind_close_deferral, bind);

        evpl_deferral_init(&bind->flush_deferral,
                           evpl_bind_flush_deferral, bind);
    }

    DL_APPEND(evpl->binds, bind);

    bind->notify_callback  = NULL;
    bind->segment_callback = NULL;
    bind->private_data     = NULL;
    bind->flags            = 0;

    bind->protocol = protocol;
    bind->local    = local;
    bind->remote   = remote;

    memset(bind + 1, 0, EVPL_MAX_PRIVATE);

    return bind;
} /* evpl_bind_prepare */

void
evpl_event_read_interest(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);
    if (!(event->flags & (EVPL_READ_INTEREST | EVPL_WRITE_INTEREST))) {
        evpl->num_enabled_events++;
    }

    event->flags |= EVPL_READ_INTEREST;

    if ((event->flags & EVPL_READ_READY) == EVPL_READ_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_read_interest */

void
evpl_event_read_disinterest(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);
    if ((event->flags & (EVPL_READ_INTEREST | EVPL_WRITE_INTEREST)) == EVPL_READ_INTEREST) {
        evpl->num_enabled_events--;
    }

    event->flags &= ~EVPL_READ_INTEREST;
} /* evpl_event_read_disinterest */

void
evpl_event_write_interest(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    if (!(event->flags & (EVPL_READ_INTEREST | EVPL_WRITE_INTEREST))) {
        evpl->num_enabled_events++;
    }

    event->flags |= EVPL_WRITE_INTEREST;

    if ((event->flags & EVPL_WRITE_READY) == EVPL_WRITE_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_write_interest */

void
evpl_event_write_disinterest(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);
    if ((event->flags & (EVPL_READ_INTEREST | EVPL_WRITE_INTEREST)) == EVPL_WRITE_INTEREST) {
        evpl->num_enabled_events--;
    }

    event->flags &= ~EVPL_WRITE_INTEREST;

} /* evpl_event_write_disinterest */

void
evpl_event_mark_readable(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    event->flags |= EVPL_READABLE;

    if ((event->flags & EVPL_READ_READY) == EVPL_READ_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }
} /* evpl_event_mark_readable */

void
evpl_event_mark_unreadable(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    event->flags &= ~EVPL_READABLE;
} /* evpl_event_mark_unreadable */

void
evpl_event_mark_writable(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    event->flags |= EVPL_WRITABLE;

    if ((event->flags & EVPL_WRITE_READY) == EVPL_WRITE_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_mark_writable */

void
evpl_event_mark_unwritable(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    event->flags &= ~EVPL_WRITABLE;
} /* evpl_event_mark_unwritable */

void
evpl_event_mark_error(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    event->flags |= EVPL_ERROR;

    if (!(event->flags & EVPL_ACTIVE)) {
        event->flags                                  |= EVPL_ACTIVE;
        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_mark_error */

static struct evpl_buffer *
evpl_buffer_alloc(struct evpl *evpl)
{
    struct evpl_buffer *buffer;

    buffer = evpl_allocator_alloc(evpl_shared->allocator);

    atomic_store(&buffer->refcnt, 1);
    buffer->used      = 0;
    buffer->external1 = NULL;
    buffer->external2 = NULL;

    return buffer;
} /* evpl_buffer_alloc */

int
evpl_iovec_reserve(
    struct evpl       *evpl,
    unsigned int       length,
    unsigned int       alignment,
    unsigned int       max_iovecs,
    struct evpl_iovec *r_iovec)
{
    struct evpl_buffer *buffer = evpl->current_buffer;
    int                 pad, left = length, chunk;
    int                 niovs = 0;
    struct evpl_iovec  *iovec;

    do{

        if (evpl->current_buffer == NULL) {
            evpl->current_buffer = evpl_buffer_alloc(evpl);
        }

        buffer = evpl->current_buffer;

        pad = evpl_buffer_pad(buffer, alignment);

        chunk = (buffer->size - buffer->used);

        if (chunk < pad + left && niovs + 1 <= max_iovecs) {
            evpl_buffer_release(buffer);
            evpl->current_buffer = NULL;
            continue;
        }

        if (chunk > pad + left) {
            chunk = pad + left;
        }

        if (unlikely(niovs + 1 > max_iovecs)) {
            return -1;
        }

        iovec = &r_iovec[niovs++];

        iovec->private = buffer;
        iovec->data    = buffer->data + buffer->used + pad;
        iovec->length  = chunk - pad;

        left -= chunk - pad;

        if (left) {
            evpl_buffer_release(buffer);
            evpl->current_buffer = NULL;
        }

    } while (left);

    return niovs;
} /* evpl_iovec_reserve */

void
evpl_iovec_commit(
    struct evpl       *evpl,
    unsigned int       alignment,
    struct evpl_iovec *iovecs,
    int                niovs)
{
    int                 i;
    struct evpl_iovec  *iovec;
    struct evpl_buffer *buffer;

    for (i = 0; i < niovs; ++i) {

        iovec = &iovecs[i];

        buffer = evpl_iovec_buffer(iovec);

        if (buffer) {

        }
        atomic_fetch_add_explicit(&buffer->refcnt, 1, memory_order_relaxed);

        buffer->used  = (iovec->data + iovec->length) - buffer->data;
        buffer->used += evpl_buffer_pad(buffer, alignment);
    }

    buffer = evpl->current_buffer;

    if (buffer && buffer->size - buffer->used < 64) {
        evpl_buffer_release(buffer);
        evpl->current_buffer = NULL;
    }
} /* evpl_iovec_commit */

int
evpl_iovec_alloc(
    struct evpl       *evpl,
    unsigned int       length,
    unsigned int       alignment,
    unsigned int       max_iovecs,
    struct evpl_iovec *r_iovec)
{
    int niovs;

    niovs = evpl_iovec_reserve(evpl, length, alignment, max_iovecs, r_iovec);

    if (unlikely(niovs < 0)) {
        return niovs;
    }

    evpl_iovec_commit(evpl, alignment, r_iovec, niovs);

    return niovs;
} /* evpl_iovec_alloc */

void
evpl_iovec_alloc_whole(
    struct evpl       *evpl,
    struct evpl_iovec *r_iovec)
{
    struct evpl_buffer *buffer;

    buffer = evpl_buffer_alloc(evpl);

    r_iovec->data    = buffer->data;
    r_iovec->length  = buffer->size;
    r_iovec->private = buffer;
} /* evpl_iovec_alloc_whole */

void
evpl_iovec_alloc_datagram(
    struct evpl       *evpl,
    struct evpl_iovec *r_iovec,
    int                size)
{
    struct evpl_buffer *buffer;

    if (!evpl->datagram_buffer) {
        evpl->datagram_buffer = evpl_buffer_alloc(evpl);
    }

    buffer = evpl->datagram_buffer;

    r_iovec->data    = buffer->data + buffer->used;
    r_iovec->length  = size;
    r_iovec->private = buffer;

    buffer->used += size;
    atomic_fetch_add_explicit(&buffer->refcnt, 1, memory_order_relaxed);

    if (buffer->size - buffer->used < evpl_shared->config->max_datagram_size) {
        evpl_buffer_release(evpl->datagram_buffer);
        evpl->datagram_buffer = NULL;
    }

} /* evpl_iovec_alloc_datagram */

void
evpl_buffer_release(struct evpl_buffer *buffer)
{
    int refset;

    refset = atomic_fetch_sub_explicit(&buffer->refcnt, 1, memory_order_relaxed);

    evpl_core_abort_if(refset < 0, "refcnt underflow for buffer %p", buffer);

    if (refset == 1) {
        if (buffer->external1) {
            buffer->release(buffer);
        } else {
            buffer->used = 0;
            evpl_allocator_free(buffer->slab->allocator, buffer);
        }
    }

} /* evpl_buffer_release */

void
evpl_iovec_release(struct evpl_iovec *iovec)
{
    evpl_iovec_decref(iovec);
} /* evpl_iovec_release */

void
evpl_iovec_addref(struct evpl_iovec *iovec)
{
    evpl_iovec_incref(iovec);
} /* evpl_iovec_addref */

void
evpl_send(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    const void       *buffer,
    unsigned int      length)
{
    struct evpl_iovec iovecs[4];
    int               niov;

    niov = evpl_iovec_alloc(evpl, length, 0, 4, iovecs);

    evpl_core_abort_if(niov < 1, "failed to allocate bounce space");

    evpl_iovec_memcpy(iovecs, buffer, length);

    evpl_sendv(evpl, bind, iovecs, niov, length);

} /* evpl_send */

void
evpl_sendto(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *address,
    const void          *buffer,
    unsigned int         length)
{
    struct evpl_iovec iovecs[4];
    int               niov;

    niov = evpl_iovec_alloc(evpl, length, 0, 4, iovecs);

    evpl_core_abort_if(niov < 1, "failed to allocate bounce space");

    evpl_iovec_memcpy(iovecs, buffer, length);

    evpl_sendtov(evpl, bind, address, iovecs, niov, length);

} /* evpl_sendto */

void
evpl_sendtoep(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    const void           *buffer,
    unsigned int          length)
{
    struct evpl_iovec iovecs[4];
    int               niov;

    niov = evpl_iovec_alloc(evpl, length, 0, 4, iovecs);

    evpl_core_abort_if(niov < 1, "failed to allocate bounce space");

    evpl_iovec_memcpy(iovecs, buffer, length);

    evpl_sendtoepv(evpl, bind, endpoint, iovecs, niov, length);

} /* evpl_sendto */

void
evpl_sendv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                niovs,
    int                length)
{
    struct evpl_dgram *dgram;
    struct evpl_iovec *iovec;
    int                i, left = length;

    if (unlikely(niovs == 0)) {
        return;
    }

    for (i = 0; left && i < niovs; ++i) {
        iovec = evpl_iovec_ring_add(&bind->iovec_send, &iovecs[i]);

        if (iovec->length <= left) {
            left -= iovec->length;
        } else {
            bind->iovec_send.length -= iovec->length - left;
            iovec->length            = left;
            left                     = 0;
        }
    }

    evpl_core_abort_if(left,
                       "evpl_send provided iov %d bytes short of covering length of %d",
                       left, length);

    dgram         = evpl_dgram_ring_add(&bind->dgram_send);
    dgram->niov   = i;
    dgram->length = length;
    dgram->addr   = bind->remote;

    evpl_defer(evpl, &bind->flush_deferral);

    for (; i < niovs; ++i) {
        evpl_iovec_release(&iovecs[i]);
    }

} /* evpl_sendv */

void
evpl_sendtov(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *address,
    struct evpl_iovec   *iovecs,
    int                  niovs,
    int                  length)
{
    struct evpl_dgram *dgram;
    struct evpl_iovec *iovec;
    int                i, left = length;

    if (unlikely(niovs == 0)) {
        return;
    }

    for (i = 0; left && i < niovs; ++i) {
        iovec = evpl_iovec_ring_add(&bind->iovec_send, &iovecs[i]);

        if (iovec->length <= left) {
            left -= iovec->length;
        } else {
            bind->iovec_send.length -= iovec->length - left;
            iovec->length            = left;
            left                     = 0;
        }
    }

    evpl_core_abort_if(left,
                       "evpl_send provided iov %d bytes short of covering length of %d",
                       left, length);

    dgram = evpl_dgram_ring_add(&bind->dgram_send);

    dgram->niov   = i;
    dgram->length = length;
    dgram->addr   = address;

    evpl_defer(evpl, &bind->flush_deferral);

    for (; i < niovs; ++i) {
        evpl_iovec_release(&iovecs[i]);
    }

} /* evpl_sendtov */

void
evpl_sendtoepv(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    struct evpl_iovec    *iovecs,
    int                   nbufvecs,
    int                   length)
{
    evpl_sendtov(evpl, bind, evpl_endpoint_resolve(endpoint), iovecs, nbufvecs, length);
} /* evpl_sendtoepv */

void
evpl_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    if (!(bind->flags & EVPL_BIND_PENDING_CLOSED)) {
        bind->flags |= EVPL_BIND_PENDING_CLOSED;
        evpl_defer(evpl, &bind->close_deferral);
    }
} /* evpl_close */

void
evpl_finish(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{

    bind->flags |= EVPL_BIND_FINISH;

    if (evpl_iovec_ring_is_empty(&bind->iovec_send)) {
        evpl_close(evpl, bind);
    }

} /* evpl_finish */

void
evpl_bind_destroy(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_notify notify;

    evpl_core_abort_if(!(bind->flags & EVPL_BIND_PENDING_CLOSED),
                       "bind %p not pending closed at destroy", bind);

    if (bind->notify_callback) {
        notify.notify_type   = EVPL_NOTIFY_DISCONNECTED;
        notify.notify_status = 0;

        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

    evpl_iovec_ring_clear(evpl, &bind->iovec_recv);
    evpl_iovec_ring_clear(evpl, &bind->iovec_send);
    evpl_dgram_ring_clear(evpl, &bind->dgram_send);

    bind->flags |= EVPL_BIND_CLOSED;

    if (bind->local) {
        evpl_address_release(bind->local);
    }

    if (bind->remote) {
        evpl_address_release(bind->remote);
    }
    DL_DELETE(evpl->pending_close_binds, bind);
    DL_PREPEND(evpl->free_binds, bind);
} /* evpl_bind_destroy */

int
evpl_peek(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length)
{
    int                left = length, chunk;
    struct evpl_iovec *cur;
    void              *ptr = buffer;

    if (unlikely(!evpl || !bind || !buffer || length <= 0)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(!bind->protocol->stream)) {
        errno = EINVAL;
        return -1;
    }

    cur = evpl_iovec_ring_tail(&bind->iovec_recv);

    if (cur == NULL) {
        return 0;
    }

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        memcpy(ptr, cur->data, chunk);

        left -= chunk;

        cur = evpl_iovec_ring_next(&bind->iovec_recv, cur);

        if (cur == NULL) {
            return length - left;
        }
    }

    return length;

} /* evpl_peek */

int
evpl_peekv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                maxiovecs,
    int                length)
{
    int                left = length, chunk, niovs = 0;
    struct evpl_iovec *cur, *out;

    if (unlikely(!evpl || !bind || !iovecs || maxiovecs <= 0 || length <= 0)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(!bind->protocol->stream)) {
        errno = EINVAL;
        return -1;
    }

    cur = evpl_iovec_ring_tail(&bind->iovec_recv);

    if (!cur) {
        return 0;
    }

    while (cur && left && niovs < maxiovecs) {
        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        out          = &iovecs[niovs++];
        out->data    = cur->data;
        out->length  = chunk;
        out->private = cur->private;

        left -= chunk;
        cur   = evpl_iovec_ring_next(&bind->iovec_recv, cur);
    }

    return niovs;
} /* evpl_peekv */

void
evpl_consume(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    int               length)
{
    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, length);
} /* evpl_consume */

int
evpl_read(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length)
{
    int                copied = 0, chunk;
    struct evpl_iovec *cur;

    if (unlikely(!evpl || !bind || !buffer || length <= 0)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(!bind->protocol->stream)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(bind->segment_callback)) {
        errno = EINVAL;
        return -1;
    }

    while (copied < length) {

        cur = evpl_iovec_ring_tail(&bind->iovec_recv);

        if (!cur) {
            break;
        }

        chunk = cur->length;

        if (chunk > length - copied) {
            chunk = length - copied;
        }

        memcpy(buffer + copied, cur->data, chunk);

        copied += chunk;

        evpl_iovec_ring_consume(evpl, &bind->iovec_recv, chunk);
    }

    return copied;

} /* evpl_read */

int
evpl_readv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                maxiovecs,
    int                length)
{
    int                left = length, chunk, niovs = 0;
    struct evpl_iovec *cur, *out;

    if (unlikely(!evpl || !bind || !iovecs || maxiovecs <= 0 || length <= 0)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(!bind->protocol->stream)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(bind->segment_callback)) {
        errno = EINVAL;
        return -1;
    }

    while (left && niovs < maxiovecs) {

        cur = evpl_iovec_ring_tail(&bind->iovec_recv);

        if (!cur) {
            break;
        }

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        out = &iovecs[niovs++];

        out->data    = cur->data;
        out->length  = chunk;
        out->private = cur->private;
        atomic_fetch_add_explicit(&evpl_iovec_buffer(out)->refcnt, 1,
                                  memory_order_relaxed)
        ;

        left -= chunk;

        evpl_iovec_ring_consume(evpl, &bind->iovec_recv, chunk);
    }

    return niovs;

} /* evpl_readv */

int
evpl_recv(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length)
{
    int                left = length, chunk;
    struct evpl_iovec *cur;
    void              *ptr   = buffer;
    uint64_t           avail = evpl_iovec_ring_bytes(&bind->iovec_recv);

    if (avail < length) {
        return -1;
    }

    cur = evpl_iovec_ring_tail(&bind->iovec_recv);

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        memcpy(ptr, cur->data, chunk);

        left -= chunk;

        cur = evpl_iovec_ring_next(&bind->iovec_recv, cur);
    }

    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, length);

    return length;

} /* evpl_recv */

int
evpl_recvv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                maxiovecs,
    int                length)
{
    int                left = length, chunk, niovs = 0;
    struct evpl_iovec *cur, *out;
    uint64_t           avail = evpl_iovec_ring_bytes(&bind->iovec_recv);

    if (avail < length) {
        return -1;
    }

    cur = evpl_iovec_ring_tail(&bind->iovec_recv);

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        if (niovs == maxiovecs) {
            return -1;
        }

        out = &iovecs[niovs++];

        out->data    = cur->data;
        out->length  = chunk;
        out->private = cur->private;
        atomic_fetch_add_explicit(&evpl_iovec_buffer(out)->refcnt, 1,
                                  memory_order_relaxed)
        ;

        left -= chunk;

        cur = evpl_iovec_ring_next(&bind->iovec_recv, cur);
    }

    if (left) {
        return -1;
    }

    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, length);

    return niovs;
} /* evpl_recvv */

void
evpl_rdma_read(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    struct evpl_protocol *protocol = bind->protocol;

    if (unlikely(!protocol->rdma_read)) {
        callback(ENOTSUP, private_data);
        return;
    }

    protocol->rdma_read(evpl, bind, remote_key, remote_address, iov, niov,
                        callback, private_data);
} /* evpl_rdma_read */

void
evpl_rdma_write(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    struct evpl_protocol *protocol = bind->protocol;

    if (unlikely(!protocol->rdma_write)) {
        callback(ENOTSUP, private_data);
        return;
    }

    protocol->rdma_write(evpl, bind, remote_key, remote_address, iov, niov,
                         callback, private_data);
} /* evpl_rdma_write */

int
evpl_recv_peek_iovec(
    struct evpl       *evpl,
    struct evpl_bind  *conn,
    struct evpl_iovec *iovecs,
    int                nbufvecs,
    int                length)
{
    int niovs = 0, left = length;

    do{

    } while (left);

    return niovs;

} /* evpl_recv_peek_iovec */

const char *
evpl_endpoint_address(const struct evpl_endpoint *ep)
{
    return ep->address;
} /* evpl_endpoint_address */

int
evpl_endpoint_port(const struct evpl_endpoint *ep)
{
    return ep->port;
} /* evpl_endpoint_port */

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

static void
evpl_event_user_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_doorbell *doorbell = container_of(event, struct evpl_doorbell, event);

    uint64_t              word;
    ssize_t               len;

    len = read(event->fd, &word, sizeof(word));

    if (len != sizeof(word)) {
        evpl_event_mark_unreadable(evpl, event);
        return;
    }

    doorbell->callback(evpl, doorbell);
} /* evpl_event_user_callback */

void
evpl_add_doorbell(
    struct evpl             *evpl,
    struct evpl_doorbell    *doorbell,
    evpl_doorbell_callback_t callback)
{
    struct evpl_event *event = &doorbell->event;

    evpl_add_event(evpl, event, eventfd(0, EFD_NONBLOCK),
                   evpl_event_user_callback, NULL, NULL);

    evpl_event_read_interest(evpl, event);

    doorbell->callback = callback;

    DL_APPEND(evpl->doorbells, doorbell);

} /* evpl_add_event_user */

void
evpl_remove_doorbell(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    pthread_mutex_lock(&evpl->lock);
    DL_DELETE(evpl->doorbells, doorbell);
    pthread_mutex_unlock(&evpl->lock);

    evpl_remove_event(evpl, &doorbell->event);

    close(doorbell->event.fd);
} /* evpl_remove_doorbell */

void
evpl_remove_timer(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    int i;

    for (i = 0; i < evpl->num_timers; i++) {
        if (evpl->timers[i] == timer) {
            break;
        }
    }

    if (i >= evpl->num_timers) {
        return;
    }

    evpl->num_timers--;

    if (i == evpl->num_timers) {
        return;
    }

    evpl->timers[i] = evpl->timers[evpl->num_timers];

    i = evpl_timer_heap_down(evpl, i);

    evpl_timer_heap_up(evpl, i);
} /* evpl_timer_remove */

void
evpl_add_timer(
    struct evpl          *evpl,
    struct evpl_timer    *timer,
    evpl_timer_callback_t callback,
    uint64_t              interval_us)
{
    timer->callback = callback;
    timer->interval = interval_us;

    evpl_timer_insert(evpl, timer);
} /* evpl_add_timer */

void
evpl_ring_doorbell(struct evpl_doorbell *doorbell)
{
    uint64_t word = 1;
    ssize_t  len;

    len = write(doorbell->event.fd, &word, sizeof(word));

    evpl_core_abort_if(len != sizeof(word), "failed to write to doorbell fd");
} /* evpl_ring_doorbell */

void
evpl_remove_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    evpl_core_remove(&evpl->core, event);
    evpl->num_events--;
} /* evpl_remove_event */

struct evpl_poll *
evpl_add_poll(
    struct evpl               *evpl,
    evpl_poll_enter_callback_t enter_callback,
    evpl_poll_exit_callback_t  exit_callback,
    evpl_poll_callback_t       callback,
    void                      *private_data)
{
    struct evpl_poll *poll = &evpl->poll[evpl->num_poll];

    poll->enter_callback = enter_callback;
    poll->exit_callback  = exit_callback;
    poll->callback       = callback;
    poll->private_data   = private_data;

    ++evpl->num_poll;

    return poll;
} /* evpl_add_poll */
void
evpl_remove_poll(
    struct evpl      *evpl,
    struct evpl_poll *poll)
{
    int index = poll - evpl->poll;

    if (index + 1 < evpl->num_poll) {
        evpl->poll[index] = evpl->poll[evpl->num_poll - 1];
    }

    evpl->num_poll--;

} /* evpl_remove_poll */

void
evpl_defer(
    struct evpl          *evpl,
    struct evpl_deferral *deferral)
{
    int index;

    if (!deferral->armed) {
        deferral->armed = 1;
        index           = evpl->num_active_deferrals;

        evpl->active_deferrals[index] = deferral;

        ++evpl->num_active_deferrals;
    }

} /* evpl_defer */

void
evpl_remove_deferral(
    struct evpl          *evpl,
    struct evpl_deferral *deferral)
{
    int i;

    if (!deferral->armed) {
        return;
    }

    for (i = 0; i < evpl->num_active_deferrals; ++i) {

        if (evpl->active_deferrals[i] != deferral) {
            continue;
        }

        deferral->armed = 0;

        if (i + 1 < evpl->num_active_deferrals) {
            evpl->active_deferrals[i] = evpl->active_deferrals[evpl->
                                                               num_active_deferrals
                                                               - 1];
        }

        --evpl->num_active_deferrals;
    }

} /* evpl_defer */

int
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

void
evpl_bind_request_send_notifications(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    bind->flags |= EVPL_BIND_SENT_NOTIFY;
} /* evpl_bind_request_send_notifications */

int
evpl_protocol_is_stream(enum evpl_protocol_id id)
{
    return evpl_shared->protocol[id]->stream;
} /* evpl_protocol_is_stream */

struct evpl_address *
evpl_address_alloc(void)
{
    struct evpl_address *address;

    address = evpl_zalloc(sizeof(*address));

    address->addr = (struct sockaddr *) &address->sa;
    atomic_init(&address->refcnt, 1);
    address->next = NULL;

    return address;
} /* evpl_address_alloc */

struct evpl_address *
evpl_address_init(
    struct sockaddr *addr,
    socklen_t        addrlen)
{
    struct evpl_address *ea = evpl_address_alloc();

    ea->addrlen = addrlen;
    memcpy(ea->addr, addr, addrlen);

    return ea;

} /* evpl_address_init */

void
evpl_address_release(struct evpl_address *address)
{
    int i;

    if (atomic_fetch_sub(&address->refcnt, 1) > 1) {
        return;
    }

    for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {

        if (!address->framework_private[i]) {
            continue;
        }

        evpl_shared->framework[i]->release_address(
            address->framework_private[i],
            evpl_shared->framework_private[i]);
    }

    evpl_free(address);
} /* evpl_address_release */

void
evpl_bind_get_local_address(
    struct evpl_bind *bind,
    char             *str,
    int               len)
{
    evpl_address_get_address(bind->local, str, len);
} /* evpl_bind_get_local_address */

void
evpl_bind_get_remote_address(
    struct evpl_bind *bind,
    char             *str,
    int               len)
{
    evpl_address_get_address(bind->remote, str, len);
} /* evpl_bind_get_remote_address */

enum evpl_protocol_id
evpl_bind_get_protocol(struct evpl_bind *bind)
{
    return bind->protocol->id;
} /* evpl_bind_get_protocol */

struct evpl_block_device *
evpl_block_open_device(
    enum evpl_block_protocol_id protocol_id,
    const char                 *uri)
{
    struct evpl_block_protocol *protocol;
    struct evpl_block_device   *blockdev;
    void                       *protocol_private_data;

    __evpl_init();

    if (protocol_id >= EVPL_NUM_BLOCK_PROTOCOL) {
        return NULL;
    }


    protocol = evpl_shared->block_protocol[protocol_id];

    evpl_attach_framework_shared(protocol->framework->id);

    protocol_private_data = evpl_shared->framework_private[protocol->framework->
                                                           id];

    blockdev = protocol->open_device(uri, protocol_private_data);

    blockdev->protocol = protocol;

    return blockdev;
} /* evpl_block_open_device */

void
evpl_block_close_device(struct evpl_block_device *bdev)
{
    bdev->close_device(bdev);
} /* evpl_block_close_device */

uint64_t
evpl_block_size(struct evpl_block_device *bdev)
{
    return bdev->size;
} /* evpl_block_size */

uint64_t
evpl_block_max_request_size(struct evpl_block_device *bdev)
{
    return bdev->max_request_size;
} /* evpl_block_max_request_size */

struct evpl_block_queue *
evpl_block_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *blockdev)
{
    struct evpl_block_queue *queue;

    evpl_attach_framework(evpl, blockdev->protocol->framework->id);

    queue = blockdev->open_queue(evpl, blockdev);

    queue->protocol = blockdev->protocol;

    return queue;
} /* evpl_block_open_queue */

void
evpl_block_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *queue)
{
    queue->close_queue(evpl, queue);
} /* evpl_block_close_queue */


void
evpl_block_read(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    queue->read(evpl, queue, iov, niov, offset, callback, private_data);
} /* evpl_block_read */

void
evpl_block_write(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    int sync,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    queue->write(evpl, queue, iov, niov, offset, sync, callback, private_data);
} /* evpl_block_write */

void
evpl_block_flush(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    queue->flush(evpl, queue, callback, private_data);
} /* evpl_block_flush */

void *
evpl_slab_alloc(void)
{
    return evpl_allocator_alloc_slab(evpl_shared->allocator);
} /* evpl_slab_alloc */

