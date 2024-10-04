/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <pthread.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "utlist.h"

#if EVPL_MECH == epoll
#include "core/epoll.h"
#else  /* if EVPL_MECH == epoll */
#error  No EVPL_MECH
#endif /* if EVPL_MECH == epoll */

#include "core/evpl.h"
#include "core/protocol.h"
#include "core/internal.h"
#include "core/event.h"
#include "core/buffer.h"
#include "core/bind.h"
#include "core/endpoint.h"
#include "core/poll.h"

#ifdef HAVE_RDMACM
#include "rdmacm/rdmacm.h"
#endif /* ifdef HAVE_RDMACM */

#include "socket/udp.h"
#include "socket/tcp.h"

struct evpl_shared {
    struct evpl_config    *config;
    struct evpl_framework *framework[EVPL_NUM_FRAMEWORK];
    void                  *framework_private[EVPL_NUM_FRAMEWORK];
    struct evpl_protocol  *protocol[EVPL_NUM_PROTO];
    void                  *protocol_private[EVPL_NUM_PROTO];
};

pthread_once_t      evpl_shared_once = PTHREAD_ONCE_INIT;
struct evpl_shared *evpl_shared      = NULL;

struct evpl {
    struct evpl_core       core; /* must be first */


    void                  *protocol_private[EVPL_NUM_PROTO];
    void                  *framework_private[EVPL_NUM_FRAMEWORK];

    struct evpl_poll      *poll;
    int                    num_poll;
    int                    max_poll;

    struct evpl_event    **active_events;
    int                    num_active_events;
    int                    max_active_events;

    int                    active_reserve;

    struct evpl_deferral **active_deferrals;
    int                    num_active_deferrals;
    int                    max_active_deferrals;

    struct evpl_buffer    *current_buffer;
    struct evpl_buffer    *datagram_buffer;
    struct evpl_buffer    *free_buffers;
    struct evpl_bind      *free_binds;
    struct evpl_address   *free_address;
    struct evpl_endpoint  *endpoints;
    struct evpl_config    *config;
    struct evpl_bind      *binds;

};

static void
evpl_framework_init(
    struct evpl_shared    *evpl_shared,
    unsigned int           id,
    struct evpl_framework *framework)
{
    evpl_shared->framework[id] = framework;

    evpl_shared->framework_private[id] = framework->init();
} /* evpl_framework_init */

static void
evpl_framework_cleanup(
    struct evpl_shared *evpl_shared,
    unsigned int        id)
{
    struct evpl_framework *framework = evpl_shared->framework[id];

    framework->cleanup(evpl_shared->framework_private[id]);
} /* evpl_framework_cleanup */

static void
evpl_protocol_init(
    struct evpl_shared   *evpl_shared,
    unsigned int          id,
    struct evpl_protocol *protocol)
{
    evpl_shared->protocol[id] = protocol;
} /* evpl_protocol_init */

static void
evpl_shared_init(struct evpl_config *config)
{
    evpl_shared = evpl_zalloc(sizeof(*evpl_shared));

    if (!config) {
        config = evpl_config_init();
    }

    evpl_shared->config = config;

    evpl_protocol_init(evpl_shared, EVPL_DATAGRAM_SOCKET_UDP,
                       &evpl_socket_udp);

    evpl_protocol_init(evpl_shared, EVPL_STREAM_SOCKET_TCP,
                       &evpl_socket_tcp);

#ifdef HAVE_RDMACM
    evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_RDMACM, &evpl_rdmacm);
    evpl_protocol_init(evpl_shared, EVPL_DATAGRAM_RDMACM_RC,
                       &evpl_rdmacm_rc_datagram);
    evpl_protocol_init(evpl_shared, EVPL_STREAM_RDMACM_RC,
                       &evpl_rdmacm_rc_stream);
    evpl_protocol_init(evpl_shared, EVPL_DATAGRAM_RDMACM_UD,
                       &evpl_rdmacm_ud_datagram);
#endif /* ifdef HAVE_RDMACM */

} /* evpl_shared_init */

void
evpl_init_auto(struct evpl_config *config)
{
    evpl_shared_init(config);
    atexit(evpl_cleanup);
} /* evpl_init_auto */

void
evpl_init(struct evpl_config *config)
{
    evpl_shared_init(config);
} /* evpl_init */

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
evpl_cleanup()
{
    unsigned int i;

    for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {
        evpl_framework_cleanup(evpl_shared, i);
    }

    evpl_config_release(evpl_shared->config);

    evpl_free(evpl_shared);
    evpl_shared = NULL;
} /* evpl_cleanup */

struct evpl *
evpl_create()
{
    struct evpl           *evpl;
    struct evpl_framework *framework;
    int                    i;

    pthread_once(&evpl_shared_once, evpl_init_once);

    evpl = evpl_zalloc(sizeof(*evpl));

    evpl->poll     = evpl_calloc(256, sizeof(struct evpl_poll));
    evpl->max_poll = 256;

    evpl->active_events     = evpl_calloc(256, sizeof(struct evpl_event *));
    evpl->max_active_events = 256;

    evpl->active_deferrals = evpl_calloc(256, sizeof(struct
                                                     evpl_deferral *));
    evpl->max_active_deferrals = 256;

    evpl->config = evpl_shared->config;
    evpl->config->refcnt++;

    evpl_core_init(&evpl->core, 64);

    for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {
        framework = evpl_shared->framework[i];

        if (!framework->create) {
            continue;
        }

        evpl->framework_private[i] = framework->create(evpl,
                                                       evpl_shared->
                                                       framework_private[i]);
    }

    return evpl;
} /* evpl_init */

void
evpl_wait(
    struct evpl *evpl,
    int          max_msecs)
{
    struct evpl_event    *event;
    struct evpl_deferral *deferral;
    struct evpl_poll     *poll;
    int                   i;

    for (i = 0; i < evpl->num_poll; ++i) {
        poll = &evpl->poll[i];
        poll->callback(evpl, poll->private_data);
    }

    if (!evpl->num_active_events &&
        !evpl->num_active_deferrals) {
        evpl_core_wait(&evpl->core, max_msecs);
    }

    while (evpl->num_active_events) {
        for (i = 0; i < evpl->num_active_events; ++i) {
            event = evpl->active_events[i];

            if ((event->flags & EVPL_READ_READY) == EVPL_READ_READY) {
                event->read_callback(evpl, event);
            }

            if ((event->flags & EVPL_WRITE_READY) ==
                EVPL_WRITE_READY) {
                event->write_callback(evpl, event);
            }

            if ((event->flags & EVPL_READ_READY)  != EVPL_READ_READY &&
                (event->flags & EVPL_WRITE_READY) != EVPL_WRITE_READY) {

                event->flags &= ~EVPL_ACTIVE;

                if (i + 1 < evpl->num_active_events) {
                    evpl->active_events[i] =
                        evpl->active_events[evpl->num_active_events - 1];
                }
                --evpl->num_active_events;
            }
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

struct evpl_bind *
evpl_listen(
    struct evpl           *evpl,
    enum evpl_protocol_id  protocol_id,
    struct evpl_endpoint  *endpoint,
    evpl_accept_callback_t accept_callback,
    void                  *private_data)
{
    struct evpl_bind *bind;

    if (!endpoint->addr) {
        evpl_endpoint_resolve(evpl, endpoint);
    }

    bind = evpl_bind_alloc(evpl,
                           evpl_shared->protocol[protocol_id],
                           endpoint->addr,
                           NULL);

    evpl_core_abort_if(!bind->protocol->listen,
                       "evpl_listen called with non-connection oriented protocol");

    bind->accept_callback = accept_callback;
    bind->private_data    = private_data;

    bind->protocol->listen(evpl, bind);

    return bind;
} /* evpl_listen */

struct evpl_endpoint *
evpl_endpoint_create(
    struct evpl *evpl,
    const char  *address,
    int          port)
{
    struct evpl_endpoint *ep;

    ep = evpl_zalloc(sizeof(*ep));

    ep->port   = port;
    ep->refcnt = 1;
    strncpy(ep->address, address, sizeof(ep->address) - 1);

    ep->addr = NULL;

    DL_APPEND(evpl->endpoints, ep);

    return ep;
} /* evpl_endpoint_create */


void
evpl_endpoint_close(
    struct evpl          *evpl,
    struct evpl_endpoint *endpoint)
{
    struct evpl_address *addr;

    --endpoint->refcnt;

    if (endpoint->refcnt == 0) {

        while (endpoint->addr) {
            addr = endpoint->addr;
            LL_DELETE(endpoint->addr, addr);
            evpl_address_release(evpl, addr);
        }

        DL_DELETE(evpl->endpoints, endpoint);
        evpl_free(endpoint);
    }
} /* evpl_endpoint_close */

int
evpl_endpoint_resolve(
    struct evpl          *evpl,
    struct evpl_endpoint *endpoint)
{
    char                 port_str[8];
    struct addrinfo      hints, *ai, *p;
    struct evpl_address *cur, *last = NULL;
    int                  rc;

    if (endpoint->addr) {
        return 0;
    }

    snprintf(port_str, sizeof(port_str), "%d", endpoint->port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_INET;
    hints.ai_socktype = 0;//SOCK_DGRAM;
    hints.ai_flags    = 0;

    rc = getaddrinfo(endpoint->address, port_str, &hints, &ai);

    if (unlikely(rc < 0)) {
        return rc;
    }

    for (p = ai; p != NULL; p = p->ai_next) {

        cur = evpl_address_init(evpl, p->ai_addr, p->ai_addrlen);

        if (last) {
            last->next = cur;
        } else {
            endpoint->addr = cur;
        }

        last = cur;
    }

    freeaddrinfo(ai);

    return 0;
} /* evpl_endpoint_resolve */


struct evpl_bind *
evpl_connect(
    struct evpl           *evpl,
    enum evpl_protocol_id  protocol_id,
    struct evpl_endpoint  *endpoint,
    evpl_notify_callback_t callback,
    void                  *private_data)
{
    struct evpl_bind     *bind;
    struct evpl_protocol *protocol = evpl_shared->protocol[protocol_id];

    if (!endpoint->addr) {
        evpl_endpoint_resolve(evpl, endpoint);
    }

    evpl_core_abort_if(!protocol->connect,
                       "Called evpl_connect with non-connection oriented protocol");

    bind               = evpl_bind_alloc(evpl, protocol, NULL, endpoint->addr);
    bind->protocol     = protocol;
    bind->callback     = callback;
    bind->private_data = private_data;

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

    if (!endpoint->addr) {
        evpl_endpoint_resolve(evpl, endpoint);
    }

    evpl_core_abort_if(!protocol->bind,
                       "Called evpl_bind with connection oriented protocol");

    bind               = evpl_bind_alloc(evpl, protocol, endpoint->addr, NULL);
    bind->protocol     = protocol;
    bind->callback     = callback;
    bind->private_data = private_data;

    bind->protocol->bind(evpl, bind);

    return bind;
} /* evpl_bind */
void
evpl_destroy(struct evpl *evpl)
{
    struct evpl_framework *framework;
    struct evpl_bind      *bind;
    struct evpl_buffer    *buffer;
    struct evpl_address   *address;
    int                    i;

    while (evpl->binds) {
        bind = evpl->binds;
        evpl_bind_destroy(evpl, bind);
    }

    while (evpl->free_binds) {
        bind = evpl->free_binds;
        DL_DELETE(evpl->free_binds, bind);

        evpl_bvec_ring_free(&bind->bvec_send);
        evpl_bvec_ring_free(&bind->bvec_recv);
        evpl_dgram_ring_free(&bind->dgram_send);
        evpl_free(bind);
    }

    while (evpl->endpoints) {
        evpl_endpoint_close(evpl, evpl->endpoints);
    }

    while (evpl->free_address) {
        address = evpl->free_address;
        LL_DELETE(evpl->free_address, address);
        evpl_free(address);
    }

    for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {
        framework = evpl_shared->framework[i];

        if (!framework->destroy) {
            continue;
        }

        framework->destroy(evpl, evpl->framework_private[i]);
    }

    while (evpl->current_buffer) {
        buffer = evpl->current_buffer;
        LL_DELETE(evpl->current_buffer, buffer);

        evpl_buffer_release(evpl, buffer);
    }

    if (evpl->datagram_buffer) {
        evpl_buffer_release(evpl, evpl->datagram_buffer);
    }

    while (evpl->free_buffers) {
        buffer = evpl->free_buffers;
        LL_DELETE(evpl->free_buffers, buffer);

        evpl_core_fatal_if(buffer->refcnt,
                           "Buffer %p has refcnt %u at evpl_destroy",
                           buffer, buffer->refcnt);

        for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {
            framework = evpl_shared->framework[i];

            if (!framework || !framework->unregister_buffer) {
                continue;
            }

            framework->unregister_buffer(
                buffer->framework_private[i],
                evpl_shared->framework_private[i]);
        }

        evpl_free(buffer->data);
        evpl_free(buffer);
    }

    evpl_core_destroy(&evpl->core);

    evpl_config_release(evpl->config);
    evpl_free(evpl->active_events);
    evpl_free(evpl->active_deferrals);
    evpl_free(evpl->poll);
    evpl_free(evpl);
} /* evpl_destroy */

static void
evpl_bind_close_deferral(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_bind *conn = private_data;

    evpl_bind_destroy(evpl, conn);
} /* evpl_bind_close_deferral */

static void
evpl_bind_flush_deferral(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_bind *conn = private_data;

    if (conn->protocol->flush) {
        conn->protocol->flush(evpl, conn);
    }
} /* evpl_bind_flush_deferral */


struct evpl_bind *
evpl_bind_alloc(
    struct evpl          *evpl,
    struct evpl_protocol *protocol,
    struct evpl_address  *local,
    struct evpl_address  *remote)
{
    struct evpl_bind *bind;

    if (evpl->free_binds) {
        bind = evpl->free_binds;
        DL_DELETE(evpl->free_binds, bind);
    } else {

        bind = evpl_zalloc(sizeof(*bind) + EVPL_MAX_PRIVATE);

        evpl_bvec_ring_alloc(
            &bind->bvec_send,
            evpl->config->bvec_ring_size,
            evpl->config->page_size);

        evpl_dgram_ring_alloc(
            &bind->dgram_send,
            evpl->config->dgram_ring_size,
            evpl->config->page_size);

        evpl_bvec_ring_alloc(
            &bind->bvec_recv,
            evpl->config->bvec_ring_size,
            evpl->config->page_size);

        evpl_deferral_init(&bind->close_deferral,
                           evpl_bind_close_deferral, bind);

        evpl_deferral_init(&bind->flush_deferral,
                           evpl_bind_flush_deferral, bind);

    }

    DL_APPEND(evpl->binds, bind);
    bind->protocol = protocol;
    bind->local    = local;

    if (local) {
        local->refcnt++;
    }

    bind->remote = remote;

    if (remote) {
        remote->refcnt++;
    }

    return bind;
} /* evpl_bind_alloc */

void
evpl_event_read_interest(
    struct evpl       *evpl,
    struct evpl_event *event)
{

    event->flags |= EVPL_READ_INTEREST;

    if ((event->flags & EVPL_READ_READY) == EVPL_READ_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_read_interest */

void
evpl_event_read_disinterest(struct evpl_event *event)
{
    event->flags &= ~EVPL_READ_INTEREST;
} /* evpl_event_read_disinterest */

void
evpl_event_write_interest(
    struct evpl       *evpl,
    struct evpl_event *event)
{

    event->flags |= EVPL_WRITE_INTEREST;

    if ((event->flags & EVPL_WRITE_READY) == EVPL_WRITE_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_write_interest */

void
evpl_event_write_disinterest(struct evpl_event *event)
{

    event->flags &= ~EVPL_WRITE_INTEREST;

} /* evpl_event_write_disinterest */


void
evpl_event_mark_readable(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    event->flags |= EVPL_READABLE;

    if ((event->flags & EVPL_READ_READY) == EVPL_READ_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }
} /* evpl_event_mark_readable */

void
evpl_event_mark_unreadable(struct evpl_event *event)
{
    event->flags &= ~EVPL_READABLE;
} /* evpl_event_mark_unreadable */

void
evpl_event_mark_writable(
    struct evpl       *evpl,
    struct evpl_event *event)
{

    event->flags |= EVPL_WRITABLE;

    if ((event->flags & EVPL_WRITE_READY) == EVPL_WRITE_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_mark_writable */

void
evpl_event_mark_unwritable(struct evpl_event *event)
{
    event->flags &= ~EVPL_WRITABLE;
} /* evpl_event_mark_unwritable */

void
evpl_event_mark_error(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    event->flags |= EVPL_ERROR;

    if (!(event->flags & EVPL_ACTIVE)) {
        event->flags                                  |= EVPL_ACTIVE;
        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_mark_error */


static struct evpl_buffer *
evpl_buffer_alloc(struct evpl *evpl)
{
    struct evpl_framework *framework;
    struct evpl_buffer    *buffer;
    int                    i;

    if (evpl->free_buffers) {
        buffer = evpl->free_buffers;
        LL_DELETE(evpl->free_buffers, buffer);
        return buffer;
    } else {
        buffer       = evpl_malloc(sizeof(*buffer));
        buffer->size = evpl->config->buffer_size;

        buffer->data = evpl_valloc(
            buffer->size,
            evpl->config->page_size);

        for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {
            framework = evpl_shared->framework[i];

            if (!framework || !framework->register_buffer) {
                continue;
            }

            buffer->framework_private[i] = framework->register_buffer(
                buffer->data, buffer->size,
                evpl_shared->framework_private[i]);

        }

    }

    buffer->refcnt = 0;
    buffer->used   = 0;
    buffer->next   = NULL;

    return buffer;
} /* evpl_buffer_alloc */

int
evpl_bvec_reserve(
    struct evpl      *evpl,
    unsigned int      length,
    unsigned int      alignment,
    unsigned int      max_bvecs,
    struct evpl_bvec *r_bvec)
{
    struct evpl_buffer *buffer = evpl->current_buffer;
    int                 pad, left = length, chunk;
    int                 nbvecs = 0;
    struct evpl_bvec   *bvec;

    if (buffer == NULL) {
        buffer = evpl_buffer_alloc(evpl);
        LL_PREPEND(evpl->current_buffer, buffer);
        ++buffer->refcnt;
    }

    do {

        pad = evpl_buffer_pad(buffer, alignment);

        chunk = (buffer->size - buffer->used);

        if (chunk > pad + left) {
            chunk = pad + left;
        }

        if (unlikely(nbvecs + 1 > max_bvecs)) {
            return -1;
        }

        bvec = &r_bvec[nbvecs++];

        bvec->buffer = buffer;
        bvec->data   = buffer->data + buffer->used + pad;
        bvec->length = chunk - pad;

        if (!buffer->next) {
            buffer->next       = evpl_buffer_alloc(evpl);
            buffer->next->next = NULL;
            buffer->next->refcnt++;
        }

        buffer = buffer->next;

        left -= chunk - pad;

    } while (left);

    return nbvecs;
} /* evpl_bvec_reserve */

void
evpl_bvec_commit(
    struct evpl      *evpl,
    unsigned int      alignment,
    struct evpl_bvec *bvecs,
    int               nbvecs)
{
    int                 i;
    struct evpl_bvec   *bvec;
    struct evpl_buffer *buffer;

    for (i = 0; i < nbvecs; ++i) {

        bvec = &bvecs[i];

        buffer = bvec->buffer;

        ++buffer->refcnt;

        buffer->used  = (bvec->data + bvec->length) - buffer->data;
        buffer->used += evpl_buffer_pad(buffer, alignment);

        if (buffer->size - buffer->used < 64) {
            LL_DELETE(evpl->current_buffer, buffer);
            evpl_buffer_release(evpl, buffer);
        }
    }

} /* evpl_bvec_commit */

int
evpl_bvec_alloc(
    struct evpl      *evpl,
    unsigned int      length,
    unsigned int      alignment,
    unsigned int      max_bvecs,
    struct evpl_bvec *r_bvec)
{
    int nbvecs;

    nbvecs = evpl_bvec_reserve(evpl, length, alignment, max_bvecs, r_bvec);

    if (unlikely(nbvecs < 0)) {
        return nbvecs;
    }

    evpl_bvec_commit(evpl, alignment, r_bvec, nbvecs);

    return nbvecs;
} /* evpl_bvec_alloc */

void
evpl_bvec_alloc_whole(
    struct evpl      *evpl,
    struct evpl_bvec *r_bvec)
{
    struct evpl_buffer *buffer;

    buffer = evpl_buffer_alloc(evpl);

    buffer->refcnt = 1;

    r_bvec->data   = buffer->data;
    r_bvec->length = buffer->size;
    r_bvec->buffer = buffer;
} /* evpl_bvec_alloc_whole */

void
evpl_bvec_alloc_datagram(
    struct evpl      *evpl,
    struct evpl_bvec *r_bvec)
{
    struct evpl_buffer *buffer;

    if (!evpl->datagram_buffer) {
        evpl->datagram_buffer = evpl_buffer_alloc(evpl);
        evpl->datagram_buffer->refcnt++;
    }

    buffer = evpl->datagram_buffer;

    r_bvec->data   = buffer->data + buffer->used;
    r_bvec->length = evpl->config->max_datagram_size;
    r_bvec->buffer = buffer;

    buffer->used += evpl->config->max_datagram_size;
    buffer->refcnt++;

    if (buffer->size - buffer->used < evpl->config->max_datagram_size) {
        evpl_buffer_release(evpl, evpl->datagram_buffer);
        evpl->datagram_buffer = NULL;
    }

} /* evpl_bvec_alloc_datagram */

void
evpl_buffer_release(
    struct evpl        *evpl,
    struct evpl_buffer *buffer)
{
    evpl_core_abort_if(buffer->refcnt == 0,
                       "Released buffer %p with zero refcnt", buffer);

    --buffer->refcnt;

    if (buffer->refcnt == 0) {
        buffer->used = 0;
        LL_PREPEND(evpl->free_buffers, buffer);
    }

} /* evpl_buffer_release */

void
evpl_bvec_release(
    struct evpl      *evpl,
    struct evpl_bvec *bvec)
{
    evpl_bvec_decref(evpl, bvec);
} /* evpl_bvec_release */

void
evpl_bvec_addref(
    struct evpl      *evpl,
    struct evpl_bvec *bvec)
{
    evpl_bvec_incref(evpl, bvec);
} /* evpl_bvec_addref */

void
evpl_send(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    const void       *buffer,
    unsigned int      length)
{
    struct evpl_bvec bvecs[4];
    int              nbvec;

    nbvec = evpl_bvec_alloc(evpl, length, 0, 4, bvecs);

    evpl_core_abort_if(nbvec < 1, "failed to allocate bounce space");

    evpl_bvec_memcpy(bvecs, buffer, length);

    evpl_sendv(evpl, bind, bvecs, nbvec, length);

} /* evpl_send */

void
evpl_sendto(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    const void           *buffer,
    unsigned int          length)
{
    struct evpl_bvec bvecs[4];
    int              nbvec;

    nbvec = evpl_bvec_alloc(evpl, length, 0, 4, bvecs);

    evpl_core_abort_if(nbvec < 1, "failed to allocate bounce space");

    evpl_bvec_memcpy(bvecs, buffer, length);

    evpl_sendtov(evpl, bind, endpoint, bvecs, nbvec, length);

} /* evpl_sendto */

void
evpl_sendv(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    struct evpl_bvec *bvecs,
    int               nbufvecs,
    int               length)
{
    struct evpl_dgram *dgram;
    int                i;

    if (unlikely(nbufvecs == 0)) {
        return;
    }

    for (i = 0; i < nbufvecs; ++i) {
        evpl_bvec_ring_add(&bind->bvec_send, &bvecs[i]);
    }

    if (!bind->protocol->stream) {
        dgram        = evpl_dgram_ring_add(&bind->dgram_send);
        dgram->nbvec = nbufvecs;
        dgram->addr  = bind->remote;
    }


    evpl_defer(evpl, &bind->flush_deferral);

} /* evpl_sendv */

void
evpl_sendtov(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    struct evpl_bvec     *bvecs,
    int                   nbufvecs,
    int                   length)
{
    struct evpl_dgram *dgram;
    int                i;

    if (unlikely(nbufvecs == 0)) {
        return;
    }

    if (!endpoint->addr) {
        evpl_endpoint_resolve(evpl, endpoint);
    }

    for (i = 0; i < nbufvecs; ++i) {
        evpl_bvec_ring_add(&bind->bvec_send, &bvecs[i]);
    }


    dgram = evpl_dgram_ring_add(&bind->dgram_send);

    dgram->nbvec = nbufvecs;
    dgram->addr  = endpoint->addr;
    dgram->addr->refcnt++;

    evpl_defer(evpl, &bind->flush_deferral);

} /* evpl_sendtov */


void
evpl_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    evpl_defer(evpl, &bind->close_deferral);
} /* evpl_close */

void
evpl_finish(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{

    bind->flags |= EVPL_BIND_FINISH;

    if (evpl_bvec_ring_is_empty(&bind->bvec_send)) {
        evpl_defer(evpl, &bind->close_deferral);
    }

} /* evpl_finish */

struct evpl_config *
evpl_config(struct evpl *evpl)
{
    return evpl->config;
} /* evpl_config */

void
evpl_bind_destroy(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_notify notify;

    if (bind->callback) {
        notify.notify_type   = EVPL_NOTIFY_DISCONNECTED;
        notify.notify_status = 0;

        bind->callback(evpl, bind, &notify, bind->private_data);
    }

    bind->protocol->close(evpl, bind);

    evpl_bvec_ring_clear(evpl, &bind->bvec_recv);
    evpl_bvec_ring_clear(evpl, &bind->bvec_send);

    DL_DELETE(evpl->binds, bind);

    bind->flags = 0;

    if (bind->local) {
        evpl_address_release(evpl, bind->local);
    }

    if (bind->remote) {
        evpl_address_release(evpl, bind->remote);
    }

    DL_PREPEND(evpl->free_binds, bind);
} /* evpl_bind_destroy */

int
evpl_peek(
    struct evpl      *evpl,
    struct evpl_bind *conn,
    void             *buffer,
    int               length)
{
    int               left = length, chunk;
    struct evpl_bvec *cur;
    void             *ptr = buffer;

    cur = evpl_bvec_ring_tail(&conn->bvec_recv);

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        memcpy(ptr, cur->data, chunk);

        left -= chunk;

        cur = evpl_bvec_ring_next(&conn->bvec_recv, cur);

        if (cur == NULL) {
            return length - left;
        }
    }

    return length;

} /* evpl_peek */

int
evpl_read(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length)
{
    int               copied = 0, chunk;
    struct evpl_bvec *cur;

    while (copied < length) {

        cur = evpl_bvec_ring_tail(&bind->bvec_recv);

        if (!cur) {
            break;
        }

        chunk = cur->length;

        if (chunk > length - copied) {
            chunk = length - copied;
        }

        memcpy(buffer + copied, cur->data, chunk);

        copied += chunk;

        evpl_bvec_ring_consume(evpl, &bind->bvec_recv, chunk);
    }

    return copied;

} /* evpl_read */

int
evpl_readv(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    struct evpl_bvec *bvecs,
    int               maxbvecs,
    int               length)
{
    int               left = length, chunk, nbvecs = 0;
    struct evpl_bvec *cur, *out;

    while (left && nbvecs < maxbvecs) {

        cur = evpl_bvec_ring_tail(&bind->bvec_recv);

        if (!cur) {
            break;
        }

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        out = &bvecs[nbvecs++];

        out->data   = cur->data;
        out->length = chunk;
        out->buffer = cur->buffer;
        out->buffer->refcnt++;

        left -= chunk;

        evpl_bvec_ring_consume(evpl, &bind->bvec_recv, chunk);
    }

    return nbvecs;

} /* evpl_readv */


int
evpl_recv(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length)
{
    int               left = length, chunk;
    struct evpl_bvec *cur;
    void             *ptr   = buffer;
    uint64_t          avail = evpl_bvec_ring_bytes(&bind->bvec_recv);

    if (avail < length) {
        return -1;
    }

    cur = evpl_bvec_ring_tail(&bind->bvec_recv);

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        memcpy(ptr, cur->data, chunk);

        left -= chunk;

        cur = evpl_bvec_ring_next(&bind->bvec_recv, cur);

        if (cur == NULL) {
            return -1;
        }
    }

    evpl_bvec_ring_consume(evpl, &bind->bvec_recv, length);

    return length;

} /* evpl_recv */

int
evpl_recvv(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    struct evpl_bvec *bvecs,
    int               maxbvecs,
    int               length)
{
    int               left = length, chunk, nbvecs = 0;
    struct evpl_bvec *cur, *out;
    uint64_t          avail = evpl_bvec_ring_bytes(&bind->bvec_recv);

    if (avail < length) {
        return -1;
    }

    cur = evpl_bvec_ring_tail(&bind->bvec_recv);

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        if (nbvecs == maxbvecs) {
            return -1;
        }

        out = &bvecs[nbvecs++];

        out->data   = cur->data;
        out->length = chunk;
        out->buffer = cur->buffer;
        out->buffer->refcnt++;

        left -= chunk;

        cur = evpl_bvec_ring_next(&bind->bvec_recv, cur);

        if (cur == NULL) {
            return -1;
        }
    }


    evpl_bvec_ring_consume(evpl, &bind->bvec_recv, length);

    return nbvecs;
} /* evpl_recvv */

int
evpl_recv_peek_bvec(
    struct evpl      *evpl,
    struct evpl_bind *conn,
    struct evpl_bvec *bvecs,
    int               nbufvecs,
    int               length)
{
    int nbvecs = 0, left = length;

    do {

    } while (left);

    return nbvecs;

} /* evpl_recv_peek_bvec */

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
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_add(&evpl->core, event);
} /* evpl_add_event */

void
evpl_add_poll(
    struct evpl         *evpl,
    evpl_poll_callback_t callback,
    void                *private_data)
{
    struct evpl_poll *poll = &evpl->poll[evpl->num_poll];

    poll->callback     = callback;
    poll->private_data = private_data;

    ++evpl->num_poll;
} /* evpl_add_poll */

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

struct evpl_address *
evpl_address_alloc(struct evpl *evpl)
{
    struct evpl_address *address;

    if (evpl->free_address) {
        address = evpl->free_address;
        LL_DELETE(evpl->free_address, address);
    } else {
        address = evpl_zalloc(sizeof(*address));
    }

    address->addr   = (struct sockaddr *) &address->sa;
    address->refcnt = 1;
    address->next   = NULL;

    return address;
} /* evpl_address_alloc */

struct evpl_address *
evpl_address_init(
    struct evpl     *evpl,
    struct sockaddr *addr,
    socklen_t        addrlen)
{
    struct evpl_address *ea = evpl_address_alloc(evpl);

    ea->addrlen = addrlen;
    memcpy(ea->addr, addr, addrlen);

    return ea;

} /* evpl_address_init */

void
evpl_address_release(
    struct evpl         *evpl,
    struct evpl_address *address)
{
    int i;

    address->refcnt--;

    if (address->refcnt) {
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

    LL_PREPEND(evpl->free_address, address);
} /* evpl_address_release */

