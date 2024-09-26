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
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>

#include "utlist.h"

#if EVPL_MECH == epoll
#include "core/epoll.h"
#else  /* if EVPL_MECH == epoll */
#error  No EVPL_MECH
#endif /* if EVPL_MECH == epoll */

#include "core/evpl.h"
#include "core/protocol.h"
#include "core/internal.h"
#include "core/config.h"
#include "core/event.h"
#include "core/buffer.h"
#include "core/conn.h"
#include "core/endpoint.h"

#ifdef HAVE_RDMACM
#include "rdmacm/rdmacm.h"
#endif

#include "socket/tcp.h"

struct evpl_shared {
    struct evpl_config          *config;
    struct evpl_framework       *framework[EVPL_NUM_FRAMEWORK];
    void                        *framework_private[EVPL_NUM_FRAMEWORK];
    struct evpl_conn_protocol   *conn_protocol[EVPL_CONN_NUM_PROTO];
    void                        *conn_protocol_private[EVPL_CONN_NUM_PROTO];
};

struct evpl_shared *evpl_shared = NULL;

struct evpl {
    struct evpl_core      core; /* must be first */


    void                 *conn_protocol_private[EVPL_CONN_NUM_PROTO];
    void                 *framework_private[EVPL_NUM_FRAMEWORK];

    struct evpl_event   **active_events;
    int                   num_active_events;
    int                   max_active_events;

    int                   active_reserve;

    struct evpl_deferral **active_deferrals;
    int                    num_active_deferrals;
    int                    max_active_deferrals;

    struct evpl_buffer   *current_buffer;
    struct evpl_buffer   *free_buffers;
    struct evpl_conn     *free_conns;
    struct evpl_config   *config;
    struct evpl_listener *listeners;

};

static void
evpl_framework_init(
    struct evpl_shared *evpl_shared,
    unsigned int id,
    struct evpl_framework *framework)
{
    evpl_shared->framework[id] = framework;

    evpl_shared->framework_private[id] = framework->init();
}

static void
evpl_framework_cleanup(
    struct evpl_shared *evpl_shared,
    unsigned int id)
{
    struct evpl_framework *framework = evpl_shared->framework[id];

    framework->cleanup(evpl_shared->framework_private[id]);
}

static void
evpl_conn_protocol_init(
    struct evpl_shared *evpl_shared,
    unsigned int id,
    struct evpl_conn_protocol *protocol)
{
    evpl_shared->conn_protocol[id] = protocol;
}

void
evpl_init(struct evpl_config *config)
{
    evpl_shared = evpl_zalloc(sizeof(*evpl_shared));

    if (config) {
        ++config->refcnt;
    } else {
        config = evpl_config_init();
    }

    evpl_shared->config = config;

    evpl_conn_protocol_init(evpl_shared, EVPL_CONN_SOCKET_TCP, &evpl_socket_tcp);

#ifdef HAVE_RDMACM
    evpl_framework_init(evpl_shared, EVPL_FRAMEWORK_RDMACM, &evpl_rdmacm);
    evpl_conn_protocol_init(evpl_shared, EVPL_CONN_RDMACM_RC, &evpl_rdmacm_rc);
#endif 

}


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
}

struct evpl *
evpl_create()
{
    struct evpl *evpl;
    struct evpl_framework *framework;
    int i;

    evpl = evpl_zalloc(sizeof(*evpl));

    evpl->active_events = evpl_calloc(256, sizeof(struct evpl_event *));
    evpl->max_active_events = 256;

    evpl->active_deferrals = evpl_calloc(256, sizeof(struct evpl_deferral *));
    evpl->max_active_deferrals = 256;

    evpl->config = evpl_shared->config;
    evpl->config->refcnt++;

    evpl_core_init(&evpl->core, 64);

    for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {
        framework = evpl_shared->framework[i];

        if (!framework->create) continue;

        evpl->framework_private[i] = framework->create(evpl, evpl_shared->framework_private[i]);
    }

    return evpl;
} /* evpl_init */

void
evpl_wait(
    struct evpl *evpl,
    int          max_msecs)
{
    struct evpl_event *event;
    struct evpl_deferral *deferral;
    int                i;

    if (!evpl->num_active_events) {
        evpl_core_wait(&evpl->core, max_msecs);
    }

    evpl_core_debug("have %d active events", evpl->num_active_events);

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
            evpl->active_deferrals[0] = evpl->active_deferrals[evpl->num_active_deferrals];
        }

        deferral->armed = 0;

        deferral->callback(evpl, deferral->private_data);

    }

} /* evpl_wait */

struct evpl_listener *
evpl_listen(
    struct evpl           *evpl,
    enum evpl_conn_protocol_id protocol_id,
    struct evpl_endpoint  *endpoint,
    evpl_accept_callback_t accept_callback,
    void                  *private_data)
{
    struct evpl_listener *listener;

    listener = evpl_zalloc(sizeof(*listener) + EVPL_MAX_PRIVATE);

    listener->protocol        = evpl_shared->conn_protocol[protocol_id];
    listener->endpoint        = endpoint;
    ++endpoint->refcnt;

    listener->accept_callback = accept_callback;
    listener->private_data = private_data;

    evpl_endpoint_resolve(evpl, endpoint);

    DL_APPEND(evpl->listeners, listener);

    listener->protocol->listen(evpl, listener);

    return listener;
} /* evpl_listen */

void
evpl_listener_destroy(
    struct evpl          *evpl,
    struct evpl_listener *listener)
{
    listener->protocol->close_listen(evpl, listener);

    DL_DELETE(evpl->listeners, listener);

    evpl_endpoint_close(evpl, listener->endpoint);

    evpl_free(listener);
} /* evpl_listener_destroy */

struct evpl_endpoint *
evpl_endpoint_create(
    struct evpl           *evpl,
    const char            *address,
    int                    port)
{
    struct evpl_endpoint *ep;

    ep = evpl_zalloc(sizeof(*ep));

    ep->port = port;
    ep->refcnt = 1;
    strncpy(ep->address, address, sizeof(ep->address) - 1);

    return ep;
}


void
evpl_endpoint_close(
    struct evpl *evpl,
    struct evpl_endpoint *endpoint)
{
    --endpoint->refcnt;

    if (endpoint->refcnt == 0) {
        freeaddrinfo(endpoint->ai);
        evpl_free(endpoint);
    }
}

int
evpl_endpoint_resolve(
    struct evpl           *evpl,
    struct evpl_endpoint  *endpoint)
{
    char            port_str[8];
    struct addrinfo hints;
    int             rc;

    snprintf(port_str, sizeof(port_str), "%d", endpoint->port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = 0;//AI_PASSIVE;

    rc = getaddrinfo(endpoint->address, port_str, &hints, &endpoint->ai);

    if (unlikely(rc < 0)) {
        return rc;
    }

    return 0;
}


struct evpl_conn *
evpl_connect(
    struct evpl          *evpl,
    enum evpl_conn_protocol_id protocol_id,
    struct evpl_endpoint *endpoint,
    evpl_event_callback_t callback,
    void                 *private_data)
{
    struct evpl_conn *conn;

    conn = evpl_alloc_conn(evpl, endpoint);
    conn->protocol = evpl_shared->conn_protocol[protocol_id];
    conn->callback     = callback;
    conn->private_data = private_data;

    evpl_endpoint_resolve(evpl, endpoint);

    conn->protocol->connect(evpl, conn);

    return conn;
} /* evpl_connect */


void
evpl_destroy(struct evpl *evpl)
{
    struct evpl_listener *listener;
    struct evpl_framework *framework;
    struct evpl_conn     *conn;
    struct evpl_buffer   *buffer;
    int i;

    while (evpl->listeners) {
        listener = evpl->listeners;
        DL_DELETE(evpl->listeners, listener);
        evpl_listener_destroy(evpl, listener);
    }

    while (evpl->free_conns) {
        conn = evpl->free_conns;
        LL_DELETE(evpl->free_conns, conn);

        evpl_bvec_ring_free(&conn->send_ring);
        evpl_bvec_ring_free(&conn->recv_ring);
        evpl_free(conn);
    }

    while (evpl->current_buffer) {
        buffer = evpl->current_buffer;
        LL_DELETE(evpl->current_buffer, buffer);

        evpl_buffer_release(evpl, buffer);
    }

    while (evpl->free_buffers) {
        buffer = evpl->free_buffers;
        evpl_core_debug("XXX freeing buffer %p", buffer);
        LL_DELETE(evpl->free_buffers, buffer);

        evpl_core_fatal_if(buffer->refcnt,
                      "Buffer %p has refcnt %u at evpl_destroy",
                      buffer, buffer->refcnt);

        for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {
            framework = evpl_shared->framework[i];

            if (!framework || !framework->unregister_buffer) continue;

            framework->unregister_buffer(
                buffer->framework_private[i],
                evpl->framework_private[i]);
        }

        evpl_free(buffer->data);
        evpl_free(buffer);
    }

    for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {
        framework = evpl_shared->framework[i];

        if (!framework->destroy) continue;

        framework->destroy(evpl, evpl->framework_private[i]);
    }

    evpl_core_destroy(&evpl->core);

    evpl_config_release(evpl->config);
    evpl_free(evpl->active_events);
    evpl_free(evpl->active_deferrals);
    evpl_free(evpl);
} /* evpl_destroy */

static void
evpl_conn_close_deferral(
    struct evpl *evpl,
    void *private_data)
{
    struct evpl_conn *conn = private_data;

    evpl_core_debug("close deferral called");
   
    evpl_conn_destroy(evpl, conn); 
}

static void
evpl_conn_flush_deferral(
    struct evpl *evpl,
    void *private_data)
{
    struct evpl_conn *conn = private_data;

    evpl_core_debug("flush deferral called");

    if (conn->protocol->flush) {
        conn->protocol->flush(evpl, conn);
    }
}


struct evpl_conn *
evpl_alloc_conn(
    struct evpl *evpl,
    struct evpl_endpoint *endpoint)
{
    struct evpl_conn *conn;

    conn = evpl_zalloc(sizeof(struct evpl_conn) + EVPL_MAX_PRIVATE);

    evpl_bvec_ring_alloc(
        &conn->send_ring,
        evpl->config->bvec_ring_size,
        evpl->config->page_size);

    evpl_bvec_ring_alloc(
        &conn->recv_ring,
        evpl->config->bvec_ring_size,
        evpl->config->page_size);

    conn->endpoint = endpoint;
    endpoint->refcnt++;

    evpl_deferral_init(&conn->close_deferral,
        evpl_conn_close_deferral, conn);

    evpl_deferral_init(&conn->flush_deferral,
        evpl_conn_flush_deferral, conn);

    return conn;
} /* evpl_alloc_conn */

const struct evpl_endpoint *
evpl_conn_endpoint(struct evpl_conn *conn)
{
    return conn->endpoint;
} /* evpl_conn_endpoint */

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
        event->flags                    |= EVPL_ACTIVE;
        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_mark_error */



void
evpl_accept(
    struct evpl          *evpl,
    struct evpl_listener *listener,
    struct evpl_conn     *conn)
{

    evpl_core_debug("accepted new conn");

    listener->accept_callback(
        conn,
        &conn->callback,
        &conn->private_data,
        listener->private_data);

    conn->callback(evpl, conn, EVPL_EVENT_CONNECTED, 0,
                   conn->private_data);
} /* evpl_accept */

static struct evpl_buffer *
evpl_buffer_alloc(
struct evpl *evpl)
{
    struct evpl_framework *framework;
    struct evpl_buffer *buffer;
    int i;

    if (evpl->free_buffers) {
        buffer = evpl->free_buffers;
        LL_DELETE(evpl->free_buffers, buffer);
        return buffer;
    } else {
        buffer = evpl_malloc(sizeof(*buffer));
        buffer->size   = evpl->config->buffer_size;

        buffer->data = evpl_valloc(
            buffer->size,
            evpl->config->page_size);

        for (i = 0; i < EVPL_NUM_FRAMEWORK; ++i) {
            framework = evpl_shared->framework[i];

            if (!framework || !framework->register_buffer) continue;

            buffer->framework_private[i] = framework->register_buffer(
                    buffer->data, buffer->size,
                    evpl->framework_private[i]);

        }

    }

    buffer->refcnt = 0;
    buffer->used   = 0;
    buffer->next   = NULL;

    evpl_core_debug("XXX allocated buffer %p", buffer);
    return buffer;
}

int 
evpl_bvec_reserve(
    struct evpl      *evpl,
    unsigned int      length,
    unsigned int      alignment,
    unsigned int      max_bvecs,
    struct evpl_bvec *r_bvec)
{
    struct evpl_buffer *buffer = evpl->current_buffer;
    int        pad, left = length, chunk;
    int nbvecs = 0;
    struct evpl_bvec *bvec;

    evpl_core_debug("evpl_bvec_reserve: length %u alignment %u max_bvecs %u",
        length, alignment, max_bvecs);


    if (buffer == NULL) {
        buffer = evpl_buffer_alloc(evpl);
        LL_PREPEND(evpl->current_buffer, buffer);
        ++buffer->refcnt;
    }

    do {

        evpl_core_debug("buffer %p used %u size %u", buffer, buffer->used, buffer->size);
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
            buffer->next = evpl_buffer_alloc(evpl);
            buffer->next->refcnt++;
        } 

        buffer = buffer->next;

        left -= chunk - pad;
             
    } while (left);

    return nbvecs;
}

void
evpl_bvec_commit(
    struct evpl *evpl,
    struct evpl_bvec *bvecs,
    int         nbvecs)
{
    int i;
    unsigned int chunk;
    struct evpl_bvec *bvec;
    struct evpl_buffer *buffer;

    for (i = 0 ; i < nbvecs; ++i) {

        bvec = &bvecs[i];

        buffer = bvec->buffer;

        ++buffer->refcnt;

        chunk = (bvec->data + bvec->length) - (buffer->data + buffer->used);

        buffer->used += chunk;

        if (buffer->size - buffer->used < 64) {
            LL_DELETE(evpl->current_buffer, buffer);
            evpl_buffer_release(evpl, buffer);
        }

        evpl_core_debug("evpl %p bvec %p took ref on buffer %p refcnt now %d",
            evpl, bvec, bvec->buffer, bvec->buffer->refcnt);
 
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

    if (unlikely(nbvecs < 0)) return nbvecs;

    evpl_bvec_commit(evpl, r_bvec, nbvecs);

    return nbvecs;
} /* evpl_bvec_alloc */

void
evpl_buffer_release(
    struct evpl        *evpl,
    struct evpl_buffer *buffer)
{
    evpl_core_debug("buffer release %p refcnt %d", buffer, buffer->refcnt);

    evpl_core_abort_if(buffer->refcnt == 0,
                  "Released buffer %p with zero refcnt", buffer);

    --buffer->refcnt;


    if (buffer->refcnt == 0) {
        evpl_core_debug("XXX release buffer %p", buffer);
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
    struct evpl *evpl,
    struct evpl_bvec *bvec)
{
    evpl_bvec_incref(evpl, bvec);
} /* evpl_bvec_addref */

void
evpl_send(
    struct evpl       *evpl,
    struct evpl_conn  *conn,
    struct evpl_bvec  *bvecs,
    int                nbufvecs)
{
    int i, eom;

    if (nbufvecs == 0) {
        return;
    }

    for (i = 0; i < nbufvecs; ++i) {
        eom = (i + 1 == nbufvecs);
        evpl_bvec_ring_add(&conn->send_ring, &bvecs[i], eom);
    }

    evpl_defer(evpl, &conn->flush_deferral);

} /* evpl_send */

void
evpl_close(
    struct evpl      *evpl,
    struct evpl_conn *conn)
{
    evpl_core_debug("evpl_close called");
    evpl_defer(evpl, &conn->close_deferral);
} /* evpl_close */

void
evpl_finish(
    struct evpl      *evpl,
    struct evpl_conn *conn)
{

    conn->flags |= EVPL_CONN_FINISH;

    if (evpl_bvec_ring_is_empty(&conn->send_ring)) {
        evpl_defer(evpl, &conn->close_deferral);
    }

} /* evpl_finish */

struct evpl_config *
evpl_config(struct evpl *evpl)
{
    return evpl->config;
} /* evpl_config */

void
evpl_conn_destroy(
    struct evpl      *evpl,
    struct evpl_conn *conn)
{
    conn->callback(
        evpl, conn, EVPL_EVENT_DISCONNECTED, 0,
        conn->private_data);

    conn->protocol->close_conn(evpl, conn);

    evpl_bvec_ring_clear(evpl, &conn->recv_ring);
    evpl_bvec_ring_clear(evpl, &conn->send_ring);

    evpl_endpoint_close(evpl, conn->endpoint);

    LL_PREPEND(evpl->free_conns, conn);
} /* evpl_conn_destroy */

int
evpl_peek(
    struct evpl       *evpl,
    struct evpl_conn  *conn,
    void              *buffer,
    int                length)
{
    int left = length, chunk;
    struct evpl_bvec *cur;
    void *ptr = buffer;

    cur = evpl_bvec_ring_tail(&conn->recv_ring);

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        } 

        memcpy(ptr, cur->data, chunk);

        left -= chunk;

        cur = evpl_bvec_ring_next(&conn->recv_ring, cur);

        if (cur == NULL) {
            return length - left;
        }
    } 

    return length;

}

int
evpl_read(
    struct evpl       *evpl,
    struct evpl_conn  *conn,
    void              *buffer,
    int                length)
{
    int left = length, chunk;
    struct evpl_bvec *cur;
    void *ptr = buffer;

    cur = evpl_bvec_ring_tail(&conn->recv_ring);

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        memcpy(ptr, cur->data, chunk);

        left -= chunk;

        cur = evpl_bvec_ring_next(&conn->recv_ring, cur);

        if (cur == NULL) {
            return -1;
        }
    }

    evpl_bvec_ring_consume(evpl, &conn->recv_ring, length);

    return length;

}

int
evpl_readv(
    struct evpl       *evpl,
    struct evpl_conn  *conn,
    struct evpl_bvec  *bvecs,
    int                maxbvecs,
    int                length)
{
    int left = length, chunk, nbvecs = 0;
    struct evpl_bvec *cur, *out;

    cur = evpl_bvec_ring_tail(&conn->recv_ring);

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        if (nbvecs == maxbvecs) {
            return -1;
        }

        out = &bvecs[nbvecs++];

        out->data = cur->data;
        out->length = chunk;
        out->buffer = cur->buffer;
        out->buffer->refcnt++;

        left -= chunk;

        cur = evpl_bvec_ring_next(&conn->recv_ring, cur);

        if (cur == NULL) {
            return -1;
        }
    }


    evpl_bvec_ring_consume(evpl, &conn->recv_ring, length);

    return nbvecs;
}


int
evpl_recv_peek_bvec(
    struct evpl       *evpl,
    struct evpl_conn  *conn,
    struct evpl_bvec  *bvecs,
    int                nbufvecs,
    int                length)
{
    int nbvecs = 0, left = length;

    do {

    } while (left);

    return nbvecs;

}

const char *
evpl_endpoint_address(const struct evpl_endpoint *ep)
{
    return ep->address;
}
 

int
evpl_endpoint_port(const struct evpl_endpoint *ep)
{
    return ep->port;
}

void *
evpl_framework_private(struct evpl *evpl, int id)
{
    return evpl->framework_private[id];
}

void
evpl_add_event(
    struct evpl *evpl,
    struct evpl_event *event)
{
    evpl_core_add(&evpl->core, event);
}

void
evpl_defer(
    struct evpl *evpl,
    struct evpl_deferral *deferral)
{
    int index;

    if (!deferral->armed) {
        deferral->armed = 1;
        index = evpl->num_active_deferrals;

        evpl->active_deferrals[index] = deferral;

        ++evpl->num_active_deferrals;
    }

}

