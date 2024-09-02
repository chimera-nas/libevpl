#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

#include "utlist.h"

#if EVENTPOLL_MECH == epoll
#include "eventpoll_core_epoll.h"
#else
#error  No EVENTPOLL_MECH
#endif

#include "eventpoll.h"
#include "eventpoll_internal.h"
#include "eventpoll_config.h"
#include "eventpoll_tcp.h"
#include "eventpoll_event.h"
#include "eventpoll_buffer.h"
#include "eventpoll_conn.h"

struct eventpoll_listener {
    struct eventpoll_event  event; /* must be first member */

    union { /* must be second member */
        struct eventpoll_socket s;
    };

    eventpoll_accept_callback_t accept_callback;
    void                       *private_data;
    int protocol;

    struct eventpoll_listener *prev;
    struct eventpoll_listener *next;
};


struct eventpoll {
    struct eventpoll_core      core; /* must be first */

    struct eventpoll_event   **active;
    int                        num_active;

    struct eventpoll_buffer   *current_buffer;
    struct eventpoll_buffer   *free_buffers;
    struct eventpoll_conn     *free_conns;
    struct eventpoll_config   *config;
    struct eventpoll_listener *listeners;
};

struct eventpoll *
eventpoll_init(struct eventpoll_config *config)
{
    struct eventpoll *eventpoll;

    if (config) {
        ++config->refcnt;
    } else {
        config = eventpoll_config_init();
    }

    eventpoll = eventpoll_zalloc(sizeof(*eventpoll));

    eventpoll->active = eventpoll_calloc(256, sizeof(struct eventpoll_event *));

    eventpoll->config = config;

    eventpoll_core_init(&eventpoll->core, 64);

    return eventpoll;
}

void
eventpoll_wait(struct eventpoll *eventpoll, int max_msecs)
{
    struct eventpoll_event *event;
    int i;

    eventpoll_core_wait(&eventpoll->core, max_msecs);

    eventpoll_debug("have %d active events", eventpoll->num_active);

    while (eventpoll->num_active) {
        for (i = 0; i < eventpoll->num_active; ++i) {
            event = eventpoll->active[i];

            if ((event->flags & EVENTPOLL_READ_READY) == EVENTPOLL_READ_READY) {
                event->read_callback(eventpoll, event);
            } 

            if ((event->flags & EVENTPOLL_WRITE_READY) == EVENTPOLL_WRITE_READY) {
                event->write_callback(eventpoll, event);
            }

            if ((event->flags & EVENTPOLL_FINISH) &&
                (event->flags & EVENTPOLL_WRITE_READY) != EVENTPOLL_WRITE_READY) {

                event->flags |= EVENTPOLL_CLOSE;
            }

            if (event->flags & EVENTPOLL_CLOSE) {

                event->flags &= ~ EVENTPOLL_ACTIVE;

                if (i + 1 < eventpoll->num_active) {
                    eventpoll->active[i] = eventpoll->active[eventpoll->num_active-1];
                }
                --eventpoll->num_active;

                eventpoll_conn_destroy(eventpoll, eventpoll_event_conn(event));
    
            } else  if ((event->flags & EVENTPOLL_READ_READY) != EVENTPOLL_READ_READY &&
                        (event->flags & EVENTPOLL_WRITE_READY) != EVENTPOLL_WRITE_READY) {

                event->flags &= ~ EVENTPOLL_ACTIVE;

                if (i + 1 < eventpoll->num_active) {
                    eventpoll->active[i] = eventpoll->active[eventpoll->num_active-1];
                }
                --eventpoll->num_active;
            }
        }
    }
}

int
eventpoll_listen(
    struct eventpoll *eventpoll,
    int protocol,
    const char *address,
    int port,
    eventpoll_accept_callback_t accept_callback,
    void *private_data)
{
    struct eventpoll_listener *listener;
    int rc;

    listener = eventpoll_zalloc(sizeof(*listener));

    listener->protocol = protocol;
    listener->accept_callback = accept_callback;

    switch (protocol) {
    case EVENTPOLL_PROTO_TCP:
        rc = eventpoll_listen_tcp(eventpoll, &listener->s, &listener->event, address, port);
        break;
    default:
        rc = EINVAL;
    }

    if (rc) {
        eventpoll_error("Failed to listen on %s:%d", address, port);
        eventpoll_free(listener);
        return 1;
    }

    listener->private_data= private_data;

    eventpoll_core_add(&eventpoll->core, &listener->event);

    eventpoll_event_read_interest(eventpoll, &listener->event);    

    DL_APPEND(eventpoll->listeners, listener);

    return 0;
}

void
eventpoll_listener_destroy(
    struct eventpoll_listener *listener)
{
    switch (listener->protocol) {
    case EVENTPOLL_PROTO_TCP:
        eventpoll_close_tcp(&listener->s);
        break;
    default:
        break;
    }

    eventpoll_free(listener);
}

struct eventpoll_conn *
eventpoll_connect(
    struct eventpoll *eventpoll,
    int protocol,
    const char *address,
    int port,
    eventpoll_event_callback_t callback,
    void *private_data)
{
    struct eventpoll_conn *conn;
    int rc;

    conn = eventpoll_alloc_conn(eventpoll, protocol, address, port);

    switch (protocol) {
    case EVENTPOLL_PROTO_TCP:
        rc = eventpoll_connect_tcp(eventpoll, &conn->s, &conn->event, address, port);
        break;
    default:
        rc = EINVAL;
    }

    if (rc) {
        eventpoll_event_mark_close(eventpoll, &conn->event);
    } else {
        eventpoll_core_add(&eventpoll->core, &conn->event);
        eventpoll_event_read_interest(eventpoll, &conn->event);
    }
    
    conn->callback = callback;
    conn->private_data = private_data;

    return conn;
}


void
eventpoll_destroy(
    struct eventpoll *eventpoll)
{
    struct eventpoll_listener *listener;

    while (eventpoll->listeners) {
        listener = eventpoll->listeners;
        DL_DELETE(eventpoll->listeners, listener);
        eventpoll_listener_destroy(listener);
    }

    eventpoll_core_destroy(&eventpoll->core);
    eventpoll_config_release(eventpoll->config);
    eventpoll_free(eventpoll->active);
    eventpoll_free(eventpoll);
}

struct eventpoll_conn *
eventpoll_alloc_conn(
    struct eventpoll *eventpoll,
    int protocol,
    const char *address,
    int port)
{
    struct eventpoll_conn *conn;

    conn = eventpoll_zalloc(sizeof(struct eventpoll_conn));

    eventpoll_bvec_ring_alloc(
        &conn->send_ring,
        eventpoll->config->bvec_ring_size,
        eventpoll->config->page_size);

    eventpoll_bvec_ring_alloc(
        &conn->recv_ring,
        eventpoll->config->bvec_ring_size,
        eventpoll->config->page_size);

    conn->protocol = protocol;
    conn->port = port;

    snprintf(conn->address, sizeof(conn->address), "%s", address);

    return conn;
}

const char *
eventpoll_conn_address(struct eventpoll_conn *conn)
{
    return conn->address;
}

int
eventpoll_conn_port(struct eventpoll_conn *conn)
{
    return conn->port;
}

void
eventpoll_event_read_interest(
    struct eventpoll *eventpoll,
    struct eventpoll_event *event)
{

    event->flags |= EVENTPOLL_READ_INTEREST;

    if ((event->flags & EVENTPOLL_READ_READY) == EVENTPOLL_READ_READY &&
        !(event->flags & EVENTPOLL_ACTIVE)) {

        event->flags |= EVENTPOLL_ACTIVE;

        eventpoll->active[eventpoll->num_active++] = event;
    }

}

void
eventpoll_event_read_disinterest(
    struct eventpoll_event *event)
{
    event->flags &= ~EVENTPOLL_READ_INTEREST;
}

void
eventpoll_event_write_interest(
    struct eventpoll *eventpoll,
    struct eventpoll_event *event)
{

    event->flags |= EVENTPOLL_WRITE_INTEREST;

    if ((event->flags & EVENTPOLL_WRITE_READY) == EVENTPOLL_WRITE_READY &&
        !(event->flags & EVENTPOLL_ACTIVE)) {

        event->flags |= EVENTPOLL_ACTIVE;

        eventpoll->active[eventpoll->num_active++] = event;
    }

}

void
eventpoll_event_write_disinterest(
    struct eventpoll_event *event)
{

    event->flags &= ~EVENTPOLL_WRITE_INTEREST;

}


void
eventpoll_event_mark_readable(
    struct eventpoll *eventpoll,
    struct eventpoll_event *event)
{
    event->flags |= EVENTPOLL_READABLE;

    if ((event->flags & EVENTPOLL_READ_READY) == EVENTPOLL_READ_READY &&
        !(event->flags & EVENTPOLL_ACTIVE)) {

        event->flags |= EVENTPOLL_ACTIVE;

        eventpoll->active[eventpoll->num_active++] = event; 
    }
}

void
eventpoll_event_mark_unreadable(
    struct eventpoll_event *event)
{
    event->flags &= ~EVENTPOLL_READABLE;
}

void
eventpoll_event_mark_writable(
    struct eventpoll *eventpoll,
    struct eventpoll_event *event)
{

    event->flags |= EVENTPOLL_WRITABLE;

    if ((event->flags & EVENTPOLL_WRITE_READY) == EVENTPOLL_WRITE_READY &&
        !(event->flags & EVENTPOLL_ACTIVE)) {

        event->flags |= EVENTPOLL_ACTIVE;

        eventpoll->active[eventpoll->num_active++] = event;
    }

}

void
eventpoll_event_mark_unwritable(
    struct eventpoll_event *event)
{
    event->flags &= ~EVENTPOLL_WRITABLE;
}

void
eventpoll_event_mark_finish(
    struct eventpoll *eventpoll,
    struct eventpoll_event *event)
{
    event->flags |= EVENTPOLL_FINISH;

    if (!(event->flags & EVENTPOLL_ACTIVE)) {
        event->flags |= EVENTPOLL_ACTIVE;
        eventpoll->active[eventpoll->num_active++] = event;
    }

}

void
eventpoll_event_mark_close(
    struct eventpoll *eventpoll,
    struct eventpoll_event *event)
{
    event->flags |= EVENTPOLL_CLOSE;

    if (!(event->flags & EVENTPOLL_ACTIVE)) {
        event->flags |= EVENTPOLL_ACTIVE;
        eventpoll->active[eventpoll->num_active++] = event;
    }

}



void eventpoll_accept(
    struct eventpoll *eventpoll,
    struct eventpoll_listener *listener,
    struct eventpoll_conn *conn)
{
    
    eventpoll_debug("accepted new conn");

    eventpoll_core_add(&eventpoll->core, &conn->event);
    eventpoll_event_read_interest(eventpoll, &conn->event);

    listener->accept_callback(
        conn,
        &conn->callback,
        &conn->private_data,
        listener->private_data);

    conn->callback(eventpoll, conn, EVENTPOLL_EVENT_CONNECTED, 0, conn->private_data);
}

void
eventpoll_bvec_alloc(
    struct eventpoll *eventpoll,
    unsigned int length,
    unsigned int alignment,
    struct eventpoll_bvec *r_bvec)
{
    struct eventpoll_buffer *buffer = eventpoll->current_buffer;
    unsigned int pad;

    eventpoll_fatal_if(length > eventpoll->config->buffer_size,
        "Requested allocation exceeds config buffer_size (%u > %u)",
        length, eventpoll->config->buffer_size);

    if (buffer) {
        pad = eventpoll_buffer_pad(buffer, alignment);

        if (eventpoll_buffer_left(buffer) < pad + length) {
            buffer = NULL;
        }
    }

    if (buffer == NULL) {
        if (eventpoll->free_buffers) {
            buffer = eventpoll->free_buffers;
            LL_DELETE(eventpoll->free_buffers, buffer);
            eventpoll->current_buffer = buffer;
        } else {
            buffer = eventpoll_malloc(sizeof(*buffer));

            buffer->refcnt = 0;
            buffer->used = 0;
            buffer->size = eventpoll->config->buffer_size;

            buffer->data = eventpoll_valloc(
                buffer->size,
                eventpoll->config->page_size);

        }
    }
    
    ++buffer->refcnt;

    buffer->used += pad;

    r_bvec->buffer = buffer;
    r_bvec->data   = buffer->data + buffer->used;
    r_bvec->length = length;
    r_bvec->flags  = 0;
    
    buffer->used += length;

}

void eventpoll_buffer_release(
    struct eventpoll *eventpoll,
    struct eventpoll_buffer *buffer)
{
    buffer->used = 0;
    LL_PREPEND(eventpoll->free_buffers, buffer);
}

void
eventpoll_bvec_release(
    struct eventpoll *eventpoll,
    struct eventpoll_bvec *bvec)
{
    eventpoll_bvec_decref(eventpoll, bvec);
}

void
eventpoll_bvec_addref(
    struct eventpoll_bvec *bvec)
{
    eventpoll_bvec_incref(bvec);
}

void
eventpoll_send(
    struct eventpoll       *eventpoll,
    struct eventpoll_conn  *conn,
    struct eventpoll_bvec   **bvecs,
    int                     nbufvecs)
{
    int i;

    if (nbufvecs == 0) return;

    for (i = 0; i < nbufvecs; ++i) {
        eventpoll_bvec_ring_add(&conn->send_ring, bvecs[i]);
    }

    eventpoll_event_write_interest(eventpoll, &conn->event);

}

void
eventpoll_close(
    struct eventpoll *eventpoll,
    struct eventpoll_conn *conn)
{
    eventpoll_event_mark_close(eventpoll, &conn->event);
}

void
eventpoll_finish(
    struct eventpoll *eventpoll,
    struct eventpoll_conn *conn)
{
    eventpoll_event_mark_finish(eventpoll, &conn->event);
}

struct eventpoll_config *
eventpoll_config(struct eventpoll *eventpoll)
{
    return eventpoll->config;
}

void
eventpoll_conn_destroy(
    struct eventpoll *eventpoll,
    struct eventpoll_conn *conn)
{

    conn->callback(eventpoll, conn, EVENTPOLL_EVENT_DISCONNECTED, 0, conn->private_data);

    switch (conn->protocol) {
    case EVENTPOLL_PROTO_TCP:
        eventpoll_close_tcp(&conn->s);
        break;
    default:    
        abort();
    }

    LL_PREPEND(eventpoll->free_conns, conn);
}
