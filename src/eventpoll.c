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

struct eventpoll_conn {
    struct eventpoll_event  event; /* must be first member */

    union { /* must be second member */
        struct eventpoll_socket s;
    };
    
    char address[256];
    int port;
    int protocol;
};

struct eventpoll_listener {
    struct eventpoll_event  event; /* must be first member */

    union { /* must be second member */
        struct eventpoll_socket s;
    };

    int protocol;

    struct eventpoll_listener *prev;
    struct eventpoll_listener *next;
};


struct eventpoll {
    struct eventpoll_core      core; /* must be first */

    struct eventpoll_event   **active;
    int                        num_active;
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
                event->backend_read_callback(event);
            } 

            if ((event->flags & EVENTPOLL_WRITE_READY) == EVENTPOLL_WRITE_READY) {
                event->backend_write_callback(event);
            }

            if ((event->flags & EVENTPOLL_READ_READY) != EVENTPOLL_READ_READY &&
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
    eventpoll_connect_callback_t connect_callback,
    eventpoll_recv_callback_t   recv_callback,
    eventpoll_error_callback_t error_callback,
    void *private_data)
{
    struct eventpoll_listener *listener;
    int rc;

    listener = eventpoll_zalloc(sizeof(*listener));

    listener->protocol = protocol;

    switch (protocol) {
    case EVENTPOLL_PROTO_TCP:
        rc = eventpoll_listen_tcp(eventpoll->config, &listener->s, &listener->event, address, port);
        break;
    default:
        rc = EINVAL;
    }

    if (rc) {
        eventpoll_error("Failed to listen on %s:%d", address, port);
        eventpoll_free(listener);
        return 1;
    }

    listener->event.user_connect_callback = connect_callback;
    listener->event.user_recv_callback = recv_callback;
    listener->event.user_error_callback = error_callback;
    listener->event.user_private_data = private_data;

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

void
eventpoll_connect(
    struct eventpoll *eventpoll,
    int protocol,
    const char *address,
    int port,
    eventpoll_connect_callback_t connect_callback,
    eventpoll_recv_callback_t   recv_callback,
    eventpoll_error_callback_t error_callback,
    void *private_data)
{
    struct eventpoll_conn *conn;
    int rc;

    conn = eventpoll_alloc_conn(protocol, address, port);

    switch (protocol) {
    case EVENTPOLL_PROTO_TCP:
        rc = eventpoll_connect_tcp(eventpoll->config, &conn->s, &conn->event, address, port);
        break;
    default:
        rc = EINVAL;
    }

    if (rc) {
        eventpoll_free(conn);
        error_callback(ENOTCONN, private_data);
        return;
    }
    
    conn->event.user_connect_callback = connect_callback;
    conn->event.user_recv_callback = recv_callback;
    conn->event.user_error_callback = error_callback;
    conn->event.user_private_data = private_data;

    eventpoll_core_add(&eventpoll->core, &conn->event);

    eventpoll_event_read_interest(eventpoll, &conn->event);
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
eventpoll_alloc_conn(int protocol, const char *address, int port)
{
    struct eventpoll_conn *conn;

    conn = eventpoll_zalloc(sizeof(struct eventpoll_conn));

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
    struct eventpoll *eventpoll,
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
    struct eventpoll *eventpoll,
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
eventpoll_event_mark_error(
    struct eventpoll *eventpoll,
    struct eventpoll_event *event)
{
    event->flags |= EVENTPOLL_ERROR;
}
