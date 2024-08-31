#ifndef __EVENTPOLL_EVENT_H__
#define __EVENTPOLL_EVENT_H__

#include "eventpoll.h"

struct eventpoll_event;

typedef void (*eventpoll_event_read_callback_t)(struct eventpoll_event *evnet);
typedef void (*eventpoll_event_write_callback_t)(struct eventpoll_event *event);
typedef void (*eventpoll_event_error_callback_t)(struct eventpoll_event *event);

struct eventpoll_event {
    int                                 fd;
    int                                 pad;

    eventpoll_event_read_callback_t     backend_read_callback;
    eventpoll_event_write_callback_t    backend_write_callback;
    eventpoll_event_error_callback_t    backend_error_callback;
    void                               *backend_private_data;

    eventpoll_connect_callback_t        user_connect_callback;
    eventpoll_recv_callback_t           user_recv_callback;
    eventpoll_error_callback_t          user_error_callback;
    void                               *user_private_data;
};

/*
 * The backend structure is always immediately following the eventpoll_event
 * in an eventpoll_conn, and eventpoll_event is always first, so we can do
 * some pointer casting to get backends from the opaque structure
 */

#define eventpoll_conn_backend(conn) \
    (void*)(((struct eventpoll_event *)conn)+1)

#endif
