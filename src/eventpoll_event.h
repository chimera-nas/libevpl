#ifndef __EVENTPOLL_EVENT_H__
#define __EVENTPOLL_EVENT_H__

#include "eventpoll.h"

struct eventpoll_listener;
struct eventpoll_conn;
struct eventpoll_event;

typedef void (*eventpoll_event_read_callback_t)(struct eventpoll *eventpoll, struct eventpoll_event *event);
typedef void (*eventpoll_event_write_callback_t)(struct eventpoll *eventpoll, struct eventpoll_event *event);
typedef void (*eventpoll_event_error_callback_t)(struct eventpoll *eventpoll, struct eventpoll_event *event);

#define EVENTPOLL_READABLE 0x01
#define EVENTPOLL_WRITABLE 0x02
#define EVENTPOLL_READ_INTEREST 0x04
#define EVENTPOLL_WRITE_INTEREST 0x08
#define EVENTPOLL_ACTIVE    0x10
#define EVENTPOLL_ERROR    0x20

#define EVENTPOLL_READ_READY (EVENTPOLL_READABLE|EVENTPOLL_READ_INTEREST)
#define EVENTPOLL_WRITE_READY (EVENTPOLL_WRITABLE|EVENTPOLL_WRITE_INTEREST)

struct eventpoll_event {
    int                                 fd;
    unsigned int                        flags;
    int                                 pad[2];

    eventpoll_event_read_callback_t     backend_read_callback;
    eventpoll_event_write_callback_t    backend_write_callback;
    eventpoll_event_error_callback_t    backend_error_callback;

    eventpoll_recv_callback_t           user_recv_callback;
    eventpoll_error_callback_t          user_error_callback;
    void                               *user_private_data;
};

void eventpoll_event_read_interest(struct eventpoll *eventpoll, struct eventpoll_event *event);
void eventpoll_event_read_disinterest(struct eventpoll_event *event);
void eventpoll_event_write_interest(struct eventpoll *eventpoll, struct eventpoll_event *event);
void eventpoll_event_write_disinterest(struct eventpoll_event *event);


void eventpoll_event_mark_readable(struct eventpoll *eventpoll, struct eventpoll_event *event);
void eventpoll_event_mark_unreadable(struct eventpoll_event *event);
void eventpoll_event_mark_writable(struct eventpoll *eventpoll, struct eventpoll_event *event);
void eventpoll_event_mark_unwritable(struct eventpoll_event *event);
void eventpoll_event_mark_error(struct eventpoll *eventpoll, struct eventpoll_event *event);


void eventpoll_accept(struct eventpoll *eventpoll,
                      struct eventpoll_listener *listener,
                      struct eventpoll_conn *conn);
/*
 * The eventpoll_core is always the first member of eventpoll,
 * so we can cast between them
 */

#define eventpoll_from_core(core) ((struct eventpoll *)core)
/*
 * The backend structure is always immediately following the eventpoll_event
 * in an eventpoll_conn, and eventpoll_event is always first, so we can do
 * some pointer casting to get backends from the opaque structure
 */

#define eventpoll_event_backend(conn) \
    (void*)(((struct eventpoll_event *)conn)+1)

#define eventpoll_conn_backend(conn) eventpoll_event_backend(conn)

#define eventpoll_event_conn(event) ((struct eventpoll_conn *)event)
#define eventpoll_event_listener(event) ((struct eventpoll_listener *)event)

#endif
