#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>

#include "eventpoll_core_epoll.h"
#include "eventpoll_internal.h"
#include "eventpoll_event.h"

int
eventpoll_core_init(
    struct eventpoll_core *evc,
    int max_events)
{
    evc->fd = epoll_create(255); /* size is ignored in linux >= 2.6.8 */

    if (evc->fd < 0) {
        return errno;
    }

    evc->max_events = max_events;

    evc->events = calloc(max_events, sizeof(struct epoll_event));

    return 0;
}

void 
eventpoll_core_destroy(
    struct eventpoll_core *evc)
{
    free(evc->events);
    close(evc->fd);
}

void
eventpoll_core_add(
    struct eventpoll_core *evc,
    struct eventpoll_event *event)
{
    struct epoll_event ev;
    int rc;

    ev.events = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLET;
    ev.data.ptr = event;

    rc = epoll_ctl(evc->fd, EPOLL_CTL_ADD, event->fd, &ev);

    eventpoll_fatal_if(rc, "Failed to add file descriptor to epoll");
}


void
eventpoll_core_wait(struct eventpoll_core *evc, int max_msecs)
{
    struct eventpoll *eventpoll = eventpoll_from_core(evc);
    struct eventpoll_event *event;
    struct epoll_event *ev;
    int i, n;

    n = epoll_wait(evc->fd, evc->events, evc->max_events, max_msecs);

    for (i = 0; i < n; ++i) {
        ev = &evc->events[i];

        event = ev->data.ptr; 

        if (ev->events & EPOLLIN) {
            eventpoll_event_mark_readable(eventpoll, event);
        }

        if (ev->events & EPOLLOUT) {
            eventpoll_event_mark_writable(eventpoll, event);
        }

        if (ev->events & EPOLLERR) {
            eventpoll_event_mark_close(eventpoll, event);
        }

    }
}
