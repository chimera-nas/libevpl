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

    eventpoll_debug("adding fd %d to epoll fd %d", event->fd, evc->fd);

    rc = epoll_ctl(evc->fd, EPOLL_CTL_ADD, event->fd, &ev);

    eventpoll_fatal_if(rc, "Failed to add file descriptor to epoll");
}


int
eventpoll_core_wait(struct eventpoll_core *evc, int max_msecs)
{
    struct eventpoll_event *event;
    struct epoll_event *ev;
    int i, n;

    eventpoll_debug("entering epoll_wait on fd %d", evc->fd);

    n = epoll_wait(evc->fd, evc->events, evc->max_events, max_msecs);

    eventpoll_debug("epoll got %d events", n);

    for (i = 0; i < n; ++i) {
        ev = &evc->events[i];

        event = ev->data.ptr; 

        if (ev->events & EPOLLIN) {
            event->backend_read_callback(event);
        }

        if (ev->events & EPOLLOUT) {
            event->backend_write_callback(event);
        }

        if (ev->events & EPOLLERR) {
            event->backend_error_callback(event);
        }

    }

    return n;
}
