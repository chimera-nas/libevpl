// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>

#include "core/epoll.h"
#include "core/event_fn.h"
#include "core/evpl.h"

int
evpl_core_init(
    struct evpl_core *evc,
    int               max_events)
{
    evc->fd = epoll_create(255);      /* size is ignored in linux >= 2.6.8 */

    if (evc->fd < 0) {
        return errno;
    }

    evc->max_events = max_events;

    evc->events = calloc(max_events, sizeof(struct epoll_event));

    return 0;
} /* evpl_core_init */

void
evpl_core_destroy(struct evpl_core *evc)
{
    free(evc->events);
    close(evc->fd);
} /* evpl_core_destroy */

void
evpl_core_add(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    struct epoll_event ev;
    int                rc;

    if (event->fd <= 0) {
        abort();
    }

    ev.events   = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLET | EPOLLRDHUP;
    ev.data.ptr = event;

    rc = epoll_ctl(evc->fd, EPOLL_CTL_ADD, event->fd, &ev);

    evpl_core_abort_if(rc, "Failed to add file descriptor to epoll");
} /* evpl_core_add */

void
evpl_core_remove(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    int rc;

    if (event->fd <= 0) {
        abort();
    }

    rc = epoll_ctl(evc->fd, EPOLL_CTL_DEL, event->fd, NULL);

    evpl_core_abort_if(rc, "Failed to remove file descriptor from epoll");
} /* evpl_core_add */



int
evpl_core_wait(
    struct evpl_core *evc,
    int               max_msecs)
{
    struct evpl        *evpl = evpl_from_core(evc);
    struct evpl_event  *event;
    struct epoll_event *ev;
    int                 i, n;

    n = epoll_wait(evc->fd, evc->events, evc->max_events, max_msecs);

    for (i = 0; i < n; ++i) {
        ev = &evc->events[i];

        event = ev->data.ptr;

        if (ev->events & (EPOLLIN | EPOLLERR | EPOLLRDHUP)) {
            evpl_event_mark_readable(evpl, event);
        }

        if (ev->events & EPOLLOUT) {
            evpl_event_mark_writable(evpl, event);
        }

        if (ev->events & (EPOLLERR | EPOLLHUP | EPOLLRDHUP)) {
            evpl_event_mark_error(evpl, event);
        }

    }

    return n;
} /* evpl_core_wait */
