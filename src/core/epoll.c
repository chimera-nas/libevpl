// SPDX-FileCopyrightText: 2024 - 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdint.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <unistd.h>
#include <errno.h>

#include "core/epoll.h"
#include "core/core.h"
#include "core/event_fn.h"
#include "core/evpl.h"

static int
evpl_core_epoll_init(
    struct evpl_core *evc,
    int               max_events)
{
    struct evpl_core_epoll *e = &evc->u.epoll;

    e->fd = epoll_create(255);      /* size is ignored in linux >= 2.6.8 */

    if (e->fd < 0) {
        return errno;
    }

    e->max_events = max_events;

    e->events = calloc(max_events, sizeof(struct epoll_event));

    return 0;
} /* evpl_core_epoll_init */

static void
evpl_core_epoll_destroy(struct evpl_core *evc)
{
    struct evpl_core_epoll *e = &evc->u.epoll;

    free(e->events);
    close(e->fd);
} /* evpl_core_epoll_destroy */

static void
evpl_core_epoll_add(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    struct evpl_core_epoll *e = &evc->u.epoll;
    struct epoll_event      ev;
    int                     rc;

    if (event->fd <= 0) {
        abort();
    }

    ev.events   = EPOLLIN | EPOLLOUT | EPOLLERR | EPOLLET | EPOLLRDHUP;
    ev.data.ptr = event;

    rc = epoll_ctl(e->fd, EPOLL_CTL_ADD, event->fd, &ev);

    evpl_core_abort_if(rc, "Failed to add file descriptor to epoll");
} /* evpl_core_epoll_add */

static void
evpl_core_epoll_remove(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    struct evpl_core_epoll *e = &evc->u.epoll;
    int                     rc;

    if (event->fd <= 0) {
        abort();
    }

    rc = epoll_ctl(e->fd, EPOLL_CTL_DEL, event->fd, NULL);

    evpl_core_abort_if(rc, "Failed to remove file descriptor from epoll");
} /* evpl_core_epoll_remove */

static int
evpl_core_epoll_wait(
    struct evpl_core *evc,
    int               max_msecs)
{
    struct evpl_core_epoll *e    = &evc->u.epoll;
    struct evpl            *evpl = evpl_from_core(evc);
    struct evpl_event      *event;
    struct epoll_event     *ev;
    int                     i, n;

    n = epoll_wait(e->fd, e->events, e->max_events, max_msecs);

    for (i = 0; i < n; ++i) {
        ev = &e->events[i];

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
} /* evpl_core_epoll_wait */

const struct evpl_core_ops evpl_core_epoll_ops = {
    .name    = "epoll",
    .init    = evpl_core_epoll_init,
    .destroy = evpl_core_epoll_destroy,
    .add     = evpl_core_epoll_add,
    .remove  = evpl_core_epoll_remove,
    .wait    = evpl_core_epoll_wait,
};
