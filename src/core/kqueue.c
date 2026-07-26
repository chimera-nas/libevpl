// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdint.h>
#include <stdlib.h>
#include <sys/event.h>
#include <sys/time.h>
#include <unistd.h>
#include <errno.h>

#include "core/kqueue.h"
#include "core/core.h"
#include "core/event_fn.h"
#include "core/evpl.h"

static int
evpl_core_kqueue_init(
    struct evpl_core *evc,
    int               max_events)
{
    struct evpl_core_kqueue *k = &evc->u.kqueue;

    k->fd = kqueue();

    if (k->fd < 0) {
        return errno;
    }

    k->max_events = max_events;

    k->events = calloc(max_events, sizeof(struct kevent));

    return 0;
} /* evpl_core_kqueue_init */

static void
evpl_core_kqueue_destroy(struct evpl_core *evc)
{
    struct evpl_core_kqueue *k = &evc->u.kqueue;

    free(k->events);
    close(k->fd);
} /* evpl_core_kqueue_destroy */

static void
evpl_core_kqueue_add(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    struct evpl_core_kqueue *k = &evc->u.kqueue;
    struct kevent            ev[2];
    int                      rc;

    if (event->fd <= 0) {
        abort();
    }

    /*
     * Register both read and write filters up front, edge-triggered
     * (EV_CLEAR), mirroring how the epoll backend registers IN|OUT once with
     * EPOLLET and lets the software EVPL_*_INTEREST flags decide dispatch.
     * EV_CLEAR is essential: a connected socket is almost always writable, so
     * a level-triggered write filter would report ready on every kevent() call
     * and spin the event loop at 100% CPU.  Readiness is latched in
     * event->flags, and the read/write paths re-arm by clearing that flag only
     * once the fd is genuinely drained/full, so a single edge is never lost.
     * udata carries the evpl_event back to us in the wait below.
     */
    EV_SET(&ev[0], event->fd, EVFILT_READ, EV_ADD | EV_CLEAR, 0, 0, event);
    EV_SET(&ev[1], event->fd, EVFILT_WRITE, EV_ADD | EV_CLEAR, 0, 0, event);

    rc = kevent(k->fd, ev, 2, NULL, 0, NULL);

    evpl_core_abort_if(rc < 0, "Failed to add file descriptor to kqueue");
} /* evpl_core_kqueue_add */

static void
evpl_core_kqueue_remove(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    struct evpl_core_kqueue *k = &evc->u.kqueue;
    struct kevent            ev[2];

    if (event->fd <= 0) {
        abort();
    }

    /*
     * EV_RECEIPT forces kevent() to post a result for each changelist entry
     * (with EV_ERROR set) and to consume no events, so a filter that is
     * already gone -- e.g. the kernel auto-removed it on EOF -- reports ENOENT
     * in the eventlist rather than failing the whole call.
     */
    EV_SET(&ev[0], event->fd, EVFILT_READ, EV_DELETE | EV_RECEIPT, 0, 0, NULL);
    EV_SET(&ev[1], event->fd, EVFILT_WRITE, EV_DELETE | EV_RECEIPT, 0, 0, NULL);

    kevent(k->fd, ev, 2, ev, 2, NULL);
} /* evpl_core_kqueue_remove */

static int
evpl_core_kqueue_wait(
    struct evpl_core *evc,
    int               max_msecs)
{
    struct evpl_core_kqueue *k    = &evc->u.kqueue;
    struct evpl             *evpl = evpl_from_core(evc);
    struct evpl_event       *event;
    struct kevent           *ev;
    struct timespec          ts, *tsp;
    int                      i, n;

    if (max_msecs < 0) {
        tsp = NULL;
    } else {
        ts.tv_sec  = max_msecs / 1000;
        ts.tv_nsec = (max_msecs % 1000) * 1000000L;
        tsp        = &ts;
    }

    n = kevent(k->fd, NULL, 0, k->events, k->max_events, tsp);

    for (i = 0; i < n; ++i) {
        ev = &k->events[i];

        event = ev->udata;

        if (!event) {
            continue;
        }

        if (ev->filter == EVFILT_READ) {
            evpl_event_mark_readable(evpl, event);
        }

        if (ev->filter == EVFILT_WRITE) {
            evpl_event_mark_writable(evpl, event);
        }

        /*
         * kqueue reports a peer disconnect as EV_EOF on the read (and write)
         * filter, and a filter-level failure as EV_ERROR.  The epoll backend
         * maps EPOLLERR/EPOLLHUP/EPOLLRDHUP to the error mark; do the same so
         * the loop tears the bind down.
         */
        if (ev->flags & (EV_EOF | EV_ERROR)) {
            evpl_event_mark_error(evpl, event);
        }
    }

    return n;
} /* evpl_core_kqueue_wait */

const struct evpl_core_ops evpl_core_kqueue_ops = {
    .name    = "kqueue",
    .init    = evpl_core_kqueue_init,
    .destroy = evpl_core_kqueue_destroy,
    .add     = evpl_core_kqueue_add,
    .remove  = evpl_core_kqueue_remove,
    .wait    = evpl_core_kqueue_wait,
};
