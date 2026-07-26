// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/time.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

#include "core/select.h"
#include "core/core.h"
#include "core/event_fn.h"
#include "core/evpl.h"

#define EVPL_SELECT_INITIAL_SLOTS 64

static int
evpl_core_select_init(
    struct evpl_core *evc,
    int               max_events)
{
    struct evpl_core_select *s = &evc->u.select;

    (void) max_events;   /* select reports every ready fd; no batch limit */

    s->num_slots = EVPL_SELECT_INITIAL_SLOTS;
    s->events    = calloc(s->num_slots, sizeof(struct evpl_event *));

    if (!s->events) {
        return ENOMEM;
    }

    s->max_fd = -1;

    return 0;
} /* evpl_core_select_init */

static void
evpl_core_select_destroy(struct evpl_core *evc)
{
    struct evpl_core_select *s = &evc->u.select;

    free(s->events);
    s->events = NULL;
} /* evpl_core_select_destroy */

static void
evpl_core_select_add(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    struct evpl_core_select *s = &evc->u.select;

    if (event->fd <= 0) {
        abort();
    }

    /* fd_set is a fixed-size bitmap; a descriptor at or beyond FD_SETSIZE
     * cannot be represented and would corrupt the stack if we set it. */
    evpl_core_abort_if(event->fd >= FD_SETSIZE,
                       "select backend: fd %d exceeds FD_SETSIZE (%d); "
                       "use the epoll or kqueue mechanism for this workload",
                       event->fd, (int) FD_SETSIZE);

    if (event->fd >= s->num_slots) {
        int new_slots = s->num_slots;

        while (new_slots <= event->fd) {
            new_slots *= 2;
        }

        if (new_slots > FD_SETSIZE) {
            new_slots = FD_SETSIZE;
        }

        s->events = realloc(s->events, new_slots * sizeof(struct evpl_event *));

        evpl_core_abort_if(!s->events, "select backend: failed to grow fd table");

        memset(&s->events[s->num_slots], 0,
               (new_slots - s->num_slots) * sizeof(struct evpl_event *));

        s->num_slots = new_slots;
    }

    s->events[event->fd] = event;

    if (event->fd > s->max_fd) {
        s->max_fd = event->fd;
    }
} /* evpl_core_select_add */

static void
evpl_core_select_remove(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    struct evpl_core_select *s = &evc->u.select;

    if (event->fd <= 0 || event->fd >= s->num_slots) {
        return;
    }

    s->events[event->fd] = NULL;

    while (s->max_fd >= 0 && !s->events[s->max_fd]) {
        s->max_fd--;
    }
} /* evpl_core_select_remove */

/*
 * A slot is live only while the event it holds is still registered on that
 * exact descriptor.  Protocols close a socket without calling
 * evpl_remove_event (with epoll/kqueue the kernel drops the registration when
 * the fd closes), and the bind -- and therefore the embedded evpl_event -- is
 * later recycled for a new connection on a different fd.  Comparing the
 * event's own fd against the slot index detects such a stale slot and lets us
 * drop it instead of polling a descriptor we no longer own.
 */
static inline struct evpl_event *
evpl_core_select_slot(
    struct evpl_core_select *s,
    int                      fd)
{
    struct evpl_event *event = s->events[fd];

    if (!event) {
        return NULL;
    }

    if (event->fd != fd) {
        s->events[fd] = NULL;
        return NULL;
    }

    return event;
} /* evpl_core_select_slot */

/*
 * select() failed with EBADF: at least one registered descriptor was closed
 * behind our back.  Probe each slot and drop the dead ones so the loop makes
 * progress instead of spinning on the same error forever.
 */
static void
evpl_core_select_prune(struct evpl_core_select *s)
{
    struct evpl_event *event;
    int                fd;

    for (fd = 0; fd <= s->max_fd; ++fd) {
        event = evpl_core_select_slot(s, fd);

        if (!event) {
            continue;
        }

        if (fcntl(fd, F_GETFD) < 0 && errno == EBADF) {
            s->events[fd] = NULL;
        }
    }

    while (s->max_fd >= 0 && !s->events[s->max_fd]) {
        s->max_fd--;
    }
} /* evpl_core_select_prune */

static int
evpl_core_select_wait(
    struct evpl_core *evc,
    int               max_msecs)
{
    struct evpl_core_select *s    = &evc->u.select;
    struct evpl             *evpl = evpl_from_core(evc);
    struct evpl_event       *event;
    fd_set                   readfds, writefds;
    struct timeval           tv, *tvp;
    int                      fd, nfds, n, count = 0;

    FD_ZERO(&readfds);
    FD_ZERO(&writefds);

    /*
     * select is level-triggered and cannot be armed edge-wise, so only ask
     * about the directions the loop actually wants.  Arming writability
     * unconditionally would report ready on every call for any idle connected
     * socket and spin the loop at 100% CPU.
     */
    for (fd = 0; fd <= s->max_fd; ++fd) {
        event = evpl_core_select_slot(s, fd);

        if (!event) {
            continue;
        }

        if (event->flags & EVPL_READ_INTEREST) {
            FD_SET(fd, &readfds);
        }

        if (event->flags & EVPL_WRITE_INTEREST) {
            FD_SET(fd, &writefds);
        }
    }

    nfds = s->max_fd + 1;

    if (max_msecs < 0) {
        tvp = NULL;
    } else {
        tv.tv_sec  = max_msecs / 1000;
        tv.tv_usec = (max_msecs % 1000) * 1000;
        tvp        = &tv;
    }

    n = select(nfds, &readfds, &writefds, NULL, tvp);

    if (n < 0) {
        if (errno == EBADF) {
            evpl_core_select_prune(s);
        }
        return n;
    }

    if (n == 0) {
        return 0;
    }

    for (fd = 0; fd <= s->max_fd; ++fd) {
        event = evpl_core_select_slot(s, fd);

        if (!event) {
            continue;
        }

        if (FD_ISSET(fd, &readfds)) {
            evpl_event_mark_readable(evpl, event);
            count++;
        }

        if (FD_ISSET(fd, &writefds)) {
            evpl_event_mark_writable(evpl, event);
            count++;
        }
    }

    return count;
} /* evpl_core_select_wait */

const struct evpl_core_ops evpl_core_select_ops = {
    .name    = "select",
    .init    = evpl_core_select_init,
    .destroy = evpl_core_select_destroy,
    .add     = evpl_core_select_add,
    .remove  = evpl_core_select_remove,
    .wait    = evpl_core_select_wait,
};
