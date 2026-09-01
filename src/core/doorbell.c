// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <utlist.h>

#include "doorbell.h"
#include "wakeup.h"
#include "evpl/evpl.h"
#include "macros.h"
#include "logging.h"
#include "event_fn.h"

/* The public opaque struct is what consumers allocate; the real one must fit
 * inside it.  Doorbells are embedded by value in caller structs, so growing
 * this past its public size corrupts them silently. */
_Static_assert(sizeof(struct evpl_doorbell) <= 10 * sizeof(uint64_t),
               "struct evpl_doorbell exceeds its public opaque size");

static void
evpl_event_user_callback(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_doorbell *doorbell = container_of(event, struct evpl_doorbell, event);

    if (evpl_wakeup_drain(event->fd) < 0) {
        evpl_event_mark_unreadable(evpl, event);
        return;
    }

    doorbell->callback(evpl, doorbell);
} /* evpl_event_user_callback */


SYMBOL_EXPORT void
evpl_add_doorbell_at(
    struct evpl             *evpl,
    struct evpl_doorbell    *doorbell,
    evpl_doorbell_callback_t callback,
    const char              *file,
    int                      line)
{
    struct evpl_event *event = &doorbell->event;

    evpl_core_abort_if(evpl_wakeup_open(&doorbell->wakeup) < 0,
                       "evpl_add_doorbell: wakeup open failed");

    evpl_add_event(evpl, event, doorbell->wakeup.rfd,
                   evpl_event_user_callback, NULL, NULL);

    evpl_event_read_interest(evpl, event);

    doorbell->callback  = callback;
    doorbell->site_file = file;
    doorbell->site_line = line;
    doorbell->state     = EVPL_DOORBELL_LIVE;

} /* evpl_add_doorbell_at */

SYMBOL_EXPORT void
evpl_remove_doorbell_at(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell,
    const char           *file,
    int                   line)
{
    evpl_remove_event(evpl, &doorbell->event);

    evpl_wakeup_close(&doorbell->wakeup);

    /* Recorded before returning, because the caller is allowed to free the
     * storage this lives in the moment we do -- a doorbell that is rung after
     * that is a use-after-free of the struct as well as a use-after-close of
     * the fd, and this is the last moment the fields are ours to set. */
    doorbell->site_file = file;
    doorbell->site_line = line;
    doorbell->state     = EVPL_DOORBELL_REMOVED;
} /* evpl_remove_doorbell_at */

SYMBOL_EXPORT int
evpl_doorbell_fd(struct evpl_doorbell *doorbell)
{
    return doorbell->event.fd;
} /* evpl_doorbell_fd */

SYMBOL_EXPORT void
evpl_ring_doorbell_at(
    struct evpl_doorbell *doorbell,
    const char           *file,
    int                   line)
{
    ssize_t len;
    int     err;

    len = evpl_wakeup_signal(&doorbell->wakeup);

    err = errno;

    if (likely(len == (ssize_t) sizeof(uint64_t))) {
        return;
    }

    /* The overwhelmingly likely cause is ringing a doorbell that has already
     * been removed -- its eventfd is closed and wfd is -1 -- from a thread
     * that still held a pointer to it.  Report BOTH ends: the site that rang
     * it, and where the doorbell last changed state.  Without the pair, the
     * abort names neither the poster nor the owner, and in a process running
     * several doorbells across several threads that is not enough to act on.
     *
     * state is checked against its magics so that an unzeroed or already-freed
     * struct is reported as unknown rather than misread as one of the states. */
    switch (doorbell->state) {
        case EVPL_DOORBELL_REMOVED:
            evpl_core_abort(
                "failed to ring doorbell %p (fd %d) from %s:%d: "
                "len=%zd errno=%d (%s); it was REMOVED at %s:%d -- "
                "something rang it after its owner retired it",
                doorbell, doorbell->wakeup.wfd, file, line, len, err,
                strerror(err),
                doorbell->site_file ? doorbell->site_file : "?",
                doorbell->site_line);
            break;
        case EVPL_DOORBELL_LIVE:
            evpl_core_abort(
                "failed to ring doorbell %p (fd %d) from %s:%d: "
                "len=%zd errno=%d (%s); it is LIVE, added at %s:%d",
                doorbell, doorbell->wakeup.wfd, file, line, len, err,
                strerror(err),
                doorbell->site_file ? doorbell->site_file : "?",
                doorbell->site_line);
            break;
        default:
            evpl_core_abort(
                "failed to ring doorbell %p (fd %d) from %s:%d: "
                "len=%zd errno=%d (%s); it was never added, or its storage is "
                "no longer a doorbell (state 0x%08x)",
                doorbell, doorbell->wakeup.wfd, file, line, len, err,
                strerror(err), doorbell->state);
            break;
    } /* switch */
} /* evpl_ring_doorbell_at */
