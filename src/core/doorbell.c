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


/*
 * Open a doorbell's wakeup fd without registering it on an evpl.  Callable
 * from any thread; a later evpl_add_doorbell_opened() on the owning thread
 * attaches it to the loop.  Rings issued between open and add are retained
 * (eventfd counter / pipe buffer) and delivered on the first dispatch after
 * add.
 */
SYMBOL_EXPORT void
evpl_doorbell_open(struct evpl_doorbell *doorbell)
{
    evpl_core_abort_if(evpl_wakeup_open(&doorbell->wakeup) < 0,
                       "evpl_doorbell_open: wakeup open failed");
} /* evpl_doorbell_open */

/*
 * Register a doorbell whose wakeup was already opened with
 * evpl_doorbell_open().  Must run on the evpl's own thread.
 */
SYMBOL_EXPORT void
evpl_add_doorbell_opened(
    struct evpl             *evpl,
    struct evpl_doorbell    *doorbell,
    evpl_doorbell_callback_t callback)
{
    struct evpl_event *event = &doorbell->event;

    evpl_add_event(evpl, event, doorbell->wakeup.rfd,
                   evpl_event_user_callback, NULL, NULL);

    evpl_event_read_interest(evpl, event);

    doorbell->callback = callback;

} /* evpl_add_doorbell_opened */

SYMBOL_EXPORT void
evpl_add_doorbell(
    struct evpl             *evpl,
    struct evpl_doorbell    *doorbell,
    evpl_doorbell_callback_t callback)
{
    evpl_doorbell_open(doorbell);

    evpl_add_doorbell_opened(evpl, doorbell, callback);
} /* evpl_add_doorbell */

SYMBOL_EXPORT void
evpl_remove_doorbell(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    evpl_remove_event(evpl, &doorbell->event);

    evpl_wakeup_close(&doorbell->wakeup);
} /* evpl_remove_doorbell */

SYMBOL_EXPORT int
evpl_doorbell_fd(struct evpl_doorbell *doorbell)
{
    return doorbell->event.fd;
} /* evpl_doorbell_fd */

SYMBOL_EXPORT void
evpl_ring_doorbell(struct evpl_doorbell *doorbell)
{
    ssize_t len;
    int     err;

    len = evpl_wakeup_signal(&doorbell->wakeup);

    err = errno;

    evpl_core_abort_if(len != sizeof(uint64_t),
                       "failed to ring doorbell (fd %d): len=%zd errno=%d (%s)",
                       doorbell->wakeup.wfd, len, err, strerror(err));
} /* evpl_ring_doorbell */
