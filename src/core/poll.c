// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/evpl.h"
#include "core/poll.h"
#include "macros.h"

/*
 * A poll slot IS the handle evpl_add_poll() hands back, and every registered
 * poller on this thread is holding one.  So a slot must never change owner:
 * removal tombstones it (callback NULL, skipped by the dispatch loops) and
 * add reuses a tombstone before extending the array.
 *
 * Compacting instead -- moving the tail entry into the removed slot -- silently
 * repoints some other poller's handle at a different poller.  Its own later
 * evpl_remove_poll() then unregisters the wrong slot and leaves its callback
 * live, firing against freed private_data.  Any thread with two or more
 * pollers that are not torn down in exact reverse order can hit it; it showed
 * up as an intermittent heap-use-after-free tearing down a thread carrying
 * both a filesystem's completion polls and an RPC thread's.
 */
SYMBOL_EXPORT struct evpl_poll *
evpl_add_poll(
    struct evpl               *evpl,
    evpl_poll_enter_callback_t enter_callback,
    evpl_poll_exit_callback_t  exit_callback,
    evpl_poll_callback_t       callback,
    void                      *private_data)
{
    struct evpl_poll *poll = NULL;
    int               i;

    for (i = 0; i < evpl->num_poll; ++i) {
        if (evpl->poll[i].callback == NULL) {
            poll = &evpl->poll[i];
            break;
        }
    }

    if (!poll) {
        poll = &evpl->poll[evpl->num_poll++];
    }

    poll->enter_callback = enter_callback;
    poll->exit_callback  = exit_callback;
    poll->callback       = callback;
    poll->private_data   = private_data;

    return poll;
} /* evpl_add_poll */

SYMBOL_EXPORT void
evpl_remove_poll(
    struct evpl      *evpl,
    struct evpl_poll *poll)
{
    poll->enter_callback = NULL;
    poll->exit_callback  = NULL;
    poll->callback       = NULL;
    poll->private_data   = NULL;

    /* Reclaim trailing tombstones so num_poll -- which also answers "does this
     * thread poll at all?" -- returns to zero once the last poller leaves. */
    while (evpl->num_poll > 0 &&
           evpl->poll[evpl->num_poll - 1].callback == NULL) {
        evpl->num_poll--;
    }
} /* evpl_remove_poll */

SYMBOL_EXPORT void
evpl_activity(struct evpl *evpl)
{
    evpl->activity++;
} /* evpl_activity */

/*
 * Pin the calling thread into poll mode for as long as the pin count is
 * non-zero.  Used by frameworks (e.g. VFIO/NVMe in poll mode) that have an
 * outstanding request which can only be reaped by polling, since the loop
 * would otherwise fall back to interrupt/event mode after spin_ns of
 * inactivity and never reap the completion.  Refcounted so that multiple
 * queues on one thread compose correctly.
 */
SYMBOL_EXPORT void
evpl_poll_pin(struct evpl *evpl)
{
    evpl->poll_pin_count++;
} /* evpl_poll_pin */

SYMBOL_EXPORT void
evpl_poll_unpin(struct evpl *evpl)
{
    evpl->poll_pin_count--;
} /* evpl_poll_unpin */