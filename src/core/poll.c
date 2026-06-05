// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/evpl.h"
#include "core/poll.h"
#include "macros.h"

SYMBOL_EXPORT struct evpl_poll *
evpl_add_poll(
    struct evpl               *evpl,
    evpl_poll_enter_callback_t enter_callback,
    evpl_poll_exit_callback_t  exit_callback,
    evpl_poll_callback_t       callback,
    void                      *private_data)
{
    struct evpl_poll *poll = &evpl->poll[evpl->num_poll];

    poll->enter_callback = enter_callback;
    poll->exit_callback  = exit_callback;
    poll->callback       = callback;
    poll->private_data   = private_data;

    ++evpl->num_poll;

    return poll;
} /* evpl_add_poll */

SYMBOL_EXPORT void
evpl_remove_poll(
    struct evpl      *evpl,
    struct evpl_poll *poll)
{
    int index = poll - evpl->poll;

    if (index + 1 < evpl->num_poll) {
        evpl->poll[index] = evpl->poll[evpl->num_poll - 1];
    }

    evpl->num_poll--;

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