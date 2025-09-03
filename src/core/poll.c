// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/evpl.h"
#include "core/poll.h"

struct evpl_poll *
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

void
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