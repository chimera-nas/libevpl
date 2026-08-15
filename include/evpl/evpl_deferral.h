// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_deferral.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

typedef void (*deferral_callback_t)(
    struct evpl *evpl,
    void        *private_data);

struct evpl_deferral {
    deferral_callback_t callback;
    void               *private_data;
    uint64_t            armed;
};

void
evpl_deferral_init(
    struct evpl_deferral *deferral,
    deferral_callback_t   callback,
    void                 *private_data);

/*
 * Arm a deferral: its callback runs once, on the next pass of the event loop.
 *
 * Arming one that is already armed is a no-op, so any number of calls before
 * the loop next runs produce exactly one callback.  Arming from inside the
 * callback is legal and produces another, since the deferral is disarmed
 * before it is called.
 */
void
evpl_defer(
    struct evpl          *evpl,
    struct evpl_deferral *deferral);

/*
 * Disarm a deferral that has been armed but has not yet run.  A no-op on one
 * that is not armed, including one that has already run, so a caller tearing
 * down state need not track whether it armed anything.  Must be called on the
 * thread that armed it.
 *
 * Needed by anything that frees the object a deferral points at: the event
 * loop holds the pointer until the deferral fires, so tearing the object down
 * without this leaves the callback to run against freed memory.
 */
void
evpl_remove_deferral(
    struct evpl          *evpl,
    struct evpl_deferral *deferral);
