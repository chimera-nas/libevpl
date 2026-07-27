// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_doorbell.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_doorbell;

#ifndef EVPL_INTERNAL
struct evpl_doorbell {
    uint64_t opaque[8];
};
#endif /* ifndef EVPL_INTERNAL */

typedef void (*evpl_doorbell_callback_t)(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell);

/*
 * Open a doorbell's wakeup fd without registering it on an evpl.  Callable
 * from any thread; a later evpl_add_doorbell_opened() on the owning thread
 * attaches it to the loop.  Rings issued between open and add are retained
 * and delivered on the first dispatch after add.  Use this pair (instead of
 * evpl_add_doorbell, which opens and registers in one step on the owning
 * thread) when the doorbell must be ringable before its owning thread is up.
 */
void
evpl_doorbell_open(
    struct evpl_doorbell *doorbell);

void
evpl_add_doorbell_opened(
    struct evpl             *evpl,
    struct evpl_doorbell    *doorbell,
    evpl_doorbell_callback_t callback);

void
evpl_add_doorbell(
    struct evpl             *evpl,
    struct evpl_doorbell    *doorbell,
    evpl_doorbell_callback_t callback);

void
evpl_remove_doorbell(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell);

int
evpl_doorbell_fd(
    struct evpl_doorbell *doorbell);

void
evpl_ring_doorbell(
    struct evpl_doorbell *doorbell);