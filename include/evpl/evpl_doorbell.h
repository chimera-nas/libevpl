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

void
evpl_add_doorbell(
    struct evpl             *evpl,
    struct evpl_doorbell    *doorbell,
    evpl_doorbell_callback_t callback);

/*
 * Retire a doorbell.  Must be called on the thread that added it, and before
 * that thread's evpl is destroyed.
 *
 * Once this returns the library holds no further reference to the doorbell, so
 * the caller may free the storage it lives in -- including from inside the
 * doorbell's own callback.
 */
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