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
    uint64_t opaque[10];
};
#endif /* ifndef EVPL_INTERNAL */

typedef void (*evpl_doorbell_callback_t)(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell);

/*
 * The add/remove/ring calls each record where they were called from, so that
 * the abort in evpl_ring_doorbell can name both the doorbell's last lifecycle
 * transition and the site that rang it.  Ringing a doorbell that has been
 * removed is a use-after-close of its eventfd, and the fatal it produces is
 * otherwise almost unactionable: "fd -1" says only that SOMETHING rang
 * SOMETHING after it died, which in a process with several doorbells and
 * several threads posting across them is not enough to find either end.
 *
 * The macros below are the API; the _at forms are what they expand to.
 */
void
evpl_add_doorbell_at(
    struct evpl             *evpl,
    struct evpl_doorbell    *doorbell,
    evpl_doorbell_callback_t callback,
    const char              *file,
    int                      line);

/*
 * Retire a doorbell.  Must be called on the thread that added it, and before
 * that thread's evpl is destroyed.
 *
 * Once this returns the library holds no further reference to the doorbell, so
 * the caller may free the storage it lives in -- including from inside the
 * doorbell's own callback.
 */
void
evpl_remove_doorbell_at(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell,
    const char           *file,
    int                   line);

int
evpl_doorbell_fd(
    struct evpl_doorbell *doorbell);

void
evpl_ring_doorbell_at(
    struct evpl_doorbell *doorbell,
    const char           *file,
    int                   line);

/* Callers use these; they capture the call site.  Deliberately not guarded on
 * EVPL_INTERNAL -- the macro names differ from the _at function names, so
 * there is nothing to collide with, and libevpl's own call sites get the same
 * diagnostics as everyone else's. */
#define evpl_add_doorbell(evpl, doorbell, callback) \
        evpl_add_doorbell_at((evpl), (doorbell), (callback), __FILE__, __LINE__)
#define evpl_remove_doorbell(evpl, doorbell) \
        evpl_remove_doorbell_at((evpl), (doorbell), __FILE__, __LINE__)
#define evpl_ring_doorbell(doorbell) \
        evpl_ring_doorbell_at((doorbell), __FILE__, __LINE__)
