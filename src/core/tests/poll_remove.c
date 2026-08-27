// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Retiring one poller must not disturb the others.
 *
 * evpl_add_poll() returns a handle, and every poller registered on a thread is
 * holding one at the same time.  A removal therefore has to leave the other
 * handles meaning exactly what they meant before -- otherwise the next poller
 * to retire unregisters somebody else's slot, and its own callback stays live
 * and keeps firing against private_data its owner has already released.
 *
 * The order below is the one that exposes it: retire the FIRST poller, then the
 * LAST.  A dispatch array compacted by moving the tail entry into the freed
 * slot answers the second removal by unregistering the wrong entry -- the
 * poller that was moved keeps running and the one that was not stops.  Any
 * thread with two or more pollers not torn down in exact reverse registration
 * order can reach it.
 *
 * The pollers are identified by value rather than by a pointer into freed
 * storage, so a stale dispatch is a plain counter mismatch: this fails the same
 * way in a Release build as under AddressSanitizer.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "evpl/evpl.h"

#define NPOLL     5
#define PUMP_ITER 64

static int failures;
static int fired[NPOLL];

#define CHECK(cond, ...) \
        do { \
            if (!(cond)) { \
                printf("FAIL: " __VA_ARGS__); printf("\n"); failures++; \
            } else { \
                printf("ok:   " __VA_ARGS__); printf("\n"); \
            } \
        } while (0)

static void
poll_callback(
    struct evpl *evpl,
    void        *private_data)
{
    fired[(intptr_t) private_data]++;
} /* poll_callback */

/* Clear the counters and run the loop long enough that every registered poller
 * has certainly been dispatched.  The loop only visits pollers while it is in
 * poll mode, which it enters on its own as soon as one is registered and holds
 * while a caller keeps pumping. */
static void
pump(struct evpl *evpl)
{
    int i;

    memset(fired, 0, sizeof(fired));

    for (i = 0; i < PUMP_ITER; ++i) {
        evpl_continue(evpl);
    }
} /* pump */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl      *evpl;
    struct evpl_poll *handle[NPOLL];
    intptr_t          i;

    evpl_init(NULL);

    evpl = evpl_create(NULL);

    for (i = 0; i < 4; ++i) {
        handle[i] = evpl_add_poll(evpl, NULL, NULL, poll_callback,
                                  (void *) i);
    }

    pump(evpl);
    CHECK(fired[0] && fired[1] && fired[2] && fired[3],
          "all four pollers dispatched");

    /* --- retire the first --- */
    evpl_remove_poll(evpl, handle[0]);

    pump(evpl);
    CHECK(!fired[0], "the retired poller stopped");
    CHECK(fired[1] && fired[2] && fired[3], "the other three still dispatch");

    /* --- retire the last, whose handle a compacting removal would have
     * invalidated above --- */
    evpl_remove_poll(evpl, handle[3]);

    pump(evpl);
    CHECK(!fired[3], "the second retired poller stopped");
    CHECK(!fired[0], "the first retired poller is still gone");
    CHECK(fired[1] && fired[2], "the survivors still dispatch");

    /* --- a poller added after the removals --- */
    handle[4] = evpl_add_poll(evpl, NULL, NULL, poll_callback, (void *) 4);

    pump(evpl);
    CHECK(fired[4], "a poller added after the removals dispatches");
    CHECK(fired[1] && fired[2], "and the survivors are undisturbed");
    CHECK(!fired[0] && !fired[3], "and the retired ones stay retired");

    evpl_remove_poll(evpl, handle[1]);

    pump(evpl);
    CHECK(!fired[1], "the third retired poller stopped");
    CHECK(fired[2] && fired[4], "the last two still dispatch");

    evpl_remove_poll(evpl, handle[4]);
    evpl_remove_poll(evpl, handle[2]);

    evpl_destroy(evpl);

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);

    return failures != 0;
} /* main */
