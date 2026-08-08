// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Retiring a doorbell from inside the dispatch loop.
 *
 * evpl_remove_doorbell() promises that the library holds no further reference
 * once it returns, so the caller may free the storage the doorbell lives in.
 * The awkward case is a doorbell removed while the very pass that dispatched
 * it is still running: it is listed in evpl->active_events, and the loop
 * reaches for it again after the callbacks return.
 *
 * Every in-tree backend happens to be immune, because its event lives in a
 * bind's private area, which the library recycles onto a freelist rather than
 * frees -- so a stale reference lands on memory that is still mapped and the
 * bug stays invisible.  A caller-allocated doorbell has no such luck, and
 * these are the two orders in which it can happen.  Both are use-after-frees,
 * so this test is only meaningful under a Debug (AddressSanitizer) build.
 *
 * The third case is the quieter failure: a removal that shifts the active list
 * under the loop's cursor makes it skip an entry, and a skipped entry keeps
 * EVPL_ACTIVE set, so nothing ever queues it again.  That does not crash --
 * delivery just stops -- which is why the last check rings a fresh doorbell and
 * insists it still arrives.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evpl/evpl.h"

static int failures;
static int self_fired;
static int pair_fired;
static int survivor_fired;

#define CHECK(cond, ...) \
        do { \
            if (!(cond)) { \
                printf("FAIL: " __VA_ARGS__); printf("\n"); failures++; \
            } else { \
                printf("ok:   " __VA_ARGS__); printf("\n"); \
            } \
        } while (0)

/* Case 1: a doorbell that retires and frees itself from its own callback. */
static void
self_callback(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    self_fired++;

    evpl_remove_doorbell(evpl, doorbell);
    free(doorbell);
} /* self_callback */

/* Case 2: two doorbells rung together, so both are dispatched in one pass;
 * whichever runs first retires and frees the other.  That covers removal on
 * either side of the loop's cursor without depending on which order the event
 * mechanism reports them in. */
static struct evpl_doorbell *pair[2];

static void
pair_callback(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    int i;

    pair_fired++;

    for (i = 0; i < 2; ++i) {
        if (pair[i] && pair[i] != doorbell) {
            evpl_remove_doorbell(evpl, pair[i]);
            free(pair[i]);
            pair[i] = NULL;
        }
    }

    for (i = 0; i < 2; ++i) {
        if (pair[i] == doorbell) {
            evpl_remove_doorbell(evpl, doorbell);
            free(doorbell);
            pair[i] = NULL;
        }
    }
} /* pair_callback */

static void
survivor_callback(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    survivor_fired++;
} /* survivor_callback */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl          *evpl;
    struct evpl_doorbell *db, *survivor;

    evpl_init(NULL);

    evpl = evpl_create(NULL);

    /* --- retired from its own callback --- */
    db = malloc(sizeof(*db));
    memset(db, 0, sizeof(*db));

    evpl_add_doorbell(evpl, db, self_callback);
    evpl_ring_doorbell(db);

    while (!self_fired) {
        evpl_continue(evpl);
    }

    CHECK(self_fired == 1, "doorbell retired from its own callback");

    /* --- one retired from another's callback, same pass --- */
    pair[0] = malloc(sizeof(*pair[0]));
    pair[1] = malloc(sizeof(*pair[1]));
    memset(pair[0], 0, sizeof(*pair[0]));
    memset(pair[1], 0, sizeof(*pair[1]));

    evpl_add_doorbell(evpl, pair[0], pair_callback);
    evpl_add_doorbell(evpl, pair[1], pair_callback);

    /* Rung before pumping, so both are marked active in the same pass. */
    evpl_ring_doorbell(pair[0]);
    evpl_ring_doorbell(pair[1]);

    while (!pair_fired) {
        evpl_continue(evpl);
    }

    CHECK(pair[0] == NULL && pair[1] == NULL,
          "both doorbells of the pair retired");

    /* --- the active list is still intact --- */

    /* A removal that shifted the list under the cursor would have left an
     * entry stranded with EVPL_ACTIVE set, and delivery would simply stop.
     * This hangs rather than fails if that regresses, which is what the test's
     * TIMEOUT is for. */
    survivor = malloc(sizeof(*survivor));
    memset(survivor, 0, sizeof(*survivor));

    evpl_add_doorbell(evpl, survivor, survivor_callback);
    evpl_ring_doorbell(survivor);

    while (!survivor_fired) {
        evpl_continue(evpl);
    }

    CHECK(survivor_fired == 1, "delivery continues after the removals");

    evpl_remove_doorbell(evpl, survivor);
    free(survivor);

    evpl_destroy(evpl);

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);

    return failures != 0;
} /* main */
