// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <unistd.h>

#include "evpl/evpl.h"
#include "tests/test_common.h"

static volatile int      test_done;
static int               oneshot_fired;
static int               rearm_fired;
static int               periodic_fired;
static struct evpl_timer oneshot;
static struct evpl_timer rearm_timer;
static struct evpl_timer periodic;

static void
oneshot_cb(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    oneshot_fired++;
} /* oneshot_cb */

/* Re-arms itself from inside the callback the first time it fires; this only
 * works because a one-shot is removed from the timer set before its callback
 * runs. */
static void
rearm_cb(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    rearm_fired++;
    if (rearm_fired == 1) {
        evpl_add_oneshot_timer(evpl, timer, rearm_cb, 1000);
    }
} /* rearm_cb */

/* Fires every 1ms and signals completion once enough time has passed for the
 * one-shots to have fired and to prove they do not refire. */
static void
periodic_cb(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    periodic_fired++;
    if (periodic_fired >= 10) {
        test_done = 1;
    }
} /* periodic_cb */

static void *
timer_thread_init(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_add_oneshot_timer(evpl, &oneshot, oneshot_cb, 1000);   /* 1 ms */
    evpl_add_oneshot_timer(evpl, &rearm_timer, rearm_cb, 1000);
    evpl_add_timer(evpl, &periodic, periodic_cb, 1000);         /* 1 ms periodic */

    return private_data;
} /* timer_thread_init */

static void
timer_thread_shutdown(
    struct evpl *evpl,
    void        *private_data)
{
    /* Removing an already-fired one-shot must be a harmless no-op. */
    evpl_remove_timer(evpl, &oneshot);
    evpl_remove_timer(evpl, &rearm_timer);
    evpl_remove_timer(evpl, &periodic);
} /* timer_thread_shutdown */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_thread *thread;

    /* Selects the core mechanism from EVPL_TEST_CORE_MECH so ctest can run
     * this against every mechanism compiled in -- the timer deadline drives
     * the core wait timeout, which each mechanism converts differently. */
    test_evpl_config();

    thread = evpl_thread_create(NULL, timer_thread_init,
                                timer_thread_shutdown, NULL);

    while (!test_done) {
        usleep(1000);
    }

    /* By the time the periodic timer has fired 10 times (~10ms), the plain
     * one-shot must have fired exactly once and the re-armed one-shot exactly
     * twice -- and neither may have refired in the intervening ~8ms. */
    if (oneshot_fired != 1) {
        fprintf(stderr, "one-shot fired %d times, expected 1\n", oneshot_fired);
        return 1;
    }
    if (rearm_fired != 2) {
        fprintf(stderr, "re-armed one-shot fired %d times, expected 2\n",
                rearm_fired);
        return 1;
    }
    if (periodic_fired < 10) {
        fprintf(stderr, "periodic fired %d times, expected >= 10\n",
                periodic_fired);
        return 1;
    }

    evpl_thread_destroy(thread);

    printf("oneshot timer test passed\n");
    return 0;
} /* main */
