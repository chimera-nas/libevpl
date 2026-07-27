// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Timer coverage under the poller pump: one-shot and periodic evpl timers on
 * an SPDK evpl thread, serviced by evpl_continue's slow path as the reactor
 * pumps.
 */

#include <stddef.h>

#include "spdk_test_harness.h"

static struct evpl_timer oneshot_timer;
static struct evpl_timer periodic_timer;
static volatile int      oneshot_fired;
static volatile int      periodic_count;

static void
oneshot_callback(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    oneshot_fired = 1;
} /* oneshot_callback */

static void
periodic_callback(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    periodic_count++;
} /* periodic_callback */

static void *
timer_init(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_add_oneshot_timer(evpl, &oneshot_timer, oneshot_callback, 10000);

    evpl_add_timer(evpl, &periodic_timer, periodic_callback, 5000);

    return private_data;
} /* timer_init */

static void
timer_shutdown(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_remove_timer(evpl, &periodic_timer);
} /* timer_shutdown */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_thread *thread;

    evpl_spdk_test_init(2);

    evpl_spdk_test_config();

    thread = evpl_thread_create(NULL, timer_init, timer_shutdown, NULL);

    while (!oneshot_fired || periodic_count < 5) {
        usleep(1000);
    }

    evpl_test_info("oneshot fired, periodic fired %d times", periodic_count);

    evpl_thread_destroy(thread);

    return 0;
} /* main */
