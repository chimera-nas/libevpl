// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Doorbell ping-pong between two SPDK evpl threads: exercises eventfd events
 * through the mechanism's internal epoll and cross-thread wakeups under the
 * poller pump.
 */

#include <stddef.h>

#include "spdk_test_harness.h"

#define DB_ITERS 100

static struct evpl_doorbell a_doorbell;
static struct evpl_doorbell b_doorbell;
static volatile int         count;
static volatile int         done;

static void
a_callback(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    if (done) {
        return;
    }

    count++;

    if (count >= DB_ITERS) {
        done = 1;
        return;
    }

    evpl_ring_doorbell(&b_doorbell);
} /* a_callback */

static void
b_callback(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    if (done) {
        return;
    }

    evpl_ring_doorbell(&a_doorbell);
} /* b_callback */

static void *
a_init(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_add_doorbell(evpl, &a_doorbell, a_callback);

    return private_data;
} /* a_init */

static void
a_shutdown(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_remove_doorbell(evpl, &a_doorbell);
} /* a_shutdown */

static void *
b_init(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_add_doorbell(evpl, &b_doorbell, b_callback);

    return private_data;
} /* b_init */

static void
b_shutdown(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_remove_doorbell(evpl, &b_doorbell);
} /* b_shutdown */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_thread *thread_a;
    struct evpl_thread *thread_b;

    evpl_spdk_test_init(2);

    evpl_spdk_test_config();

    thread_a = evpl_thread_create(NULL, a_init, a_shutdown, NULL);
    thread_b = evpl_thread_create(NULL, b_init, b_shutdown, NULL);

    evpl_ring_doorbell(&a_doorbell);

    while (!done) {
        usleep(1000);
    }

    evpl_test_info("doorbell ping-pong completed %d rounds", count);

    evpl_thread_destroy(thread_a);
    evpl_thread_destroy(thread_b);

    return 0;
} /* main */
