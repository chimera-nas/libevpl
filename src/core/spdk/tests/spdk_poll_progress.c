// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "spdk_test_harness.h"

static struct evpl_poll *poller;
static atomic_int        polled;
static void
poll_fn(
    struct evpl *evpl,
    void        *arg)
{
    atomic_fetch_add(&polled, 1);
    evpl_activity(evpl);
} /* poll_fn */
static void *
start(
    struct evpl *evpl,
    void        *arg)
{
    poller = evpl_add_poll(evpl, NULL, NULL, poll_fn, NULL);
    evpl_poll_pin(evpl);
    return NULL;
} /* start */
static void
stop(
    struct evpl *evpl,
    void        *arg)
{
    evpl_poll_unpin(evpl);
    evpl_remove_poll(evpl, poller);
} /* stop */
int
main(void)
{
    struct evpl_thread *thread;

    evpl_spdk_test_init(1);
    evpl_spdk_test_config();
    thread = evpl_thread_create(NULL, start, stop, NULL);
    while (atomic_load(&polled) < 5) {
        usleep(1000);
    }
    evpl_thread_destroy(thread);
    return 0;
} /* main */
