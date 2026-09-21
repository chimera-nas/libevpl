// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stddef.h>

#include "spdk_test_harness.h"

static void *
thread_init(
    struct evpl *evpl,
    void        *private_data)
{
    int *number = private_data;

    evpl_test_info("thread_init ran with number=%d", *number);

    evpl_test_abort_if(*number != 42,
                       "got wrong argument in thread init function");

    return private_data;
} /* thread_init */

static void
thread_shutdown(
    struct evpl *evpl,
    void        *private_data)
{
    int *number = private_data;

    evpl_test_info("thread_shutdown ran with number=%d", *number);
} /* thread_shutdown */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_thread *thread;
    int                 number = 42;

    evpl_spdk_test_init(3);

    evpl_spdk_test_config();

    /* From a plain pthread the create blocks until init ran on the worker
     * spdk_thread and destroy blocks until teardown completed. */
    thread = evpl_thread_create(NULL, thread_init, thread_shutdown, &number);

    evpl_test_info("thread created, now destroying");

    evpl_thread_destroy(thread);

    evpl_test_info("thread destroyed");

    return 0;
} /* main */
