// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stddef.h>

#include "core/test_log.h"
#include "evpl/evpl.h"

void *
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

void
thread_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    int *number = private_data;

    evpl_test_info("thread_destroy ran with number=%d", *number);
} /* thread_destroy */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_thread *thread;
    int                 number = 42;

    thread = evpl_thread_create(NULL, thread_init, thread_destroy, &number);

    evpl_test_info("thread created, now destroying");

    evpl_thread_destroy(thread);

    evpl_test_info("thread destroyed");

    return 0;
} /* main */
