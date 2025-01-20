// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include "core/test_log.h"
#include "thread/thread.h"
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
thread_destroy(void *private_data)
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

    evpl_init(NULL);

    thread = evpl_thread_create(thread_init, NULL, NULL, thread_destroy, -1,
                                &number);

    evpl_thread_destroy(thread);

    evpl_cleanup();
} /* main */
