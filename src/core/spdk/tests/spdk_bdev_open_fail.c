// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Opening a nonexistent bdev fails asynchronously with a nonzero status and
 * a NULL device, and a subsequent good open on the same evpl succeeds.
 */

#include <stddef.h>

#include "spdk_test_harness.h"
#include "spdk_bdev_test_common.h"

struct open_fail_state {
    struct evpl_block_device *bdev;
    volatile int              done;
};

static void
close_done(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    struct open_fail_state *state = private_data;

    evpl_test_abort_if(status, "close failed: %d", status);

    state->done = 1;
} /* close_done */

static void
good_open_done(
    struct evpl              *evpl,
    struct evpl_block_device *bdev,
    int                       status,
    void                     *private_data)
{
    struct open_fail_state *state = private_data;

    evpl_test_abort_if(status || !bdev,
                       "expected open of Malloc0 to succeed: %d", status);

    state->bdev = bdev;

    evpl_block_close_device(evpl, bdev, close_done, state);
} /* good_open_done */

static void
bad_open_done(
    struct evpl              *evpl,
    struct evpl_block_device *bdev,
    int                       status,
    void                     *private_data)
{
    evpl_test_abort_if(status == 0 || bdev,
                       "open of nonexistent bdev unexpectedly succeeded");

    evpl_block_open_device(evpl, EVPL_BLOCK_PROTOCOL_SPDK_BDEV, "Malloc0",
                           good_open_done, private_data);
} /* bad_open_done */

static void *
thread_init(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_block_open_device(evpl, EVPL_BLOCK_PROTOCOL_SPDK_BDEV,
                           "DoesNotExist", bad_open_done, private_data);

    return private_data;
} /* thread_init */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_thread    *thread;
    struct open_fail_state state = { 0 };

    evpl_spdk_test_init(2);

    evpl_spdk_bdev_test_up(EVPL_SPDK_BDEV_TEST_MALLOC_JSON);

    evpl_spdk_test_config();

    thread = evpl_thread_create(NULL, thread_init, NULL, &state);

    while (!state.done) {
        usleep(1000);
    }

    evpl_thread_destroy(thread);

    evpl_spdk_bdev_test_down();

    return 0;
} /* main */
