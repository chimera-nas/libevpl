// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * SPDK bdev block backend: async open on the owning evpl thread, then a
 * callback-driven chain over a malloc bdev covering sync write (flush
 * chain), read-verify, flush, discard, write_zeroes, zero-verify, a
 * misaligned-buffer write/read pair (bounce path when the bdev has an
 * alignment requirement), async close.
 */

#include <stddef.h>
#include <string.h>

#include "spdk_test_harness.h"
#include "spdk_bdev_test_common.h"

#define TEST_PATTERN_A 0xAB
#define TEST_PATTERN_B 0x5C

struct bdev_test_state {
    struct evpl              *evpl;
    struct evpl_block_device *bdev;
    struct evpl_block_queue  *queue;
    struct evpl_iovec         iov;    /* 8 KiB scratch */
    int                       step;
    volatile int              done;
};

static void bdev_step(
    struct evpl            *evpl,
    struct bdev_test_state *state);

static void
bdev_step_done(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    struct bdev_test_state *state = private_data;

    evpl_test_abort_if(status, "step %d failed: %d", state->step, status);

    state->step++;

    bdev_step(evpl, state);
} /* bdev_step_done */

static void
bdev_close_done(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    struct bdev_test_state *state = private_data;

    evpl_test_abort_if(status, "device close failed: %d", status);

    state->done = 1;
} /* bdev_close_done */

static void
bdev_step(
    struct evpl            *evpl,
    struct bdev_test_state *state)
{
    struct evpl_iovec view;

    switch (state->step) {
        case 0:
            /* Durable write: exercises the write-then-flush chain when the
             * bdev reports a write cache. */
            memset(state->iov.data, TEST_PATTERN_A, 4096);
            view        = state->iov;
            view.length = 4096;
            evpl_block_write(evpl, state->queue, &view, 1, 0, 1,
                             bdev_step_done, state);
            break;
        case 1:
            memset(state->iov.data, 0, 4096);
            view        = state->iov;
            view.length = 4096;
            evpl_block_read(evpl, state->queue, &view, 1, 0,
                            bdev_step_done, state);
            break;
        case 2:
            for (int i = 0; i < 4096; i++) {
                evpl_test_abort_if(
                    ((unsigned char *) state->iov.data)[i] != TEST_PATTERN_A,
                    "read data mismatch at %d", i);
            }
            evpl_block_flush(evpl, state->queue, bdev_step_done, state);
            break;
        case 3:
            evpl_block_discard(evpl, state->queue, 0, 8 * 4096,
                               bdev_step_done, state);
            break;
        case 4:
            /* First re-establish a known pattern... */
            memset(state->iov.data, TEST_PATTERN_A, 4096);
            view        = state->iov;
            view.length = 4096;
            evpl_block_write(evpl, state->queue, &view, 1, 4096, 0,
                             bdev_step_done, state);
            break;
        case 5:
            /* ...then zero it. */
            evpl_block_write_zeroes(evpl, state->queue, 4096, 4096,
                                    bdev_step_done, state);
            break;
        case 6:
            memset(state->iov.data, TEST_PATTERN_A, 4096);
            view        = state->iov;
            view.length = 4096;
            evpl_block_read(evpl, state->queue, &view, 1, 4096,
                            bdev_step_done, state);
            break;
        case 7:
            for (int i = 0; i < 4096; i++) {
                evpl_test_abort_if(
                    ((unsigned char *) state->iov.data)[i] != 0,
                    "write_zeroes left nonzero data at %d", i);
            }

            /* Misaligned view into the buffer: exercises the bounce path on
             * bdevs with a buffer alignment requirement (correctness holds
             * either way). */
            view        = state->iov;
            view.data   = (char *) state->iov.data + 512;
            view.length = 4096;
            memset(view.data, TEST_PATTERN_B, 4096);
            evpl_block_write(evpl, state->queue, &view, 1, 8192, 0,
                             bdev_step_done, state);
            break;
        case 8:
            view        = state->iov;
            view.data   = (char *) state->iov.data + 512;
            view.length = 4096;
            memset(view.data, 0, 4096);
            evpl_block_read(evpl, state->queue, &view, 1, 8192,
                            bdev_step_done, state);
            break;
        case 9:
            for (int i = 0; i < 4096; i++) {
                evpl_test_abort_if(
                    ((unsigned char *) state->iov.data)[512 + i] !=
                    TEST_PATTERN_B,
                    "misaligned read mismatch at %d", i);
            }

            evpl_iovec_release(evpl, &state->iov);

            evpl_block_close_queue(evpl, state->queue);

            evpl_block_close_device(evpl, state->bdev,
                                    bdev_close_done, state);
            break;
        default:
            evpl_test_abort_if(1, "unexpected step %d", state->step);
    } /* switch */
} /* bdev_step */

static void
bdev_open_done(
    struct evpl              *evpl,
    struct evpl_block_device *bdev,
    int                       status,
    void                     *private_data)
{
    struct bdev_test_state *state = private_data;
    int                     niov;

    evpl_test_abort_if(status || !bdev, "device open failed: %d", status);

    state->bdev = bdev;

    evpl_test_abort_if(evpl_block_size(bdev) != 16384ULL * 4096,
                       "unexpected device size %lu",
                       (unsigned long) evpl_block_size(bdev));

    state->queue = evpl_block_open_queue(evpl, bdev);

    niov = evpl_iovec_alloc(evpl, 8192, 4096, 1, 0, &state->iov);

    evpl_test_abort_if(niov < 1, "iovec alloc failed");

    bdev_step(evpl, state);
} /* bdev_open_done */

static void *
bdev_thread_init(
    struct evpl *evpl,
    void        *private_data)
{
    struct bdev_test_state *state = private_data;

    state->evpl = evpl;

    evpl_block_open_device(evpl, EVPL_BLOCK_PROTOCOL_SPDK_BDEV, "Malloc0",
                           bdev_open_done, state);

    return private_data;
} /* bdev_thread_init */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_thread    *thread;
    struct bdev_test_state state = { 0 };

    evpl_spdk_test_init(2);

    evpl_spdk_bdev_test_up(EVPL_SPDK_BDEV_TEST_MALLOC_JSON);

    evpl_spdk_test_config();

    thread = evpl_thread_create(NULL, bdev_thread_init, NULL, &state);

    while (!state.done) {
        usleep(1000);
    }

    evpl_test_info("bdev op chain completed");

    evpl_thread_destroy(thread);

    evpl_spdk_bdev_test_down();

    return 0;
} /* main */
