// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "evpl/evpl.h"

struct test_state {
    struct evpl_block_device *bdev;
    int                       open_status;
    int                       opened;
    int                       closed;
    int                       pending;
};

static void
open_callback(
    struct evpl              *evpl,
    struct evpl_block_device *blockdev,
    int                       status,
    void                     *private_data)
{
    struct test_state *state = private_data;

    state->bdev        = blockdev;
    state->open_status = status;
    state->opened      = 1;
} /* open_callback */

static void
close_callback(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    struct test_state *state = private_data;

    if (status) {
        exit(1);
    }

    state->closed = 1;
} /* close_callback */

static void
io_callback(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    struct test_state *state = private_data;

    if (status) {
        exit(1);
    }

    state->pending--;

} /* io_callback */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl             *evpl;
    int                      fd;
    int                      rc;
    struct evpl_block_queue *bqueue;
    struct test_state        state = { 0 };
    struct evpl_iovec        iov;
    int                      niov;

    fd = open("test.img", O_RDWR | O_CREAT, 0666);
    rc = ftruncate(fd, 1024 * 1024 * 1024);

    if (rc < 0) {
        perror("ftruncate");
        exit(1);
    }

    close(fd);

    evpl = evpl_create(NULL);

    evpl_block_open_device(evpl, EVPL_BLOCK_PROTOCOL_IO_URING, "test.img",
                           open_callback, &state);

    while (!state.opened) {
        evpl_continue(evpl);
    }

    if (state.open_status || !state.bdev) {
        fprintf(stderr, "open failed: %d\n", state.open_status);
        exit(1);
    }

    bqueue = evpl_block_open_queue(evpl, state.bdev);


    niov = evpl_iovec_alloc(evpl, 4096, 4096, 1, 0, &iov);

    state.pending++;
    evpl_block_write(evpl, bqueue, &iov, niov, 0, 0, io_callback, &state);

    state.pending++;
    evpl_block_read(evpl, bqueue, &iov, niov, 0, io_callback, &state);

    state.pending++;
    evpl_block_flush(evpl, bqueue, io_callback, &state);

    while (state.pending) {
        evpl_continue(evpl);
    }

    evpl_iovec_release(evpl, &iov);

    evpl_block_close_queue(evpl, bqueue);

    evpl_block_close_device(evpl, state.bdev, close_callback, &state);

    while (!state.closed) {
        evpl_continue(evpl);
    }

    evpl_destroy(evpl);

    return 0;
} /* main */
