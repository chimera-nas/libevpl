// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "evpl/evpl.h"

struct test_state {
    struct evpl_block_device *bdev;
    int                       open_status;
    int                       opened;
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

int
main(
    int   argc,
    char *argv[])
{
    struct evpl      *evpl;
    struct test_state state = { 0 };
    int               fd;

    fd = open("test.img", O_RDWR | O_CREAT, 0666);

    if (fd < 0) {
        perror("open");
        exit(1);
    }

    close(fd);

    evpl = evpl_create(NULL);

    /* A plain file is not an NVMe namespace: the open must fail, delivered
     * asynchronously with a nonzero status and a NULL device. */
    evpl_block_open_device(evpl, EVPL_BLOCK_PROTOCOL_IO_URING_NVME, "test.img",
                           open_callback, &state);

    while (!state.opened) {
        evpl_continue(evpl);
    }

    if (state.open_status == 0 || state.bdev) {
        fprintf(stderr, "open unexpectedly succeeded\n");
        exit(1);
    }

    evpl_destroy(evpl);

    return 0;
} /* main */
