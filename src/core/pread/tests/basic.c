// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Round-trip the pread block backend on a single thread: sized correctly,
 * writes land where they were addressed, reads bring back what was written,
 * and the core's write_zeroes emulation reaches the device.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "core/test_log.h"
#include "evpl/evpl.h"
#include "tests/test_common.h"

#define DEVICE_PATH "pread_basic.img"
#define DEVICE_SIZE (16 * 1024 * 1024)
#define CHUNK       4096
#define TEST_OFFSET (1024 * 1024)

static void
block_callback(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    int *pending = private_data;

    evpl_test_abort_if(status, "block operation failed: %d", status);

    (*pending)--;
} /* block_callback */

static void
run_until_idle(
    struct evpl *evpl,
    int         *pending)
{
    while (*pending) {
        evpl_continue(evpl);
    }
} /* run_until_idle */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl              *evpl;
    struct evpl_block_device *bdev;
    struct evpl_block_queue  *queue;
    struct evpl_iovec         wiov[2], riov[2];
    int                       fd, rc, i, pending = 0;

    test_evpl_config();

    fd = open(DEVICE_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);

    evpl_test_abort_if(fd < 0, "failed to create " DEVICE_PATH);

    rc = ftruncate(fd, DEVICE_SIZE);

    evpl_test_abort_if(rc < 0, "failed to size " DEVICE_PATH);

    close(fd);

    evpl = evpl_create(NULL);

    bdev = evpl_block_open_device(EVPL_BLOCK_PROTOCOL_PREAD, DEVICE_PATH);

    evpl_test_abort_if(!bdev, "failed to open pread device");

    evpl_test_abort_if(evpl_block_size(bdev) != DEVICE_SIZE,
                       "device size %lu, expected %u",
                       evpl_block_size(bdev), DEVICE_SIZE);

    evpl_test_abort_if(evpl_block_max_request_size(bdev) == 0,
                       "device reports a zero maximum request size");

    queue = evpl_block_open_queue(evpl, bdev);

    /* Two segments, each with its own byte pattern, so a backend that lost
     * track of where one iovec ended and the next began would be caught.
     */
    for (i = 0; i < 2; i++) {
        evpl_iovec_alloc(evpl, CHUNK, 4096, 1, 0, &wiov[i]);
        memset(wiov[i].data, 'a' + i, CHUNK);

        evpl_iovec_alloc(evpl, CHUNK, 4096, 1, 0, &riov[i]);
        memset(riov[i].data, 0, CHUNK);
    }

    pending++;
    evpl_block_write(evpl, queue, wiov, 2, TEST_OFFSET, 1,
                     block_callback, &pending);

    run_until_idle(evpl, &pending);

    pending++;
    evpl_block_flush(evpl, queue, block_callback, &pending);

    run_until_idle(evpl, &pending);

    pending++;
    evpl_block_read(evpl, queue, riov, 2, TEST_OFFSET,
                    block_callback, &pending);

    run_until_idle(evpl, &pending);

    for (i = 0; i < 2; i++) {
        evpl_test_abort_if(memcmp(riov[i].data, wiov[i].data, CHUNK),
                           "segment %d did not read back what was written", i);
    }

    /* Emulated in the core as ordinary writes, so this also proves the
     * backend handles a chain of requests issued from its own callbacks. */
    pending++;
    evpl_block_write_zeroes(evpl, queue, TEST_OFFSET, 2 * CHUNK,
                            block_callback, &pending);

    run_until_idle(evpl, &pending);

    pending++;
    evpl_block_read(evpl, queue, riov, 2, TEST_OFFSET,
                    block_callback, &pending);

    run_until_idle(evpl, &pending);

    for (i = 0; i < 2; i++) {
        const char *bytes = riov[i].data;

        evpl_test_abort_if(bytes[0] != 0 ||
                           memcmp(bytes, bytes + 1, CHUNK - 1),
                           "segment %d was not zeroed", i);
    }

    /* No native discard here, so the core answers it as a successful no-op. */
    pending++;
    evpl_block_discard(evpl, queue, TEST_OFFSET, 2 * CHUNK,
                       block_callback, &pending);

    run_until_idle(evpl, &pending);

    for (i = 0; i < 2; i++) {
        evpl_iovec_release(evpl, &wiov[i]);
        evpl_iovec_release(evpl, &riov[i]);
    }

    evpl_block_close_queue(evpl, queue);
    evpl_block_close_device(bdev);
    evpl_destroy(evpl);

    unlink(DEVICE_PATH);

    return 0;
} /* main */
