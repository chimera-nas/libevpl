// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

#include "evpl/evpl.h"

static void
read_callback(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    int *pending = private_data;

    if (status) {
        exit(1);
    }

    (*pending)--;

} /* read_callback */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl              *evpl;
    struct evpl_block_device *bdev;
    int                       fd;
    int                       rc;
    struct evpl_block_queue  *bqueue;
    int                       pending = 0;
    struct evpl_iovec         iov;
    int                       niov;

    fd = open("test.img", O_RDWR | O_CREAT, 0666);
    rc = ftruncate(fd, 1024 * 1024 * 1024);

    if (rc < 0) {
        perror("ftruncate");
        exit(1);
    }

    close(fd);

    evpl = evpl_create(NULL);

    bdev = evpl_block_open_device(EVPL_BLOCK_PROTOCOL_IO_URING, "test.img");

    bqueue = evpl_block_open_queue(evpl, bdev);


    niov = evpl_iovec_alloc(evpl, 4096, 4096, 1, &iov);

    pending++;
    evpl_block_write(evpl, bqueue, &iov, niov, 0, 0, read_callback, &pending);

    pending++;
    evpl_block_read(evpl, bqueue, &iov, niov, 0, read_callback, &pending);

    pending++;
    evpl_block_flush(evpl, bqueue, read_callback, &pending);

    while (pending) {
        evpl_continue(evpl);
    }

    evpl_iovec_release(&iov);

    evpl_block_close_queue(evpl, bqueue);

    evpl_block_close_device(bdev);

    evpl_destroy(evpl);

    return 0;
} /* main */