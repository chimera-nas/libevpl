// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "evpl/evpl.h"

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_block_device *bdev;
    int                       fd;

    fd = open("test.img", O_RDWR | O_CREAT, 0666);

    if (fd < 0) {
        perror("open");
        exit(1);
    }

    close(fd);

    bdev = evpl_block_open_device(EVPL_BLOCK_PROTOCOL_IO_URING_NVME, "test.img");

    if (bdev) {
        evpl_block_close_device(bdev);
        exit(1);
    }

    return 0;
} /* main */
