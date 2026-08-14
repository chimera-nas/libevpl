// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Stage more block writes in one event-loop iteration than the aio ring holds.
 *
 * Deferrals only arm; the flush callback does not run until the current
 * callback chain returns.  Every write issued in the loop below is therefore
 * staged before a single io_submit() happens, so the staging array must absorb
 * the whole burst regardless of the ring depth.  Callers reach this shape
 * routinely -- diskfs' tail pusher gates its home writes per device, so its
 * total in-flight budget is (per-device cap x device count), well above the
 * ring -- and a full staging array is ordinary backpressure, not an error.
 *
 * The ring is deliberately set far smaller than the burst so submission is
 * forced to make partial progress and drain via completions.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <fcntl.h>

#include "evpl/evpl.h"
#include "evpl/evpl_config.h"

#define BURST_RING   32     /* aio ring depth (io_setup nr_events) */
#define BURST_WRITES 512    /* iocbs staged before anything submits */

static void
write_callback(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    int *pending = private_data;

    (void) evpl;

    if (status) {
        fprintf(stderr, "burst write failed: %d\n", status);
        exit(1);
    }

    (*pending)--;

} /* write_callback */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_global_config *config;
    struct evpl               *evpl;
    struct evpl_block_device  *bdev;
    struct evpl_block_queue   *bqueue;
    struct evpl_iovec          iov;
    int                        fd, rc, i, niov;
    int                        pending = 0;

    (void) argc;
    (void) argv;

    fd = open("burst.img", O_RDWR | O_CREAT, 0666);

    if (fd < 0) {
        perror("open");
        exit(1);
    }

    rc = ftruncate(fd, (off_t) BURST_WRITES * 4096);

    if (rc < 0) {
        perror("ftruncate");
        exit(1);
    }

    close(fd);

    config = evpl_global_config_init();

    evpl_global_config_set_libaio_max_pending(config, BURST_RING);

    evpl_init(config);

    evpl = evpl_create(NULL);

    bdev = evpl_block_open_device(EVPL_BLOCK_PROTOCOL_LIBAIO, "burst.img");

    if (!bdev) {
        fprintf(stderr, "failed to open burst.img\n");
        exit(1);
    }

    bqueue = evpl_block_open_queue(evpl, bdev);

    niov = evpl_iovec_alloc(evpl, 4096, 4096, 1, 0, &iov);

    /* No evpl_continue() in this loop: nothing submits or completes until it
     * returns, so all BURST_WRITES iocbs pile into the staging array at once. */
    for (i = 0; i < BURST_WRITES; i++) {
        pending++;
        evpl_block_write(evpl, bqueue, &iov, niov, (uint64_t) i * 4096, 0,
                         write_callback, &pending);
    }

    while (pending) {
        evpl_continue(evpl);
    }

    evpl_iovec_release(evpl, &iov);

    evpl_block_close_queue(evpl, bqueue);

    evpl_block_close_device(bdev);

    evpl_destroy(evpl);

    unlink("burst.img");

    return 0;
} /* main */
