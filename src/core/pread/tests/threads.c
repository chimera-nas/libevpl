// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * One device, several evpl threads.
 *
 * The pread backend funnels every queue into a single per-device service
 * thread and hands each completion back to the thread that issued it, so what
 * matters here is that the routing is right: each worker owns a disjoint
 * region and a pattern derived from its own index, and verifies its reads
 * against it.  A completion delivered to the wrong thread, or a request
 * serviced against the wrong queue, shows up as a pattern mismatch rather
 * than as a hang.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "core/test_log.h"
#include "evpl/evpl.h"
#include "tests/test_common.h"

#define DEVICE_PATH "pread_threads.img"
#define DEVICE_SIZE (16 * 1024 * 1024)
#define NUM_WORKERS 4
#define CHUNK       (64 * 1024)
#define NUM_ROUNDS  16
#define REGION      (NUM_ROUNDS * CHUNK)

struct shared_state {
    struct evpl_block_device *bdev;
    int                       next_index;
    int                       finished;
};

struct worker {
    struct shared_state     *shared;
    struct evpl_block_queue *queue;
    struct evpl_iovec        wiov;
    struct evpl_iovec        riov;
    uint64_t                 base;
    int                      index;
    int                      round;
    int                      reading;
};

static char
worker_pattern(
    int index,
    int round)
{
    return (char) (index * 37 + round * 11 + 1);
} /* worker_pattern */

static void
worker_issue(
    struct evpl   *evpl,
    struct worker *w);

static void
worker_callback(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    struct worker       *w     = private_data;
    const unsigned char *bytes = w->riov.data;
    unsigned char        expect;

    evpl_test_abort_if(status, "worker %d round %d failed: %d",
                       w->index, w->round, status);

    if (!w->reading) {
        w->reading = 1;

        memset(w->riov.data, 0, CHUNK);

        evpl_block_read(evpl, w->queue, &w->riov, 1,
                        w->base + (uint64_t) w->round * CHUNK,
                        worker_callback, w);
        return;
    }

    expect = (unsigned char) worker_pattern(w->index, w->round);

    evpl_test_abort_if(memcmp(w->riov.data, w->wiov.data, CHUNK),
                       "worker %d round %d read back 0x%02x, expected 0x%02x",
                       w->index, w->round, bytes[0], expect);

    w->round++;
    w->reading = 0;

    if (w->round == NUM_ROUNDS) {
        __atomic_add_fetch(&w->shared->finished, 1, __ATOMIC_RELEASE);
        return;
    }

    worker_issue(evpl, w);
} /* worker_callback */

static void
worker_issue(
    struct evpl   *evpl,
    struct worker *w)
{
    memset(w->wiov.data, worker_pattern(w->index, w->round), CHUNK);

    evpl_block_write(evpl, w->queue, &w->wiov, 1,
                     w->base + (uint64_t) w->round * CHUNK, 0,
                     worker_callback, w);
} /* worker_issue */

static void *
worker_init(
    struct evpl *evpl,
    void        *private_data)
{
    struct shared_state *shared = private_data;
    struct worker       *w;

    w = calloc(1, sizeof(*w));

    w->shared = shared;
    w->index  = __atomic_fetch_add(&shared->next_index, 1, __ATOMIC_RELAXED);
    w->base   = (uint64_t) w->index * REGION;
    w->queue  = evpl_block_open_queue(evpl, shared->bdev);

    evpl_iovec_alloc(evpl, CHUNK, 4096, 1, 0, &w->wiov);
    evpl_iovec_alloc(evpl, CHUNK, 4096, 1, 0, &w->riov);

    worker_issue(evpl, w);

    return w;
} /* worker_init */

static void
worker_shutdown(
    struct evpl *evpl,
    void        *private_data)
{
    struct worker *w = private_data;

    evpl_test_abort_if(w->round != NUM_ROUNDS,
                       "worker %d shut down after %d of %d rounds",
                       w->index, w->round, NUM_ROUNDS);

    evpl_iovec_release(evpl, &w->wiov);
    evpl_iovec_release(evpl, &w->riov);

    evpl_block_close_queue(evpl, w->queue);

    free(w);
} /* worker_shutdown */

int
main(
    int   argc,
    char *argv[])
{
    struct shared_state     shared;
    struct evpl_threadpool *pool;
    int                     fd, rc;

    test_evpl_config();

    fd = open(DEVICE_PATH, O_RDWR | O_CREAT | O_TRUNC, 0644);

    evpl_test_abort_if(fd < 0, "failed to create " DEVICE_PATH);

    rc = ftruncate(fd, DEVICE_SIZE);

    evpl_test_abort_if(rc < 0, "failed to size " DEVICE_PATH);

    close(fd);

    memset(&shared, 0, sizeof(shared));

    shared.bdev = evpl_block_open_device(EVPL_BLOCK_PROTOCOL_PREAD,
                                         DEVICE_PATH);

    evpl_test_abort_if(!shared.bdev, "failed to open pread device");

    pool = evpl_threadpool_create(NULL, NUM_WORKERS, worker_init,
                                  worker_shutdown, &shared);

    /* The workers drive themselves from their own completions; wait for the
     * last one rather than for any particular amount of time.  A worker that
     * never completes hangs here and is caught by the ctest timeout. */
    while (__atomic_load_n(&shared.finished, __ATOMIC_ACQUIRE) < NUM_WORKERS) {
        usleep(1000);
    }

    evpl_threadpool_destroy(pool);

    evpl_block_close_device(shared.bdev);

    unlink(DEVICE_PATH);

    return 0;
} /* main */
