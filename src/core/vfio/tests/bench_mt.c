// SPDX-FileCopyrightText: 2025-2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Multi-thread, all-drives libevpl VFIO block microbench.
 *
 * Mirrors chimera's ideal data-path shape: N worker threads, each with its own
 * evpl loop and its own queue on EVERY drive, issuing 4K random reads striped
 * across all drives at a fixed per-thread queue depth.  No diskfs/NFS/RDMA --
 * just the raw evpl block/VFIO path under chimera-like fan-out, to confirm the
 * hardware + libevpl can sustain the aggregate IOPS we expect.
 *
 * Usage:  vfio_bench_mt <seconds> <qd-per-thread> <threads> <bdf> [bdf ...]
 *   e.g.  vfio_bench_mt 5 16 16 01:00.0 03:00.0 ... c7:00.0
 *
 * Devices must be VFIO-bound and free (stop the chimera daemon first).
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>
#include <pthread.h>

#include "evpl/evpl.h"

#define MAX_DEV    64
#define MAX_QD     512
#define NUM_BUCKET 40

static int                       g_ndev;
static struct evpl_block_device *g_dev[MAX_DEV];
static uint64_t                  g_nblocks[MAX_DEV];
static uint32_t                  g_bsize  = 4096;
static int                       g_seconds;
static int                       g_qd;

struct worker;

struct slot {
    struct worker    *w;
    struct evpl_iovec iov;
    struct timespec   start;
};

struct worker {
    pthread_t                tid;
    int                      id;
    struct evpl             *evpl;
    struct evpl_block_queue *q[MAX_DEV];
    struct slot              slots[MAX_QD];
    int                      running;
    int                      outstanding;
    long                     completions;
    uint64_t                 lat_sum_ns;
    uint64_t                 lat_bucket[NUM_BUCKET];
    unsigned int             seed;
    double                   secs;
};

static inline uint64_t
ns_since(
    const struct timespec *s,
    const struct timespec *e)
{
    return (uint64_t) (e->tv_sec - s->tv_sec) * 1000000000ULL +
           (e->tv_nsec - s->tv_nsec);
} /* ns_since */

static void w_issue(
    struct slot *sl);

static void
w_complete(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    struct slot    *sl = private_data;
    struct worker  *w  = sl->w;
    struct timespec now;
    uint64_t        lat;
    int             bk;

    (void) evpl;

    if (status) {
        fprintf(stderr, "read error status=%d\n", status);
        exit(1);
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    lat = ns_since(&sl->start, &now);

    w->lat_sum_ns += lat;
    bk             = 0;
    while ((lat >> bk) > 1 && bk < NUM_BUCKET - 1) {
        bk++;
    }
    w->lat_bucket[bk]++;
    w->completions++;
    w->outstanding--;

    if (w->running) {
        w_issue(sl);
    }
} /* w_complete */

static void
w_issue(struct slot *sl)
{
    struct worker *w = sl->w;
    int            d = rand_r(&w->seed) % g_ndev;
    uint64_t       off;

    off = (uint64_t) (rand_r(&w->seed) % g_nblocks[d]) * g_bsize;

    clock_gettime(CLOCK_MONOTONIC, &sl->start);
    w->outstanding++;
    evpl_block_read(w->evpl, w->q[d], &sl->iov, 1, off, w_complete, sl);
} /* w_issue */

static void *
worker_main(void *arg)
{
    struct worker  *w = arg;
    struct timespec t0, now;
    int             d, i;

    w->evpl = evpl_create(NULL);

    for (d = 0; d < g_ndev; d++) {
        w->q[d] = evpl_block_open_queue(w->evpl, g_dev[d]);
    }

    for (i = 0; i < g_qd; i++) {
        w->slots[i].w = w;
        evpl_iovec_alloc(w->evpl, g_bsize, 4096, 1, 0, &w->slots[i].iov);
    }

    w->running = 1;
    clock_gettime(CLOCK_MONOTONIC, &t0);

    for (i = 0; i < g_qd; i++) {
        w_issue(&w->slots[i]);
    }

    do {
        evpl_continue(w->evpl);
        clock_gettime(CLOCK_MONOTONIC, &now);
    } while (ns_since(&t0, &now) < (uint64_t) g_seconds * 1000000000ULL);

    w->running = 0;
    while (w->outstanding) {
        evpl_continue(w->evpl);
    }

    clock_gettime(CLOCK_MONOTONIC, &now);
    w->secs = (double) ns_since(&t0, &now) / 1e9;

    return NULL;
} /* worker_main */

int
main(
    int   argc,
    char *argv[])
{
    struct worker *workers;
    int            nthreads, t, i;
    double         agg_iops = 0.0;
    long           agg_compl = 0;
    uint64_t       agg_lat_sum = 0, agg_bucket[NUM_BUCKET], total = 0, cum;
    char           p50[16] = "", p99[16] = "";

    if (argc < 5) {
        fprintf(stderr, "usage: %s <seconds> <qd-per-thread> <threads> <bdf> [bdf ...]\n", argv[0]);
        return 1;
    }

    g_seconds = atoi(argv[1]);
    g_qd      = atoi(argv[2]);
    nthreads  = atoi(argv[3]);
    g_ndev    = argc - 4;

    if (g_qd > MAX_QD || g_ndev > MAX_DEV) {
        fprintf(stderr, "qd<=%d, ndev<=%d\n", MAX_QD, MAX_DEV);
        return 1;
    }

    for (i = 0; i < g_ndev; i++) {
        g_dev[i] = evpl_block_open_device(EVPL_BLOCK_PROTOCOL_VFIO, argv[4 + i]);
        if (!g_dev[i]) {
            fprintf(stderr, "failed to open VFIO device %s\n", argv[4 + i]);
            return 1;
        }
        g_nblocks[i] = evpl_block_size(g_dev[i]) / g_bsize;
    }

    printf("threads=%d qd/thread=%d devices=%d bsize=%u %ds  (total offered = %d)\n",
           nthreads, g_qd, g_ndev, g_bsize, g_seconds, nthreads * g_qd);

    workers = calloc(nthreads, sizeof(*workers));

    for (t = 0; t < nthreads; t++) {
        workers[t].id   = t;
        workers[t].seed = 0x1000 + t * 2654435761u;
        pthread_create(&workers[t].tid, NULL, worker_main, &workers[t]);
    }

    memset(agg_bucket, 0, sizeof(agg_bucket));
    for (t = 0; t < nthreads; t++) {
        pthread_join(workers[t].tid, NULL);
        agg_iops    += workers[t].completions / workers[t].secs;
        agg_compl   += workers[t].completions;
        agg_lat_sum += workers[t].lat_sum_ns;
        for (i = 0; i < NUM_BUCKET; i++) {
            agg_bucket[i] += workers[t].lat_bucket[i];
        }
    }

    for (i = 0; i < NUM_BUCKET; i++) {
        total += agg_bucket[i];
    }
    cum = 0;
    for (i = 0; i < NUM_BUCKET; i++) {
        cum += agg_bucket[i];
        if (!p50[0] && cum >= total / 2) {
            snprintf(p50, sizeof(p50), "%.1f", (double) (1ULL << (i + 1)) / 1000.0);
        }
        if (!p99[0] && cum >= total * 99 / 100) {
            snprintf(p99, sizeof(p99), "%.1f", (double) (1ULL << (i + 1)) / 1000.0);
            break;
        }
    }

    printf("\nAGGREGATE: %.0f IOPS   %.0f MB/s   mean %.1fus   p50 %sus   p99 %sus\n",
           agg_iops,
           agg_iops * g_bsize / (1024.0 * 1024.0),
           agg_compl ? (double) agg_lat_sum / agg_compl / 1000.0 : 0.0,
           p50, p99);
    printf("per-drive: %.0f IOPS   effective QD/drive ~%.1f\n",
           agg_iops / g_ndev,
           (agg_compl ? (double) agg_lat_sum / agg_compl / 1e9 : 0.0) * agg_iops / g_ndev);

    return 0;
} /* main */
