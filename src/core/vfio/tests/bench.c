// SPDX-FileCopyrightText: 2025-2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Standalone libevpl VFIO block microbench.
 *
 * Drives 4K (configurable) random reads against ONE VFIO NVMe device from a
 * single thread, through the exact same evpl block/VFIO submit+poll path the
 * chimera daemon uses -- but with no diskfs, NFS, RDMA, or multi-threading.
 * Sweeps queue depth and reports IOPS + latency percentiles per level, to
 * isolate the per-op cost of libevpl's VFIO driving from everything above it.
 *
 * Usage:  vfio_bench <pci-bdf> [seconds-per-level] [block-bytes]
 *   e.g.  vfio_bench 01:00.0 5 4096
 *
 * The device must be VFIO-bound and not in use (stop the chimera daemon first).
 * Pure reads -- does not modify the device.
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <time.h>

#include "evpl/evpl.h"

#define MAX_QD     256
#define NUM_BUCKET 40

struct bench;

struct slot {
    struct bench     *b;
    struct evpl_iovec iov;
    struct timespec   start;
};

struct bench {
    struct evpl             *evpl;
    struct evpl_block_queue *q;
    uint64_t                 nblocks;
    uint32_t                 bsize;
    int                      running;
    int                      outstanding;
    long                     completions;
    uint64_t                 lat_sum_ns;
    uint64_t                 lat_bucket[NUM_BUCKET]; /* log2(ns) */
    unsigned int             seed;
};

static inline uint64_t
ns_since(
    const struct timespec *s,
    const struct timespec *e)
{
    return (uint64_t) (e->tv_sec - s->tv_sec) * 1000000000ULL +
           (e->tv_nsec - s->tv_nsec);
} /* ns_since */

static void bench_issue(
    struct slot *sl);

static void
bench_complete(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    struct slot    *sl = private_data;
    struct bench   *b  = sl->b;
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

    b->lat_sum_ns += lat;
    bk             = 0;
    while ((lat >> bk) > 1 && bk < NUM_BUCKET - 1) {
        bk++;
    }
    b->lat_bucket[bk]++;

    b->completions++;
    b->outstanding--;

    if (b->running) {
        bench_issue(sl);
    }
} /* bench_complete */

static void
bench_issue(struct slot *sl)
{
    struct bench *b = sl->b;
    uint64_t      off;

    off = (uint64_t) (rand_r(&b->seed) % b->nblocks) * b->bsize;

    clock_gettime(CLOCK_MONOTONIC, &sl->start);
    b->outstanding++;
    evpl_block_read(b->evpl, b->q, &sl->iov, 1, off, bench_complete, sl);
} /* bench_issue */

static const char *
us_at_pct(
    const uint64_t *bucket,
    uint64_t        total,
    double          pct,
    char           *buf,
    size_t          buflen)
{
    uint64_t target = (uint64_t) (pct / 100.0 * (double) total);
    uint64_t cum    = 0;
    int      k;

    for (k = 0; k < NUM_BUCKET; k++) {
        cum += bucket[k];
        if (cum >= target) {
            /* bucket k covers [2^k, 2^(k+1)) ns; report the upper bound in us */
            snprintf(buf, buflen, "%.1f", ((double) (1ULL << (k + 1))) / 1000.0);
            return buf;
        }
    }
    snprintf(buf, buflen, "inf");
    return buf;
} /* us_at_pct */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl              *evpl;
    struct evpl_block_device *bdev;
    struct evpl_block_queue  *q;
    struct bench              b;
    static struct slot        slots[MAX_QD];
    uint64_t                  size;
    const char               *bdf;
    int                       seconds, qd, qi, i;
    int                       qds[] = { 1, 4, 16, 32, 64, 128, 256 };
    int                       nqd   = sizeof(qds) / sizeof(qds[0]);
    char                      p50[16], p99[16];

    if (argc < 2) {
        fprintf(stderr, "usage: %s <pci-bdf> [seconds-per-level] [block-bytes]\n", argv[0]);
        return 1;
    }

    bdf     = argv[1];
    seconds = (argc > 2) ? atoi(argv[2]) : 5;

    memset(&b, 0, sizeof(b));
    b.bsize = (argc > 3) ? (uint32_t) atoi(argv[3]) : 4096;
    b.seed  = 0x1234abcd;

    evpl = evpl_create(NULL);

    bdev = evpl_block_open_device(EVPL_BLOCK_PROTOCOL_VFIO, bdf);
    if (!bdev) {
        fprintf(stderr, "failed to open VFIO device %s (bound to vfio-pci? daemon stopped?)\n", bdf);
        return 1;
    }

    q       = evpl_block_open_queue(evpl, bdev);
    size    = evpl_block_size(bdev);
    b.evpl  = evpl;
    b.q     = q;
    b.nblocks = size / b.bsize;

    for (i = 0; i < MAX_QD; i++) {
        slots[i].b = &b;
        evpl_iovec_alloc(evpl, b.bsize, 4096, 1, 0, &slots[i].iov);
    }

    printf("device %s  size %lu GiB  bsize %u  %ds/level\n",
           bdf, size >> 30, b.bsize, seconds);
    printf("%6s %14s %10s %10s %10s %8s\n",
           "QD", "IOPS", "MB/s", "mean_us", "p50_us", "p99_us");

    for (qi = 0; qi < nqd; qi++) {
        struct timespec t0, now;
        double          secs;
        uint64_t        total;

        qd = qds[qi];

        memset(b.lat_bucket, 0, sizeof(b.lat_bucket));
        b.lat_sum_ns  = 0;
        b.completions = 0;
        b.outstanding = 0;
        b.running     = 1;

        clock_gettime(CLOCK_MONOTONIC, &t0);

        for (i = 0; i < qd; i++) {
            bench_issue(&slots[i]);
        }

        do {
            evpl_continue(evpl);
            clock_gettime(CLOCK_MONOTONIC, &now);
        } while (ns_since(&t0, &now) < (uint64_t) seconds * 1000000000ULL);

        b.running = 0;
        while (b.outstanding) {
            evpl_continue(evpl);
        }

        clock_gettime(CLOCK_MONOTONIC, &now);
        secs  = (double) ns_since(&t0, &now) / 1e9;
        total = 0;
        for (i = 0; i < NUM_BUCKET; i++) {
            total += b.lat_bucket[i];
        }

        printf("%6d %14.0f %10.0f %10.1f %10s %8s\n",
               qd,
               b.completions / secs,
               (b.completions / secs) * b.bsize / (1024.0 * 1024.0),
               b.completions ? (double) b.lat_sum_ns / b.completions / 1000.0 : 0.0,
               us_at_pct(b.lat_bucket, total, 50.0, p50, sizeof(p50)),
               us_at_pct(b.lat_bucket, total, 99.0, p99, sizeof(p99)));
        fflush(stdout);
    }

    for (i = 0; i < MAX_QD; i++) {
        evpl_iovec_release(evpl, &slots[i].iov);
    }

    evpl_block_close_queue(evpl, q);
    evpl_block_close_device(bdev);
    evpl_destroy(evpl);

    return 0;
} /* main */
