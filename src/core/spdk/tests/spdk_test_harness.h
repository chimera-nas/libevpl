// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

/*
 * Mini-reactor harness for SPDK guest-mode tests.
 *
 * Production libevpl never pumps spdk_threads -- the host application's
 * reactors do -- so the tests provide the host side themselves: an SPDK env
 * (no hugepages, so it runs in CI containers), the thread library with a
 * round-robin scheduler op, and N pthreads that poll their assigned
 * spdk_threads and reap exited ones.  Test main() stays on a plain pthread,
 * where the blocking forms of evpl_thread_create/evpl_listen/
 * evpl_thread_destroy are safe.
 *
 * Teardown ordering: evpl_spdk_test_init() registers its atexit handler
 * before the test calls evpl_init(), so evpl_cleanup (registered later, run
 * first -- atexit is LIFO) unregisters slab memory while the SPDK env is
 * still alive.
 */

#include <pthread.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>

#include <spdk/env.h>
#include <spdk/thread.h>

#include "core/test_log.h"
#include "evpl/evpl.h"

#define EVPL_SPDK_TEST_MAX_REACTORS 8
#define EVPL_SPDK_TEST_BATCH        256

struct evpl_spdk_test_reactor {
    pthread_t            pthread;
    pthread_mutex_t      lock;
    struct spdk_thread **threads;
    int                  num_threads;
    int                  max_threads;
    volatile int         stop;
};

static struct evpl_spdk_test_reactor
                    evpl_spdk_test_reactors[EVPL_SPDK_TEST_MAX_REACTORS];
static int          evpl_spdk_test_num_reactors;
static unsigned int evpl_spdk_test_rotor;

static int
evpl_spdk_test_new_thread(struct spdk_thread *thread)
{
    struct evpl_spdk_test_reactor *reactor;
    unsigned int                   idx;

    idx = __sync_fetch_and_add(&evpl_spdk_test_rotor, 1);

    reactor = &evpl_spdk_test_reactors[idx % evpl_spdk_test_num_reactors];

    pthread_mutex_lock(&reactor->lock);

    if (reactor->num_threads >= reactor->max_threads) {
        reactor->max_threads = reactor->max_threads ?
            reactor->max_threads * 2 : 8;
        reactor->threads = realloc(reactor->threads,
                                   reactor->max_threads *
                                   sizeof(*reactor->threads));
    }

    reactor->threads[reactor->num_threads++] = thread;

    pthread_mutex_unlock(&reactor->lock);

    return 0;
} /* evpl_spdk_test_new_thread */

static void *
evpl_spdk_test_reactor_fn(void *arg)
{
    struct evpl_spdk_test_reactor *reactor = arg;
    struct spdk_thread            *threads[EVPL_SPDK_TEST_BATCH];
    struct spdk_thread            *thread;
    int                            i, j, n, done, busy;

    for (;;) {
        pthread_mutex_lock(&reactor->lock);

        n = reactor->num_threads;

        if (n > EVPL_SPDK_TEST_BATCH) {
            n = EVPL_SPDK_TEST_BATCH;
        }

        for (i = 0; i < n; i++) {
            threads[i] = reactor->threads[i];
        }

        done = reactor->stop && reactor->num_threads == 0;

        pthread_mutex_unlock(&reactor->lock);

        if (done) {
            break;
        }

        busy = 0;

        for (i = 0; i < n; i++) {
            thread = threads[i];

            /* Poll without holding the lock: pollers and messages may create
             * new spdk_threads, which re-enters the scheduler op. */
            busy |= spdk_thread_poll(thread, 0, 0);

            if (spdk_thread_is_exited(thread)) {
                pthread_mutex_lock(&reactor->lock);

                for (j = 0; j < reactor->num_threads; j++) {
                    if (reactor->threads[j] == thread) {
                        reactor->threads[j] =
                            reactor->threads[--reactor->num_threads];
                        break;
                    }
                }

                pthread_mutex_unlock(&reactor->lock);

                spdk_thread_destroy(thread);
            }
        }

        if (!busy) {
            usleep(100);
        }
    }

    return NULL;
} /* evpl_spdk_test_reactor_fn */

static void
evpl_spdk_test_thread_exit_msg(void *ctx)
{
    spdk_thread_exit(spdk_get_thread());
} /* evpl_spdk_test_thread_exit_msg */

static void
evpl_spdk_test_fini(void)
{
    struct evpl_spdk_test_reactor *reactor;
    int                            i, j;

    /* Ask any threads the test left behind (e.g. bootstrap threads) to exit;
     * evpl worker threads exit themselves during evpl_thread_destroy. */
    for (i = 0; i < evpl_spdk_test_num_reactors; i++) {
        reactor = &evpl_spdk_test_reactors[i];

        pthread_mutex_lock(&reactor->lock);

        for (j = 0; j < reactor->num_threads; j++) {
            if (!spdk_thread_is_exited(reactor->threads[j])) {
                spdk_thread_send_msg(reactor->threads[j],
                                     evpl_spdk_test_thread_exit_msg, NULL);
            }
        }

        pthread_mutex_unlock(&reactor->lock);

        reactor->stop = 1;
    }

    for (i = 0; i < evpl_spdk_test_num_reactors; i++) {
        pthread_join(evpl_spdk_test_reactors[i].pthread, NULL);
        free(evpl_spdk_test_reactors[i].threads);
    }

    spdk_thread_lib_fini();
    spdk_env_fini();
} /* evpl_spdk_test_fini */

static void
evpl_spdk_test_init(int nreactors)
{
    struct spdk_env_opts opts;
    int                  rc, i;

    evpl_test_abort_if(nreactors < 1 ||
                                   nreactors > EVPL_SPDK_TEST_MAX_REACTORS,
                       "invalid reactor count %d", nreactors);

    memset(&opts, 0, sizeof(opts));

    opts.opts_size = sizeof(opts);

    spdk_env_opts_init(&opts);

    opts.name = "evpl_spdk_test";

    /* No hugepages so the suite runs in unprivileged CI containers; evpl
     * slabs are external memory, so DPDK only backs SPDK internals.  512MB
     * leaves room for the iobuf subsystem's default pools (~200MB), which
     * the bdev tests initialize. */
    opts.no_huge  = true;
    opts.mem_size = 512;

    rc = spdk_env_init(&opts);

    evpl_test_abort_if(rc, "spdk_env_init failed: %d", rc);

    rc = spdk_thread_lib_init(evpl_spdk_test_new_thread, 0);

    evpl_test_abort_if(rc, "spdk_thread_lib_init failed: %d", rc);

    evpl_spdk_test_num_reactors = nreactors;

    for (i = 0; i < nreactors; i++) {
        pthread_mutex_init(&evpl_spdk_test_reactors[i].lock, NULL);

        rc = pthread_create(&evpl_spdk_test_reactors[i].pthread, NULL,
                            evpl_spdk_test_reactor_fn,
                            &evpl_spdk_test_reactors[i]);

        evpl_test_abort_if(rc, "reactor pthread_create failed: %d", rc);
    }

    /* Before any evpl call, so evpl_cleanup's atexit runs first (LIFO). */
    atexit(evpl_spdk_test_fini);
} /* evpl_spdk_test_init */

static void
evpl_spdk_test_config(void)
{
    struct evpl_global_config *config = evpl_global_config_init();

    evpl_global_config_set_core_mech(config, EVPL_CORE_MECH_SPDK);

    evpl_init(config);
} /* evpl_spdk_test_config */
