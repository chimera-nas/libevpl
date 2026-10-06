// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only
//
// Managed SPDK env/reactor mode: when config->spdk_managed is set, libevpl
// initializes the SPDK env and thread library itself and drives each created
// spdk_thread from a dedicated reactor pthread pinned to that thread's cpumask.
// This mirrors the host bootstrap that SPDK applications otherwise provide, so
// a plain evpl consumer can use EVPL_CORE_MECH_SPDK with no SPDK boilerplate.

#define _GNU_SOURCE
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <spdk/env.h>
#include <spdk/thread.h>
#include <spdk/cpuset.h>

#include "core/evpl.h"
#include "core/logging.h"
#include "core/spdk/spdk_managed.h"

#define EVPL_SPDK_MANAGED_MAX_REACTORS 512

struct evpl_spdk_managed_reactor {
    pthread_t           pthread;
    struct spdk_thread *thread;
    volatile int        stop;
};

static int                              evpl_spdk_managed_active;
static char                             evpl_spdk_managed_core_mask[32];
static struct evpl_spdk_managed_reactor evpl_spdk_managed_reactors[
    EVPL_SPDK_MANAGED_MAX_REACTORS];
static int                              evpl_spdk_managed_num_reactors;
static pthread_mutex_t                  evpl_spdk_managed_lock =
    PTHREAD_MUTEX_INITIALIZER;

static void *
evpl_spdk_managed_reactor_fn(void *arg)
{
    struct evpl_spdk_managed_reactor *reactor = arg;
    struct spdk_cpuset               *cpumask;
    cpu_set_t                         set;
    int                               i, busy;

    /* Pin to the thread's configured cpumask (from thread_config cpumask), so
     * the worker runs where the caller asked. */
    cpumask = spdk_thread_get_cpumask(reactor->thread);
    if (cpumask) {
        CPU_ZERO(&set);
        for (i = 0; i < CPU_SETSIZE; i++) {
            if (spdk_cpuset_get_cpu(cpumask, i)) {
                CPU_SET(i, &set);
            }
        }
        if (CPU_COUNT(&set) > 0) {
            pthread_setaffinity_np(pthread_self(), sizeof(set), &set);
        }
    }

    /* Poll this spdk_thread until it exits (evpl_thread_destroy drives the
     * exit). Pollers or messages may create further spdk_threads, which
     * re-enter the scheduler op and spawn their own reactors. */
    while (!spdk_thread_is_exited(reactor->thread)) {
        busy = spdk_thread_poll(reactor->thread, 0, 0);
        if (!busy) {
            usleep(50);
        }
    }

    spdk_thread_destroy(reactor->thread);
    return NULL;
} /* evpl_spdk_managed_reactor_fn */

static int
evpl_spdk_managed_new_thread(struct spdk_thread *thread)
{
    struct evpl_spdk_managed_reactor *reactor;
    int                               rc;

    pthread_mutex_lock(&evpl_spdk_managed_lock);

    evpl_core_abort_if(evpl_spdk_managed_num_reactors >=
                       EVPL_SPDK_MANAGED_MAX_REACTORS,
                       "evpl managed SPDK: too many reactors (%d)",
                       evpl_spdk_managed_num_reactors);

    reactor         = &evpl_spdk_managed_reactors[evpl_spdk_managed_num_reactors];
    reactor->thread = thread;
    reactor->stop   = 0;

    rc = pthread_create(&reactor->pthread, NULL,
                        evpl_spdk_managed_reactor_fn, reactor);

    evpl_core_abort_if(rc, "evpl managed SPDK: reactor pthread_create failed: %d",
                       rc);

    evpl_spdk_managed_num_reactors++;

    pthread_mutex_unlock(&evpl_spdk_managed_lock);
    return 0;
} /* evpl_spdk_managed_new_thread */

static int
evpl_spdk_managed_thread_op(
    struct spdk_thread *thread,
    enum spdk_thread_op op)
{
    return op == SPDK_THREAD_OP_NEW ? evpl_spdk_managed_new_thread(thread) : 0;
} /* evpl_spdk_managed_thread_op */

static bool
evpl_spdk_managed_thread_op_supported(enum spdk_thread_op op)
{
    return op == SPDK_THREAD_OP_NEW || op == SPDK_THREAD_OP_RESCHED;
} /* evpl_spdk_managed_thread_op_supported */

void
evpl_spdk_managed_init(struct evpl_global_config *config)
{
    struct spdk_env_opts opts;
    int                  rc;

    if (evpl_spdk_managed_active) {
        return;
    }

    /* Defer to a host that already owns the SPDK env (e.g. an application
     * driving its own reactor, or the test harness): do not double-init it and
     * do not tear it down.  managed_active stays 0 so fini() is a no-op. */
    if (spdk_env_get_core_count() > 0) {
        return;
    }

    memset(&opts, 0, sizeof(opts));
    opts.opts_size = sizeof(opts);
    spdk_env_opts_init(&opts);
    opts.name = "evpl";
    /* No hugepages: run in ordinary (even unprivileged) containers. SPDK only
     * backs its own internals from this pool; evpl slabs are external. */
    opts.no_huge  = true;
    opts.mem_size = 512;

    /* DPDK's default core mask is 0x1 (CPU 0). When the process is confined to
     * a cpuset that excludes CPU 0 (e.g. a pinned benchmark container), EAL
     * fails with "Cannot set affinity". Place the EAL main lcore on the first
     * CPU actually allowed to this process. */
    {
        cpu_set_t allowed;
        CPU_ZERO(&allowed);
        if (sched_getaffinity(0, sizeof(allowed), &allowed) == 0) {
            int cpu;
            for (cpu = 0; cpu < CPU_SETSIZE; cpu++) {
                if (CPU_ISSET(cpu, &allowed)) {
                    snprintf(evpl_spdk_managed_core_mask,
                             sizeof(evpl_spdk_managed_core_mask), "[%d]", cpu);
                    opts.core_mask = evpl_spdk_managed_core_mask;
                    break;
                }
            }
        }
    }

    rc = spdk_env_init(&opts);
    evpl_core_abort_if(rc, "evpl managed SPDK: spdk_env_init failed: %d", rc);

    rc = spdk_thread_lib_init_ext(evpl_spdk_managed_thread_op,
                                  evpl_spdk_managed_thread_op_supported,
                                  0, SPDK_DEFAULT_MSG_MEMPOOL_SIZE);
    evpl_core_abort_if(rc, "evpl managed SPDK: spdk_thread_lib_init failed: %d",
                       rc);

    evpl_spdk_managed_active = 1;
} /* evpl_spdk_managed_init */

void
evpl_spdk_managed_fini(void)
{
    int i;

    if (!evpl_spdk_managed_active) {
        return;
    }

    /* Worker spdk_threads have already exited (evpl_cleanup runs only once all
     * evpl contexts are destroyed), so each reactor pthread has returned or is
     * about to. Signal and join them, then release the env we own. */
    for (i = 0; i < evpl_spdk_managed_num_reactors; i++) {
        evpl_spdk_managed_reactors[i].stop = 1;
    }
    for (i = 0; i < evpl_spdk_managed_num_reactors; i++) {
        pthread_join(evpl_spdk_managed_reactors[i].pthread, NULL);
    }
    evpl_spdk_managed_num_reactors = 0;

    spdk_thread_lib_fini();
    spdk_env_fini();

    evpl_spdk_managed_active = 0;
} /* evpl_spdk_managed_fini */

int
evpl_spdk_managed_is_active(void)
{
    return evpl_spdk_managed_active;
} /* evpl_spdk_managed_is_active */
