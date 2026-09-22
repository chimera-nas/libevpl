// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <stdatomic.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include "evpl/evpl.h"
#include "tests/test_common.h"
#include "lifecycle_cases.h"

static atomic_int              ready, stopped, completed;
static struct evpl_thread     *thread;
static struct evpl_threadpool *pool;
static int                     pending, created;

static void *
worker_ready(
    struct evpl *evpl,
    void        *arg)
{
    (void) arg;
    atomic_fetch_add(&ready, 1);
    return evpl;
} /* worker_ready */
static void
worker_stopped(
    struct evpl *evpl,
    void        *arg)
{
    evpl_test_abort_if(evpl != arg, "shutdown before readiness or wrong worker context");
    atomic_fetch_add(&stopped, 1);
} /* worker_stopped */
static void done(void *arg) { (void) arg; atomic_fetch_add(&completed, 1); }

static void
barrier(
    int r,
    int s,
    int c)
{
    struct timespec pause = { 0, 1000000 };
    int             i;

    for (i = 0; i < 5000; i++) {
        if (atomic_load(&ready) == r && atomic_load(&stopped) == s && atomic_load(&completed) == c) {
            break;
        }
        nanosleep(&pause, NULL);
    }
    evpl_test_abort_if(i == 5000, "lifecycle: got %d/%d/%d expected %d/%d/%d",
                       atomic_load(&ready), atomic_load(&stopped), atomic_load(&completed), r, s, c);
} /* barrier */
static void
cleanup(void)
{
    if (thread) {
        evpl_thread_destroy(thread);
    }
    if (pool) {
        evpl_threadpool_destroy(pool);
    }
    thread = NULL; pool = NULL;
    barrier(created, created, pending);
} /* cleanup */
int
main(void)
{
    test_evpl_config();
    for (size_t i = 0; i < sizeof(lifecycle_steps) / sizeof(lifecycle_steps[0]); i++) {
        const struct lifecycle_step *s = &lifecycle_steps[i];
        if (s->op != lifecycle_Reset) {
            created = s->created;
        }
        switch (s->op) {
            case lifecycle_Reset:
                cleanup(); ready = stopped = completed = 0; pending = created = 0; break;
            case lifecycle_Thread:
                thread = evpl_thread_create(NULL, worker_ready, worker_stopped, NULL); break;
            case lifecycle_ThreadAsync:
                thread = evpl_thread_create_async(NULL, worker_ready, worker_stopped, NULL); break;
            case lifecycle_EmptyPool:
            case lifecycle_Pool:
                pool = evpl_threadpool_create(NULL, s->live, worker_ready, worker_stopped, NULL); break;
            case lifecycle_Stop:
                if (thread) {
                    evpl_thread_destroy(thread);
                }
                if (pool) {
                    evpl_threadpool_destroy(pool);
                }
                thread = NULL; pool = NULL; break;
            case lifecycle_StopAsync:
                pending++;
                if (thread) {
                    evpl_thread_destroy_async(thread, done, NULL);
                }
                if (pool) {
                    evpl_threadpool_destroy_async(pool, done, NULL);
                }
                thread = NULL; pool = NULL; break;
            case lifecycle_Quiesce: barrier(s->ready, s->stopped, s->completions); break;
            default: abort();
        } /* switch */
    }
    cleanup();
    printf("lifecycle model: %zu transitions passed\n", sizeof(lifecycle_steps) / sizeof(lifecycle_steps[0]));
    return 0;
} /* main */
