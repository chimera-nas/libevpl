// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include <pthread.h>
#include <stdatomic.h>
#include <unistd.h>
#include <spdk/env.h>
#include <spdk/thread.h>
#include "core/test_log.h"
#include "evpl/evpl.h"

static struct spdk_thread *host;
static struct evpl        *guest;
static struct evpl_iovec   buffer;
static atomic_int          phase;

static void
attach(void *arg)
{
    struct evpl_thread_config *config = evpl_thread_config_init();

    evpl_thread_config_set_core_mech(config, EVPL_CORE_MECH_SPDK);
    guest = evpl_create(config);
    evpl_test_abort_if(evpl_iovec_alloc(guest, 4096, 4096, 1, 0, &buffer) != 1,
                       "buffer allocation failed");
} /* attach */

static void
detached(void *arg)
{
    spdk_thread_exit(host);
} /* detached */

static void
release(void *arg)
{
    struct evpl_iovec clone;

    evpl_iovec_clone(&clone, &buffer);
    evpl_iovec_release(guest, &clone);
    evpl_iovec_release(guest, &buffer);
    evpl_destroy_async(guest, detached, NULL);
} /* release */

static void *
first(void *arg)
{
    while (!guest) {
        spdk_thread_poll(host, 0, 0);
    }
    /* Transfer only after polling returns. Keep this pthread alive so its
     * identity cannot be recycled for the second executor. */
    atomic_store(&phase, 1);
    while (atomic_load(&phase) != 2) {
        usleep(100);
    }
    return NULL;
} /* first */

static void *
second(void *arg)
{
    while (!atomic_load(&phase)) {
        usleep(100);
    }
    spdk_thread_send_msg(host, release, NULL);
    while (!spdk_thread_is_exited(host)) {
        spdk_thread_poll(host, 0, 0);
    }
    atomic_store(&phase, 2);
    return NULL;
} /* second */

int
main(void)
{
    struct spdk_env_opts opts;
    pthread_t            a, b;

    spdk_env_opts_init(&opts);
    opts.name     = "evpl_migration";
    opts.no_huge  = true;
    opts.mem_size = 512;
    evpl_test_abort_if(spdk_env_init(&opts), "environment failed");
    evpl_test_abort_if(spdk_thread_lib_init(NULL, 0), "thread library failed");
    evpl_init(NULL);
    host = spdk_thread_create("migrating-host", NULL);
    spdk_thread_send_msg(host, attach, NULL);
    pthread_create(&a, NULL, first, NULL);
    pthread_create(&b, NULL, second, NULL);
    pthread_join(a, NULL);
    pthread_join(b, NULL);
    spdk_thread_destroy(host);
    evpl_cleanup();
    spdk_thread_lib_fini();
    spdk_env_fini();
    /* The registered atexit handler must now be harmless. */
    return 0;
} /* main */
