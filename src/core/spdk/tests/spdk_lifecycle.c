// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only

#include <errno.h>
#include "spdk_test_harness.h"

static atomic_int              finished;
static atomic_int              stopped;
static struct spdk_thread     *host;
static struct evpl            *borrowed;
static struct evpl_listener   *listener;
static struct evpl_thread     *worker;
static struct evpl_thread     *native;
static struct evpl_threadpool *pool;
static struct evpl_timer       timer;
static struct evpl_deferral    deferral;
static int                     timer_ran, deferred;

static void
host_survived(void *arg)
{
    evpl_test_abort_if(spdk_get_thread() != host, "borrowed host was lost");
    atomic_store(&finished, 1);
    spdk_thread_exit(host);
} /* host_survived */

static void
detached(void *arg)
{
    evpl_test_abort_if(!timer_ran || !deferred, "guest work lost");
    spdk_thread_send_msg(host, host_survived, NULL);
} /* detached */

static void
stop_on_host(void *arg)
{
    evpl_destroy_async(borrowed, detached, NULL);
} /* stop_on_host */

static void
stopped_one(void *arg)
{
    if (atomic_fetch_add(&stopped, 1) == 4) {
        spdk_thread_send_msg(host, stop_on_host, NULL);
    }
} /* stopped_one */

static void
listened(
    int   status,
    void *arg)
{
    evpl_test_abort_if(status, "async listen failed: %d", status);
    evpl_listener_destroy_async(listener, stopped_one, NULL);
    evpl_thread_destroy_async(worker, stopped_one, NULL);
    evpl_thread_destroy_async(native, stopped_one, NULL);
    evpl_threadpool_destroy_async(pool, stopped_one, NULL);
} /* listened */

static void
deferred_fn(
    struct evpl *evpl,
    void        *arg)
{
    deferred = 1;
} /* deferred_fn */

static void
timer_fn(
    struct evpl       *evpl,
    struct evpl_timer *unused)
{
    struct evpl_endpoint *ep = evpl_endpoint_create("127.0.0.1", 0);

    timer_ran = 1;
    evpl_test_abort_if(evpl_listen(listener, EVPL_STREAM_SPDK_TCP, ep) != EWOULDBLOCK,
                       "reactor blocking listen was not rejected");
    evpl_listen_async(listener, EVPL_STREAM_SPDK_TCP, ep, listened, NULL);
    evpl_endpoint_close(ep);
} /* timer_fn */

static void
attach(void *arg)
{
    struct evpl_thread_config *config = evpl_thread_config_init();

    evpl_thread_config_set_core_mech(config, EVPL_CORE_MECH_SPDK);
    borrowed = evpl_create(config);
    config   = evpl_thread_config_init();
    evpl_thread_config_set_core_mech(config, EVPL_CORE_MECH_SPDK);
    evpl_thread_config_set_name(config, "configured-worker");
    evpl_thread_config_set_spdk_cpumask(config, "[0]");
    worker = evpl_thread_create(config, NULL, NULL, NULL);
    config = evpl_thread_config_init();
    evpl_thread_config_set_core_mech(config, EVPL_CORE_MECH_SPDK);
    evpl_thread_config_set_name(config, "configured-pool");
    pool   = evpl_threadpool_create(config, 2, NULL, NULL, NULL);
    config = evpl_thread_config_init();
    evpl_thread_config_set_core_mech(config, EVPL_CORE_MECH_SPDK);
    listener = evpl_listener_create_config(config);
    config   = evpl_thread_config_init();
    evpl_thread_config_set_core_mech(config, EVPL_CORE_MECH_SPDK);
    struct evpl_listener *early = evpl_listener_create_config(config);
    evpl_listener_destroy_async(early, stopped_one, NULL);
    evpl_deferral_init(&deferral, deferred_fn, NULL);
    evpl_defer(borrowed, &deferral);
    evpl_add_oneshot_timer(borrowed, &timer, timer_fn, 1000);
} /* attach */

int
main(void)
{
    struct evpl_global_config *config;

    evpl_spdk_test_init(1);
    config = evpl_global_config_init();
    /* Native global default with explicit SPDK contexts in the same process. */
    evpl_init(config);
    native = evpl_thread_create(NULL, NULL, NULL, NULL);
    host   = spdk_thread_create("borrowed-host", NULL);
    spdk_thread_send_msg(host, attach, NULL);
    while (!atomic_load(&finished)) {
        usleep(1000);
    }
    return 0;
} /* main */
