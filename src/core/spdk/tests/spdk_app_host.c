// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include <stdlib.h>
#include <spdk/event.h>
#include <spdk/thread.h>
#include "core/test_log.h"
#include "evpl/evpl.h"

static struct evpl        *guest;
static struct evpl_timer   timer;
static struct spdk_thread *host;

static void
host_still_running(void *arg)
{
    evpl_test_abort_if(spdk_get_thread() != host, "host thread lost");
    evpl_cleanup();
    spdk_app_stop(0);
} /* host_still_running */

static void
detached(void *arg)
{
    spdk_thread_send_msg(host, host_still_running, NULL);
} /* detached */

static void
timeout_cb(
    struct evpl       *evpl,
    struct evpl_timer *unused)
{
    evpl_destroy_async(evpl, detached, NULL);
} /* timeout_cb */

static void
start(void *arg)
{
    struct evpl_thread_config *config;

    host = spdk_get_thread();
    evpl_init(NULL);
    config = evpl_thread_config_init();
    evpl_thread_config_set_core_mech(config, EVPL_CORE_MECH_SPDK);
    guest = evpl_create(config);
    evpl_add_oneshot_timer(guest, &timer, timeout_cb, 1000);
} /* start */

int
main(void)
{
    struct spdk_app_opts opts;
    int                  rc;

    spdk_app_opts_init(&opts, sizeof(opts));
    opts.name         = "evpl_host";
    opts.no_huge      = true;
    opts.mem_size     = 512;
    opts.rpc_addr     = NULL;
    opts.reactor_mask = "0x1";
    if (getenv("EVPL_TEST_INTERRUPT")) {
        spdk_interrupt_mode_enable();
    }
    rc = spdk_app_start(&opts, start, NULL);
    spdk_app_fini();
    return rc;
} /* main */
