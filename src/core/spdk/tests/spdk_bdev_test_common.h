// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

/*
 * bdev subsystem bring-up for SPDK bdev tests, without the app framework:
 * a bootstrap spdk_thread runs spdk_subsystem_load_config with a JSON config
 * (e.g. creating a malloc bdev), the way SPDK's fio plugin does.
 *
 * The bootstrap thread is created before any evpl call so it is the first
 * spdk_thread in the process (SPDK's "app thread", which some init paths
 * are restricted to).  Call evpl_spdk_bdev_test_up right after
 * evpl_spdk_test_init, and evpl_spdk_bdev_test_down before returning from
 * main; the bootstrap thread itself is reaped by the harness atexit fini.
 */

#include <spdk/init.h>
#include <spdk/rpc.h>

#include "spdk_test_harness.h"

static struct spdk_thread *evpl_spdk_bdev_test_thread;
static volatile int        evpl_spdk_bdev_test_rc;
static volatile int        evpl_spdk_bdev_test_flag;

struct evpl_spdk_bdev_test_json {
    const char *json;
    size_t      len;
};

static void
evpl_spdk_bdev_test_init_done(
    int   rc,
    void *ctx)
{
    evpl_spdk_bdev_test_rc   = rc;
    evpl_spdk_bdev_test_flag = 1;
} /* evpl_spdk_bdev_test_init_done */

static void
evpl_spdk_bdev_test_subsystems_up(
    int   rc,
    void *ctx)
{
    if (rc == 0) {
        /* The RPC state gates which config methods spdk_subsystem_load_config
         * will replay; runtime methods like bdev_malloc_create are silently
         * skipped unless the state is advanced (the app framework does this
         * in its own init-done callback). */
        spdk_rpc_set_state(SPDK_RPC_RUNTIME);
    }

    evpl_spdk_bdev_test_init_done(rc, ctx);
} /* evpl_spdk_bdev_test_subsystems_up */

static void
evpl_spdk_bdev_test_init_msg(void *ctx)
{
    spdk_subsystem_init(evpl_spdk_bdev_test_subsystems_up, NULL);
} /* evpl_spdk_bdev_test_init_msg */

static void
evpl_spdk_bdev_test_load_msg(void *ctx)
{
    struct evpl_spdk_bdev_test_json *cfg = ctx;

    /* Replays the config RPCs against the current (post-init) RPC state;
     * unlike the old init_from_json_config this does NOT initialize the
     * subsystems itself, hence the spdk_subsystem_init step first. */
    spdk_subsystem_load_config((void *) cfg->json, cfg->len,
                               evpl_spdk_bdev_test_init_done, NULL, true);
} /* evpl_spdk_bdev_test_load_msg */

static void
evpl_spdk_bdev_test_step(
    spdk_msg_fn fn,
    void       *arg,
    const char *what)
{
    int rc;

    evpl_spdk_bdev_test_flag = 0;
    evpl_spdk_bdev_test_rc   = 0;

    rc = spdk_thread_send_msg(evpl_spdk_bdev_test_thread, fn, arg);

    evpl_test_abort_if(rc, "spdk_thread_send_msg failed: %d", rc);

    while (!evpl_spdk_bdev_test_flag) {
        usleep(1000);
    }

    evpl_test_abort_if(evpl_spdk_bdev_test_rc, "%s failed: %d",
                       what, evpl_spdk_bdev_test_rc);
} /* evpl_spdk_bdev_test_step */

static void
evpl_spdk_bdev_test_up(const char *json)
{
    static struct evpl_spdk_bdev_test_json cfg;

    cfg.json = json;
    cfg.len  = strlen(json);

    evpl_spdk_bdev_test_thread = spdk_thread_create("bootstrap", NULL);

    evpl_test_abort_if(!evpl_spdk_bdev_test_thread,
                       "bootstrap spdk_thread_create failed");

    evpl_spdk_bdev_test_step(evpl_spdk_bdev_test_init_msg, NULL,
                             "subsystem init");

    evpl_spdk_bdev_test_step(evpl_spdk_bdev_test_load_msg, &cfg,
                             "JSON config load");
} /* evpl_spdk_bdev_test_up */

static void
evpl_spdk_bdev_test_fini_done(void *ctx)
{
    evpl_spdk_bdev_test_flag = 1;
} /* evpl_spdk_bdev_test_fini_done */

static void
evpl_spdk_bdev_test_fini_msg(void *ctx)
{
    spdk_subsystem_fini(evpl_spdk_bdev_test_fini_done, NULL);
} /* evpl_spdk_bdev_test_fini_msg */

static void
evpl_spdk_bdev_test_down(void)
{
    int rc;

    evpl_spdk_bdev_test_flag = 0;

    rc = spdk_thread_send_msg(evpl_spdk_bdev_test_thread,
                              evpl_spdk_bdev_test_fini_msg, NULL);

    evpl_test_abort_if(rc, "spdk_thread_send_msg failed: %d", rc);

    while (!evpl_spdk_bdev_test_flag) {
        usleep(1000);
    }
} /* evpl_spdk_bdev_test_down */

#define EVPL_SPDK_BDEV_TEST_MALLOC_JSON                                  \
        "{\"subsystems\":[{\"subsystem\":\"bdev\",\"config\":["          \
        "{\"method\":\"bdev_malloc_create\",\"params\":"                 \
        "{\"name\":\"Malloc0\",\"num_blocks\":16384,\"block_size\":4096" \
        "}}]}]}"
