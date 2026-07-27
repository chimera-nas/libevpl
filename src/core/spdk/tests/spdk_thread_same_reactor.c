// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Deadlock regression test: with a single reactor, an spdk_thread that calls
 * evpl_thread_create/evpl_thread_destroy shares its reactor with the new
 * worker, so any blocking wait inside those calls can never complete -- the
 * reactor is executing the caller.  The SPDK paths must return immediately
 * for spdk_thread callers; this test hangs (and trips the ctest timeout) if
 * anyone reintroduces a wait.
 */

#include <stddef.h>

#include "spdk_test_harness.h"

static volatile int bootstrap_done;
static volatile int init_ran;
static volatile int shutdown_ran;

static void *
inner_init(
    struct evpl *evpl,
    void        *private_data)
{
    init_ran = 1;

    return private_data;
} /* inner_init */

static void
inner_shutdown(
    struct evpl *evpl,
    void        *private_data)
{
    shutdown_ran = 1;
} /* inner_shutdown */

static void
bootstrap_fn(void *ctx)
{
    struct evpl_thread *thread;

    /* On an spdk_thread: must return without waiting for readiness. */
    thread = evpl_thread_create(NULL, inner_init, inner_shutdown, NULL);

    /* Must detach rather than wait; the worker frees the handle itself. */
    evpl_thread_destroy(thread);

    bootstrap_done = 1;

    spdk_thread_exit(spdk_get_thread());
} /* bootstrap_fn */

int
main(
    int   argc,
    char *argv[])
{
    struct spdk_thread *bootstrap;
    int                 rc;

    evpl_spdk_test_init(1);

    evpl_spdk_test_config();

    bootstrap = spdk_thread_create("bootstrap", NULL);

    evpl_test_abort_if(!bootstrap, "bootstrap spdk_thread_create failed");

    rc = spdk_thread_send_msg(bootstrap, bootstrap_fn, NULL);

    evpl_test_abort_if(rc, "spdk_thread_send_msg failed: %d", rc);

    while (!bootstrap_done || !init_ran || !shutdown_ran) {
        usleep(1000);
    }

    evpl_test_info("bootstrap completed; worker init and shutdown ran");

    return 0;
} /* main */
