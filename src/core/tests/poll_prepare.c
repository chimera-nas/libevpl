// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdint.h>
#include <unistd.h>
#include "core/evpl.h"
#include "core/test_log.h"
#include "test_common.h"

static unsigned int                prepared[2], seen[2], waits, pre_hooks, post_hooks;
static unsigned int                veto, retired;
static const struct evpl_core_ops *real_ops;

static int
prepare(
    struct evpl *evpl,
    void        *arg)
{
    unsigned int id = (uintptr_t) arg;

    evpl_test_abort_if(pre_hooks != post_hooks, "prepare ran inside application wait hooks");
    prepared[id]++;
    return id == 0 && veto;
} /* prepare */

static void
unused_poll(
    struct evpl *evpl,
    void        *arg)
{
    evpl_test_abort("busy-poll callback ran with polling disabled");
} /* unused_poll */

static void
pre_wait(
    struct evpl *evpl,
    void        *arg)
{
    pre_hooks++;
} /* pre_wait */

static void
post_wait(
    struct evpl *evpl,
    void        *arg)
{
    post_hooks++;
} /* post_wait */

static int
tracked_wait(
    struct evpl_core *core,
    int               msecs)
{
    evpl_test_abort_if(pre_hooks != post_hooks + 1, "application hooks were replaced");
    if (msecs != 0) {
        evpl_test_abort_if((!retired && prepared[0] == seen[0]) ||
                           prepared[1] == seen[1], "blocking wait was not prepared");
    }
    if (!retired && prepared[0] != seen[0]) {
        evpl_test_abort_if(prepared[1] == seen[1], "a veto skipped the next prepare callback");
        evpl_test_abort_if(veto && msecs != 0, "sleep was not vetoed");
    }
    seen[0] = prepared[0];
    seen[1] = prepared[1];
    waits++;
    return real_ops->wait(core, msecs);
} /* tracked_wait */

int
main(void)
{
    struct evpl               *evpl;
    struct evpl_poll          *first, *second;
    struct evpl_thread_config *config;
    struct evpl_core_ops       ops;
    struct evpl_loop_hooks     hooks = { .pre_wait = pre_wait, .post_wait = post_wait };
    unsigned int               i, old;

    alarm(10);
    test_evpl_config();
    config = evpl_thread_config_init();
    evpl_thread_config_set_poll_mode(config, 0);
    evpl_thread_config_set_wait_ms(config, 1);
    evpl           = evpl_create(config);
    real_ops       = evpl->core.ops;
    ops            = *real_ops;
    ops.wait       = tracked_wait;
    evpl->core.ops = &ops;
    evpl_set_loop_hooks(evpl, &hooks);
    first  = evpl_add_poll(evpl, NULL, NULL, unused_poll, (void *) 0);
    second = evpl_add_poll(evpl, NULL, NULL, unused_poll, (void *) 1);
    evpl_poll_set_prepare_callback(first, prepare);
    evpl_poll_set_prepare_callback(second, prepare);
    for (i = 0; i < 32; i++) {
        veto = i & 1;
        evpl_continue(evpl);
    }
    evpl_test_abort_if(prepared[0] < 16 || prepared[1] != prepared[0],
                       "prepare callbacks did not run on repeated sleeps");
    old = prepared[0];
    evpl_remove_poll(evpl, first);
    retired = 1;
    for (i = 0; i < 16; i++) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if(prepared[0] != old || prepared[1] <= old,
                       "removing a poller left its prepare callback active");
    evpl_test_abort_if(pre_hooks != waits || post_hooks != waits, "unbalanced wait hooks");
    evpl_remove_poll(evpl, second);
    evpl->core.ops = real_ops;
    evpl_set_loop_hooks(evpl, NULL);
    evpl_destroy(evpl);
    return 0;
} /* main */
