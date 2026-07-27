// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Verify the core-mechanism config knob: every mechanism compiled into this
 * build must initialize and yield a working event loop, as must the platform
 * default.  (Requesting a mechanism the platform does not support aborts at
 * evpl_init, which is exercised out-of-band rather than in this pass/fail
 * test.)
 *
 * The mechanism is chosen per-process because evpl_init is once-per-process,
 * so the harness runs this binary once per mechanism via argv.
 */

#include <stdio.h>
#include <string.h>

#include "evpl/evpl.h"

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_global_config *config = evpl_global_config_init();
    struct evpl               *evpl;
    const char                *name = argc > 1 ? argv[1] : "default";

    if (strcmp(name, "default") == 0) {
        evpl_global_config_set_core_mech(config, EVPL_CORE_MECH_DEFAULT);
    } else if (strcmp(name, "epoll") == 0) {
        evpl_global_config_set_core_mech(config, EVPL_CORE_MECH_EPOLL);
    } else if (strcmp(name, "kqueue") == 0) {
        evpl_global_config_set_core_mech(config, EVPL_CORE_MECH_KQUEUE);
    } else if (strcmp(name, "select") == 0) {
        evpl_global_config_set_core_mech(config, EVPL_CORE_MECH_SELECT);
    } else {
        fprintf(stderr, "unknown core mechanism '%s'\n", name);
        return 1;
    }

    evpl_init(config);

    evpl = evpl_create(NULL);

    if (!evpl) {
        fprintf(stderr, "evpl_create failed for core mechanism '%s'\n", name);
        return 1;
    }

    evpl_destroy(evpl);

    return 0;
} /* main */
