// SPDX-FileCopyrightText: 2025 - 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evpl/evpl.h"

/*
 * Optional core-mechanism override for the test suite.
 *
 * ctest registers each socket test once per event-loop mechanism compiled into
 * the build (see src/core/socket/tests/CMakeLists.txt) and selects it through
 * EVPL_TEST_CORE_MECH.  Keeping this in the harness rather than in the library
 * means no test source -- and no libevpl consumer -- needs to know about it.
 */
static inline void
test_evpl_set_core_mech(struct evpl_global_config *config)
{
    const char *mech = getenv("EVPL_TEST_CORE_MECH");

    if (!mech || !*mech) {
        return;
    }

    if (strcmp(mech, "epoll") == 0) {
        evpl_global_config_set_core_mech(config, EVPL_CORE_MECH_EPOLL);
    } else if (strcmp(mech, "kqueue") == 0) {
        evpl_global_config_set_core_mech(config, EVPL_CORE_MECH_KQUEUE);
    } else if (strcmp(mech, "select") == 0) {
        evpl_global_config_set_core_mech(config, EVPL_CORE_MECH_SELECT);
    } else {
        fprintf(stderr, "EVPL_TEST_CORE_MECH: unknown mechanism '%s'\n", mech);
        exit(1);
    }
} /* test_evpl_set_core_mech */

static inline void
test_evpl_config(void)
{
    struct evpl_global_config *config = evpl_global_config_init();

    evpl_global_config_set_tls_verify_peer(config, 0);

    test_evpl_set_core_mech(config);

    evpl_init(config);
} // test_setup_tls_config
