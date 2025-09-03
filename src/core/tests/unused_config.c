// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>

#include "evpl/evpl.h"


int
main(
    int   argc,
    char *argv[])
{
    struct evpl_global_config *config = evpl_global_config_init();

    /* if we called evpl_init(), it would take ownership of the config,
     * but if we decided not to init for whatever reason we need a way
     * to clean it up
     */

    evpl_global_config_release(config);

    return 0;
} /* main */
