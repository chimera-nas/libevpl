// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>

#include "core/evpl.h"


int
main(
    int   argc,
    char *argv[])
{
    struct evpl_config *config = evpl_config_init();

    evpl_init_auto(config);

    return 0;
} /* main */
