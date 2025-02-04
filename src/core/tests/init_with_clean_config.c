// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include <stdio.h>

#include "evpl/evpl.h"


int
main(
    int   argc,
    char *argv[])
{
    struct evpl_global_config *config = evpl_global_config_init();

    evpl_init(config);

    return 0;
} /* main */
