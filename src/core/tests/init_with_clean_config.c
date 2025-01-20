// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include <stdio.h>

#include "evpl/evpl.h"


int main(int argc, char *argv[])
{
    struct evpl_config *config = evpl_config_init();

    evpl_init(config);

    evpl_cleanup();

    return 0;
}
