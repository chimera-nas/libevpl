// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include <stdio.h>

#include "evpl/evpl.h"


int main(int argc, char *argv[])
{
    evpl_init(NULL);

    evpl_cleanup();

    return 0;
}
