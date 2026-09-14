// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
/* Short-option parsing for test executables. Kept private to the Windows
 * test harness; the library itself does not need getopt. */
static char *optarg;
static int
evpl_test_getopt(
    int         argc,
    char      **argv,
    const char *options)
{
    static int  index = 1;
    char        option;
    const char *spec;

    if (index >= argc || argv[index][0] != '-') {
        return -1;
    }
    if (!strcmp(argv[index], "--")) {
        index++; return -1;
    }
    option = argv[index][1];
    spec   = option ? strchr(options, option) : NULL;
    if (!spec) {
        index++; return '?';
    }
    if (spec[1] != ':') {
        index++; return option;
    }
    if (argv[index][2]) {
        optarg = argv[index++] + 2;
    } else if (++index < argc) {
        optarg = argv[index++];
    } else {
        return '?';
    }
    return option;
} // evpl_test_getopt
#define getopt evpl_test_getopt
