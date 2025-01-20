// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include <stdarg.h>
#include <stdio.h>

#include "common.h"

void
dump_output(
    const char *format,
    ...)
{
    char    buf[1024];
    va_list ap;

    va_start(ap, format);
    vsnprintf(buf, sizeof(buf), format, ap);
    va_end(ap);

    evpl_rpc2_debug("%s", buf);
} /* dump_output */