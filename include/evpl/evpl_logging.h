// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_logging.h directly, include evpl/evpl.h instead"
#endif

#include <stdarg.h>

typedef void (*evpl_log_fn)(
    const char *level,
    const char *module,
    const char *srcfile,
    int lineno,
    const char *fmt,
    va_list argp);

void evpl_set_log_fn(
    evpl_log_fn log_fn);