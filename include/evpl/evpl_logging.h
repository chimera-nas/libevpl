// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once
#include "evpl/evpl_export.h"

#ifndef EVPL_INCLUDED
#error "Do not include evpl_logging.h directly, include evpl/evpl.h instead"
#endif // ifndef EVPL_INCLUDED

#include <stdarg.h>

typedef void (*evpl_log_fn)(
    const char *level,
    const char *module,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    va_list     argp);

typedef void (*evpl_flush_fn)(
    void);

EVPL_API void evpl_set_log_fn(
    evpl_log_fn   log_fn,
    evpl_flush_fn flush_fn);

EVPL_API EVPL_NORETURN void
evpl_abort(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...);