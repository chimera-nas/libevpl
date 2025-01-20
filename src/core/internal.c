// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>

#include "core/internal.h"
#include "evpl/evpl.h"

static const char *level_string[] = {
    "none",
    "debug",
    "info",
    "error",
    "fatal"
};

void
evpl_vlog(
    const char *level,
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    va_list     argp)
{
    struct timespec ts;
    struct tm       tm_info;
    char            buf[256], *bp = buf;
    uint64_t        pid, tid;

    clock_gettime(CLOCK_REALTIME, &ts);

    gmtime_r(&ts.tv_sec, &tm_info);

    pid = getpid();

    tid = gettid();

    bp += snprintf(bp, sizeof(buf),
                   "time=%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ message=\"",
                   tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
                   tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec);

    bp += vsnprintf(bp, (buf + sizeof(buf)) - bp, fmt, argp);
    bp += snprintf(bp, (buf + sizeof(buf)) - bp,
                   "\" process=%lu thread=%lu level=%s module=%s file=\"%s:%d\"\n",
                   pid, tid, level, mod, srcfile, lineno);
    fprintf(stderr, "%s", buf);
} /* evpl_vlog */

evpl_log_fn EvplLog = evpl_vlog;

void
evpl_debug(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    evpl_vlog(level_string[EVPL_LOG_DEBUG], mod, srcfile, lineno, fmt, argp);
    va_end(argp);
} /* evpl_debug */

void
evpl_info(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    evpl_vlog(level_string[EVPL_LOG_INFO], mod, srcfile, lineno, fmt, argp);
    va_end(argp);
} /* evpl_info */

void
evpl_error(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    evpl_vlog(level_string[EVPL_LOG_ERROR], mod, srcfile, lineno, fmt, argp);
    va_end(argp);
} /* evpl_error */

void
evpl_fatal(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    evpl_vlog(level_string[EVPL_LOG_FATAL], mod, srcfile, lineno, fmt, argp);
    va_end(argp);

    exit(1);
} /* evpl_fatal */

void
evpl_abort(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    evpl_vlog(level_string[EVPL_LOG_FATAL], mod, srcfile, lineno, fmt, argp);
    va_end(argp);

    abort();
} /* evpl_abort */


void *
evpl_malloc(unsigned int size)
{
    void *p = malloc(size);

    if (!p) {
        evpl_core_fatal("Failed to allocate %u bytes\n", size);
    }

    return p;
} /* evpl_malloc */

void *
evpl_zalloc(unsigned int size)
{
    void *p = calloc(1, size);

    if (!p) {
        evpl_core_fatal("Failed to allocate %u bytes\n", size);
    }

    return p;
} /* evpl_zalloc */

void *
evpl_calloc(
    unsigned int n,
    unsigned int size)
{
    void *p = calloc(n, size);

    if (!p) {
        evpl_core_fatal("Failed to allocate %u chunks of %u bytes\n", n, size);
    }

    return p;
} /* evpl_calloc */

void *
evpl_valloc(
    unsigned int size,
    unsigned int alignment)
{
    void  *p;
    size_t padded_size = (size + alignment - 1) & ~(alignment - 1);

    p = aligned_alloc(alignment, padded_size);

    if (!p) {
        evpl_core_fatal("Failed to allocate %u bytes\n", size);
    }

    return p;
} /* evpl_valloc */

void
evpl_free(void *p)
{
    free(p);
} /* evpl_free */
