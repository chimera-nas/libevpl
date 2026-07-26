// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <pthread.h>

#include "logging.h"
#include "macros.h"

/* Portable thread id for log lines: Linux gettid(2); macOS has no gettid, so
 * use pthread_threadid_np() which yields the same kernel-level 64-bit id. */
static inline uint64_t
evpl_gettid(void)
{
#ifdef __APPLE__
    uint64_t tid = 0;
    pthread_threadid_np(NULL, &tid);
    return tid;
#else  /* ifdef __APPLE__ */
    return (uint64_t) gettid();
#endif /* ifdef __APPLE__ */
} /* evpl_gettid */

#include "evpl/evpl.h"


extern evpl_log_fn   EvplLog;
extern evpl_flush_fn EvplFlush;

SYMBOL_EXPORT void
evpl_set_log_fn(
    evpl_log_fn   log_fn,
    evpl_flush_fn flush_fn)
{
    EvplLog   = log_fn;
    EvplFlush = flush_fn;
} /* evpl_set_log_fn */

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
    char            buf[512], *bp = buf;
    uint64_t        pid, tid;

    clock_gettime(CLOCK_REALTIME, &ts);

    gmtime_r(&ts.tv_sec, &tm_info);

    pid = getpid();

    tid = evpl_gettid();

    bp += snprintf(bp, sizeof(buf),
                   "time=%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ message=\"",
                   tm_info.tm_year + 1900, tm_info.tm_mon + 1, tm_info.tm_mday,
                   tm_info.tm_hour, tm_info.tm_min, tm_info.tm_sec, ts.tv_nsec);

    bp += vsnprintf(bp, (buf + sizeof(buf)) - bp, fmt, argp);
    snprintf(bp, (buf + sizeof(buf)) - bp,
             "\" process=%llu thread=%llu level=%s module=%s file=\"%s:%d\"\n",
             (unsigned long long) pid, (unsigned long long) tid, level, mod,
             srcfile, lineno);
    fprintf(stderr, "%s", buf);
} /* evpl_vlog */

evpl_log_fn   EvplLog   = evpl_vlog;
evpl_flush_fn EvplFlush = NULL;

SYMBOL_EXPORT void
evpl_debug(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    EvplLog(level_string[EVPL_LOG_DEBUG], mod, srcfile, lineno, fmt, argp);
    va_end(argp);
} /* evpl_debug */

SYMBOL_EXPORT void
evpl_info(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    EvplLog(level_string[EVPL_LOG_INFO], mod, srcfile, lineno, fmt, argp);
    va_end(argp);
} /* evpl_info */

SYMBOL_EXPORT void
evpl_error(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    EvplLog(level_string[EVPL_LOG_ERROR], mod, srcfile, lineno, fmt, argp);
    va_end(argp);
} /* evpl_error */

SYMBOL_EXPORT void
evpl_fatal(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    EvplLog(level_string[EVPL_LOG_FATAL], mod, srcfile, lineno, fmt, argp);
    va_end(argp);

    if (EvplFlush) {
        EvplFlush();
    }

    exit(1);
} /* evpl_fatal */

SYMBOL_EXPORT __attribute__((noreturn)) void
evpl_abort(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    EvplLog(level_string[EVPL_LOG_FATAL], mod, srcfile, lineno, fmt, argp);
    va_end(argp);

    if (EvplFlush) {
        EvplFlush();
    }

    abort();
} /* evpl_abort */