/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "core/internal.h"

void
evpl_vlog(
    int         level,
    const char *fmt,
    va_list     argp)
{
    char buf[256], *bp = buf;

    bp += vsnprintf(bp, sizeof(buf), fmt, argp);
    bp += snprintf(bp, (buf + sizeof(buf)) - bp, "\n");
    fprintf(stderr, "%s", buf);
} /* evpl_vlog */


void
evpl_debug(
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    evpl_vlog(EVPL_LOG_DEBUG, fmt, argp);
    va_end(argp);
} /* evpl_debug */

void
evpl_info(
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    evpl_vlog(EVPL_LOG_INFO, fmt, argp);
    va_end(argp);
} /* evpl_info */

void
evpl_error(
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    evpl_vlog(EVPL_LOG_ERROR, fmt, argp);
    va_end(argp);
} /* evpl_error */

void
evpl_fatal(
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    evpl_vlog(EVPL_LOG_FATAL, fmt, argp);
    va_end(argp);

    exit(1);
} /* evpl_fatal */

void
evpl_abort(
    const char *fmt,
    ...)
{
    va_list argp;

    va_start(argp, fmt);
    evpl_vlog(EVPL_LOG_FATAL, fmt, argp);
    va_end(argp);

    abort();
} /* evpl_abort */


void *
evpl_malloc(unsigned int size)
{
    void *p = malloc(size);

    if (!p) {
        evpl_fatal("Failed to allocate %u bytes\n", size);
    }

    return p;
} /* evpl_malloc */

void *
evpl_zalloc(unsigned int size)
{
    void *p = calloc(1, size);

    if (!p) {
        evpl_fatal("Failed to allocate %u bytes\n", size);
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
        evpl_fatal("Failed to allocate %u chunks of %u bytes\n", n, size);
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
        evpl_fatal("Failed to allocate %u bytes\n", size);
    }

    return p;
} /* evpl_valloc */

void
evpl_free(void *p)
{
    free(p);
} /* evpl_free */
