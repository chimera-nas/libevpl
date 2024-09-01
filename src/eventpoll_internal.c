#include <stdio.h>
#include <stdarg.h>
#include <stdlib.h>

#include "eventpoll_internal.h"

void
eventpoll_vlog(int level, const char *fmt, va_list argp)
{
    char buf[256], *bp = buf;

    bp += vsnprintf(bp, sizeof(buf), fmt, argp);
    bp += snprintf(bp, (buf + sizeof(buf)) - bp, "\n");
    fprintf(stderr, "%s", buf);
}


void eventpoll_debug(const char *fmt, ...)
{
    va_list argp;

    va_start(argp, fmt);
    eventpoll_vlog(EVENTPOLL_LOG_DEBUG, fmt, argp);
    va_end(argp);
}

void eventpoll_info(const char *fmt, ...)
{
    va_list argp;

    va_start(argp, fmt);
    eventpoll_vlog(EVENTPOLL_LOG_INFO, fmt, argp);
    va_end(argp);
}

void eventpoll_error(const char *fmt, ...)
{
    va_list argp;

    va_start(argp, fmt);
    eventpoll_vlog(EVENTPOLL_LOG_ERROR, fmt, argp);
    va_end(argp);
}

void eventpoll_fatal(const char *fmt, ...)
{
    va_list argp;

    va_start(argp, fmt);
    eventpoll_vlog(EVENTPOLL_LOG_FATAL, fmt, argp);
    va_end(argp);

    exit(1);
}

void eventpoll_abort(const char *fmt, ...)
{
    va_list argp;

    va_start(argp, fmt);
    eventpoll_vlog(EVENTPOLL_LOG_FATAL, fmt, argp);
    va_end(argp);

    abort();
}


void *
eventpoll_malloc(unsigned int size)
{
    void *p = malloc(size);

    if (!p) {
        eventpoll_fatal("Failed to allocate %u bytes\n", size);
    }

    return p;
}

void *
eventpoll_zalloc(unsigned int size)
{
    void *p = calloc(1,size);

    if (!p) {
        eventpoll_fatal("Failed to allocate %u bytes\n", size);
    }

    return p;
}

void *
eventpoll_calloc(unsigned int n, unsigned int size)
{
    void *p = calloc(n,size);

    if (!p) {
        eventpoll_fatal("Failed to allocate %u chunks of %u bytes\n", n, size);
    }

    return p;
}

void *
eventpoll_valloc(unsigned int size, unsigned int alignment)
{
    void *p = aligned_alloc(alignment, size);

    if (!p) {
        eventpoll_fatal("Failed to allocate %u bytes\n", size);
    }

    return p;
}

void
eventpoll_free(void *p)
{
    free(p);
}
