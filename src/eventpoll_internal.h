/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#ifndef __EVENTPOLL_INTERNAL_H__
#define __EVENTPOLL_INTERNAL_H__

#include "eventpoll.h"

struct eventpoll_config {
    unsigned int max_pending;
    unsigned int max_poll_fd;
    unsigned int buffer_size;
    unsigned int page_size;
    unsigned int refcnt;
    unsigned int bvec_ring_size;
};

void * eventpoll_malloc(unsigned int size);
void * eventpoll_zalloc(unsigned int size);
void * eventpoll_calloc(unsigned int n, unsigned int size);
void * eventpoll_valloc(unsigned int size, unsigned int alignment);
void   eventpoll_free(void *p);

#define EVENTPOLL_LOG_NONE  0
#define EVENTPOLL_LOG_DEBUG 1
#define EVENTPOLL_LOG_INFO  2
#define EVENTPOLL_LOG_ERROR 3
#define EVENTPOLL_LOG_FATAL 4


void eventpoll_debug(const char *fmt, ...);
void eventpoll_info(const char *fmt, ...);
void eventpoll_error(const char *fmt, ...);
void eventpoll_fatal(const char *fmt, ...);
void eventpoll_crash(const char *fmt, ...);

#define eventpoll_fatal_if(cond, ...) \
    if (cond) { \
        eventpoll_fatal(__VA_ARGS__); \
    }

#define eventpoll_crash_if(cond, ...) \
    if (cond) { \
        eventpoll_crash(__VA_ARGS__); \
    }

#endif
