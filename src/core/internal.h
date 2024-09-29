/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#include "core/evpl.h"

struct evpl_config {
    unsigned int max_pending;
    unsigned int max_poll_fd;
    unsigned int buffer_size;
    unsigned int page_size;
    unsigned int max_msg_size;
    unsigned int max_msg_batch;
    unsigned int refcnt;
    unsigned int bvec_ring_size;
    unsigned int dgram_ring_size;
};

void * evpl_malloc(
    unsigned int size);
void * evpl_zalloc(
    unsigned int size);
void * evpl_calloc(
    unsigned int n,
    unsigned int size);
void * evpl_valloc(
    unsigned int size,
    unsigned int alignment);
void evpl_free(
    void *p);

#define EVPL_LOG_NONE  0
#define EVPL_LOG_DEBUG 1
#define EVPL_LOG_INFO  2
#define EVPL_LOG_ERROR 3
#define EVPL_LOG_FATAL 4


void evpl_debug(
    const char *mod,
    const char *fmt,
    ...);
void evpl_info(
    const char *mod,
    const char *fmt,
    ...);
void evpl_error(
    const char *mod,
    const char *fmt,
    ...);
void evpl_fatal(
    const char *mod,
    const char *fmt,
    ...);
void evpl_abort(
    const char *mod,
    const char *fmt,
    ...);

#define evpl_fatal_if(cond, ...) \
    if (cond) { \
        evpl_fatal(__VA_ARGS__); \
    }

#define evpl_abort_if(cond, ...) \
    if (cond) { \
        evpl_abort(__VA_ARGS__); \
    }

#define evpl_core_debug(...)            evpl_debug("core", __VA_ARGS__)
#define evpl_core_info(...)             evpl_info("core", __VA_ARGS__)
#define evpl_core_error(...)            evpl_error("core", __VA_ARGS__)
#define evpl_core_fatal(...)            evpl_fatal("core", __VA_ARGS__)
#define evpl_core_abort(...)            evpl_abort("core", __VA_ARGS__)

#define evpl_core_fatal_if(cond, ...) \
    evpl_fatal_if(cond, "core", __VA_ARGS__)

#define evpl_core_abort_if(cond, ...) \
    evpl_fatal_if(cond, "core", __VA_ARGS__)

#ifndef unlikely
#define unlikely(x)                     __builtin_expect(!!(x), 0)
#endif // ifndef unlikely

#define container_of(ptr, type, member) ({            \
        typeof(((type *) 0)->member) * __mptr = (ptr); \
        (type *) ((char *) __mptr - offsetof(type, member)); })


#ifndef FORCE_INLINE
#define FORCE_INLINE __attribute__((always_inline)) inline
#endif // ifndef FORCE_INLINE