/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

#include "core/evpl.h"

struct evpl_config {
    unsigned int max_pending;
    unsigned int max_poll_fd;
    unsigned int buffer_size;
    unsigned int page_size;
    unsigned int refcnt;
    unsigned int bvec_ring_size;
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
    const char *fmt,
    ...);
void evpl_info(
    const char *fmt,
    ...);
void evpl_error(
    const char *fmt,
    ...);
void evpl_fatal(
    const char *fmt,
    ...);
void evpl_crash(
    const char *fmt,
    ...);

#define evpl_fatal_if(cond, ...) \
    if (cond) { \
        evpl_fatal(__VA_ARGS__); \
    }

#define evpl_crash_if(cond, ...) \
    if (cond) { \
        evpl_crash(__VA_ARGS__); \
    }
