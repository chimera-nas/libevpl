// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#include "evpl/evpl.h"

#define evpl_iovec_buffer(iov) ((struct evpl_buffer *) (iov)->private)

#define NS_PER_S           (1000000000UL)

#define EVPL_BVEC_EXTERNAL 0x01

struct evpl_config {
    unsigned int max_pending;
    unsigned int max_poll_fd;
    unsigned int max_num_iovec;
    unsigned int buffer_size;
    unsigned int huge_pages;
    uint64_t     slab_size;
    unsigned int page_size;
    unsigned int max_datagram_size;
    unsigned int max_datagram_batch;
    unsigned int refcnt;
    unsigned int iovec_ring_size;
    unsigned int dgram_ring_size;
    unsigned int resolve_timeout_ms;
    unsigned int spin_ns;
    unsigned int wait_ms;

    unsigned int io_uring_enabled;

    unsigned int rdmacm_enabled;
    unsigned int rdmacm_cq_size;
    unsigned int rdmacm_sq_size;
    unsigned int rdmacm_datagram_size_override;
    unsigned int rdmacm_srq_size;
    unsigned int rdmacm_srq_min;
    unsigned int rdmacm_srq_prefill;
    unsigned int rdmacm_retry_count;
    unsigned int rdmacm_rnr_retry_count;

    unsigned int xlio_enabled;

    unsigned int vfio_enabled;
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
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...);
void evpl_info(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...);
void evpl_error(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...);
void evpl_fatal(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...);
void evpl_abort(
    const char *mod,
    const char *srcfile,
    int         lineno,
    const char *fmt,
    ...);

#define evpl_fatal_if(cond, ...) \
        if (cond)                    \
        {                            \
            evpl_fatal(__VA_ARGS__); \
        }

#define evpl_abort_if(cond, ...) \
        if (cond)                    \
        {                            \
            evpl_abort(__VA_ARGS__); \
        }

#define evpl_core_debug(...)            evpl_debug("core", __FILE__, __LINE__, \
                                                   __VA_ARGS__)
#define evpl_core_info(...)             evpl_info("core", __FILE__, __LINE__, \
                                                  __VA_ARGS__)
#define evpl_core_error(...)            evpl_error("core", __FILE__, __LINE__, \
                                                   __VA_ARGS__)
#define evpl_core_fatal(...)            evpl_fatal("core", __FILE__, __LINE__, \
                                                   __VA_ARGS__)
#define evpl_core_abort(...)            evpl_abort("core", __FILE__, __LINE__, \
                                                   __VA_ARGS__)

#define evpl_core_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "core", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_core_abort_if(cond, ...) \
        evpl_abort_if(cond, "core", __FILE__, __LINE__, __VA_ARGS__)

#ifndef unlikely
#define unlikely(x)                     __builtin_expect(!!(x), 0)
#endif // ifndef unlikely

#define container_of(ptr, type, member) ({            \
        typeof(((type *) 0)->member) * __mptr = (ptr); \
        (type *) ((char *) __mptr - offsetof(type, member)); })

#ifndef FORCE_INLINE
#define FORCE_INLINE __attribute__((always_inline)) inline

/* Allocate a iovec representing an entire evpl_buffer
 * guaranteed to be contiguous
 */

void evpl_iovec_alloc_whole(
    struct evpl       *evpl,
    struct evpl_iovec *r_iovec);

/*
 * Allocate a iovec to hold one datagram of maximal size
 * guaranteed to be contiguous
 */
void evpl_iovec_alloc_datagram(
    struct evpl       *evpl,
    struct evpl_iovec *r_iovec,
    int                size);

static uint64_t
evpl_ts_interval(
    const struct timespec *end,
    const struct timespec *start)
{
    return NS_PER_S * (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->
                                                       tv_nsec);
} // evpl_ts_interval

void evpl_activity(
    struct evpl *evpl);

#endif // ifndef FORCE_INLINE
