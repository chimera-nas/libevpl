// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once
#include <stdint.h>
#include <stdlib.h>
#include <stddef.h>

#include "evpl/evpl.h"

#if EVPL_MECH == epoll
#include "core/epoll.h"
#else /* if EVPL_MECH == epoll */
#error No EVPL_MECH
#endif /* if EVPL_MECH == epoll */

#define evpl_iovec_buffer(iov) ((struct evpl_buffer *) (iov)->private)

#define NS_PER_S           (1000000000UL)

#define EVPL_BVEC_EXTERNAL 0x01

struct evpl_thread_config {
    unsigned int spin_ns;
    int          wait_ms;

};

struct evpl_global_config {

    struct evpl_thread_config thread_default;

    unsigned int              max_pending;
    unsigned int              max_poll_fd;
    unsigned int              max_num_iovec;
    unsigned int              buffer_size;
    unsigned int              huge_pages;
    uint64_t                  slab_size;
    unsigned int              page_size;
    unsigned int              max_datagram_size;
    unsigned int              max_datagram_batch;
    unsigned int              refcnt;
    unsigned int              iovec_ring_size;
    unsigned int              dgram_ring_size;
    unsigned int              resolve_timeout_ms;

    unsigned int              io_uring_enabled;

    unsigned int              rdmacm_enabled;
    unsigned int              rdmacm_tos;
    unsigned int              rdmacm_max_sge;
    unsigned int              rdmacm_cq_size;
    unsigned int              rdmacm_sq_size;
    unsigned int              rdmacm_datagram_size_override;
    unsigned int              rdmacm_srq_size;
    unsigned int              rdmacm_srq_min;
    unsigned int              rdmacm_srq_batch;
    unsigned int              rdmacm_srq_prefill;
    unsigned int              rdmacm_retry_count;
    unsigned int              rdmacm_rnr_retry_count;

    unsigned int              xlio_enabled;

    unsigned int              vfio_enabled;
};

typedef void (*evpl_accept_callback_t)(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *remote_addr,
    void                *accepted,
    void                *private_data);

struct evpl {
    struct evpl_core             core; /* must be first */

    struct timespec              last_activity_ts;
    uint64_t                     activity;
    uint64_t                     last_activity;
    uint64_t                     poll_iterations;

    struct evpl_poll            *poll;
    int                          num_poll;
    int                          max_poll;

    int                          eventfd;
    int                          running;
    struct evpl_event            run_event;

    pthread_mutex_t              lock;
    struct evpl_connect_request *connect_requests;

    struct evpl_event          **active_events;
    int                          num_active_events;
    int                          max_active_events;
    int                          num_events;
    int                          num_enabled_events;
    int                          poll_mode;
    int                          force_poll_mode;

    struct evpl_doorbell        *doorbells;


    struct evpl_timer          **timers;
    int                          num_timers;
    int                          max_timers;

    struct evpl_deferral       **active_deferrals;
    int                          num_active_deferrals;
    int                          max_active_deferrals;

    struct evpl_buffer          *current_buffer;
    struct evpl_buffer          *datagram_buffer;
    struct evpl_bind            *free_binds;
    struct evpl_bind            *binds;
    struct evpl_bind            *pending_close_binds;

    struct evpl_thread_config    config;

    void                        *protocol_private[EVPL_NUM_PROTO];
    void                        *framework_private[EVPL_NUM_FRAMEWORK];
};

struct evpl_listen_request {
    enum evpl_protocol_id protocol_id;
    pthread_mutex_t             lock;
    pthread_cond_t              cond;
    int                         complete;
    struct evpl_address        *address;
    struct evpl_listen_request *prev;
    struct evpl_listen_request *next;
};

struct evpl_listener_binding {
    struct evpl           *evpl;
    evpl_attach_callback_t attach_callback;
    void                  *private_data;
};

struct evpl_connect_request {
    struct evpl_address         *local_address;
    struct evpl_address         *remote_address;
    struct evpl_protocol        *protocol;
    evpl_attach_callback_t       attach_callback;
    void                        *accepted;
    void                        *private_data;
    struct evpl_connect_request *prev;
    struct evpl_connect_request *next;
};

struct evpl_listener {
    struct evpl_thread           *thread;
    int                           running;
    struct evpl_doorbell          doorbell;
    struct evpl_bind            **binds;
    int                           num_binds;
    int                           max_binds;
    struct evpl_listen_request   *requests;
    struct evpl_listener_binding *attached;
    int                           num_attached;
    int                           max_attached;
    int                           rotor;
    pthread_mutex_t               lock;

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


#if defined(EVPL_ASSERT)
#define evpl_assert(module, file, line, cond) \
        if (!(cond)) { \
            evpl_abort(module, file, line, "assertion failed: " #cond); \
        }
#else // if defined(EVPL_ASSERT)
#define evpl_assert(module, cond)
#endif // if defined(EVPL_ASSERT)

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

#define evpl_core_assert(cond)          evpl_assert("core", __FILE__, __LINE__, cond)

#ifndef unlikely
#define unlikely(x)                     __builtin_expect(!!(x), 0)
#endif // ifndef unlikely

#ifndef likely
#define likely(x)                       __builtin_expect(!!(x), 1)
#endif // ifndef likely

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

static inline int64_t
evpl_ts_interval(
    const struct timespec *end,
    const struct timespec *start)
{
    return NS_PER_S * (end->tv_sec - start->tv_sec) + (end->tv_nsec - start->
                                                       tv_nsec);
} // evpl_ts_interval

static inline int
evpl_ts_compare(
    const struct timespec *a,
    const struct timespec *b)
{
    if (a->tv_sec == b->tv_sec) {
        if (a->tv_nsec < b->tv_nsec) {
            return -1;
        } else if (a->tv_nsec > b->tv_nsec) {
            return 1;
        }
        return 0;
    } else if (a->tv_sec < b->tv_sec) {
        return -1;
    } else {
        return 1;
    }
} // evpl_ts_compare

void
__evpl_init(
    void);


static inline void
evpl_activity(struct evpl *evpl)
{
    evpl->activity++;
} /* evpl_activity */

#endif // ifndef FORCE_INLINE
