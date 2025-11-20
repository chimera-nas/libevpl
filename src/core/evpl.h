// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once
#include <stdint.h>
#include <stddef.h>
#include <pthread.h>

#define EVPL_INTERNAL 1
#include "event.h"
#include "doorbell.h"
#include "evpl/evpl.h"


#if EVPL_MECH == epoll
#include "core/epoll.h"
#else /* if EVPL_MECH == epoll */
#error No EVPL_MECH
#endif /* if EVPL_MECH == epoll */

struct evpl_thread_config {
    int          poll_mode;
    int          poll_iterations;
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
    unsigned int              rdma_request_ring_size;
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

    char                     *tls_cert_file;
    char                     *tls_key_file;
    char                     *tls_ca_file;
    char                     *tls_cipher_list;
    int                       tls_verify_peer;
    int                       tls_ktls_enabled;
};

typedef void (*evpl_accept_callback_t)(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *remote_addr,
    void                *accepted,
    void                *private_data);

struct evpl {
    struct evpl_core              core; /* must be first */


    uint64_t                      hf_tsc_value;
    uint64_t                      hf_tsc_mult;
    struct timespec               hf_tsc_start;

    uint64_t                      poll_iters;

    struct timespec               last_activity_ts;
    uint64_t                      activity;
    uint64_t                      last_activity;
    uint64_t                      poll_iterations;

    struct evpl_poll             *poll;
    int                           num_poll;
    int                           max_poll;

    int                           eventfd;
    int                           running;
    struct evpl_event             run_event;

    pthread_mutex_t               lock;
    struct evpl_connect_request  *connect_requests;

    struct evpl_event           **active_events;
    int                           num_active_events;
    int                           max_active_events;
    int                           num_events;
    int                           num_enabled_events;
    int                           poll_mode;
    int                           force_poll_mode;

    struct evpl_doorbell         *doorbells;


    struct evpl_timer           **timers;
    int                           num_timers;
    int                           max_timers;

    struct evpl_deferral        **active_deferrals;
    int                           num_active_deferrals;
    int                           max_active_deferrals;

    struct evpl_buffer           *current_buffer;
    struct evpl_buffer           *datagram_buffer;
    struct evpl_bind             *free_binds;
    struct evpl_bind             *binds;
    struct evpl_bind             *pending_close_binds;

    struct evpl_listener_binding *listener_bindings;

    struct evpl_thread_config     config;

    void                         *protocol_private[EVPL_NUM_PROTO];
    void                         *framework_private[EVPL_NUM_FRAMEWORK];
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
    struct evpl                  *evpl;
    struct evpl_listener         *listener;
    evpl_attach_callback_t        attach_callback;
    void                         *private_data;
    int                           enabled;
    struct evpl_listener_binding *prev;
    struct evpl_listener_binding *next;
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
    struct evpl_thread            *thread;
    int                            running;
    struct evpl_doorbell           doorbell;
    struct evpl_bind             **binds;
    int                            num_binds;
    int                            max_binds;
    struct evpl_listen_request    *requests;
    struct evpl_listener_binding **attached;
    int                            num_attached;
    int                            max_attached;
    int                            rotor;
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

void
__evpl_init(
    void);



void
evpl_destroy_close_bind(
    struct evpl *evpl);

static inline void
evpl_activity(struct evpl *evpl)
{
    evpl->activity++;
} /* evpl_activity */

