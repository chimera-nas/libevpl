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
#include "wakeup.h"
#include "evpl/evpl.h"


#include "core/core.h"

struct evpl_thread_config {
    int          poll_mode;
    int          poll_iterations;
    unsigned int spin_ns;
    int          wait_ms;

};

/*
 * Default ceiling on one RPC2 message, counted over every fragment of a record.
 *
 * The record mark is unauthenticated input: a peer can claim any length it
 * likes before sending a byte of it.  Without a ceiling the transport keeps
 * buffering whatever the claim asks for, so a single connection can be made to
 * consume memory without bound.  Capping it means an oversized claim is refused
 * at the framing layer, before anything is allocated for it.
 *
 * 4 MiB is comfortably above realistic RPC traffic -- NFS rsize/wsize is
 * typically 1 MiB, and the payload for a large READ/WRITE travels in RDMA
 * chunks rather than inline -- while staying small enough that the worst case
 * per connection is bounded.
 */
#define EVPL_DEFAULT_RPC2_MAX_MESSAGE_SIZE (4U * 1024U * 1024U)

/*
 * Read the configured RPC2 message ceiling.
 *
 * rpc2 builds as its own shared object and so cannot reach the evpl_shared
 * global directly; this is the exported accessor it uses.  Internal rather
 * than public API: the value is set through
 * evpl_global_config_set_rpc2_max_message_size() like every other knob.
 */
unsigned int
evpl_config_rpc2_max_message_size(
    void);

struct evpl_global_config {

    struct evpl_thread_config thread_default;

    unsigned int              core_mech;

    unsigned int              hf_time_mode;
    unsigned int              virtual_clock;
    unsigned int              max_pending;
    unsigned int              max_poll_fd;
    unsigned int              max_num_iovec;
    unsigned int              buffer_size;
    unsigned int              huge_pages;
    uint64_t                  huge_page_size;
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
    unsigned int              io_uring_entries;

    unsigned int              rdmacm_enabled;
    unsigned int              rdmacm_tos;
    unsigned int              rdmacm_max_sge;
    unsigned int              rdmacm_cq_size;
    unsigned int              rdmacm_sq_size;
    unsigned int              rdmacm_datagram_size_override;
    unsigned int              rdmacm_srq_size;
    unsigned int              rdmacm_srq_min;
    unsigned int              rdmacm_max_inline;
    unsigned int              rdmacm_srq_batch;
    unsigned int              rdmacm_srq_prefill;
    unsigned int              rdmacm_retry_count;
    unsigned int              rdmacm_rnr_retry_count;

    unsigned int              xlio_enabled;

    unsigned int              vfio_enabled;

    unsigned int              libaio_enabled;
    unsigned int              libaio_max_pending;

    unsigned int              preallocate_slabs;
    unsigned int              preallocate_threads;

    unsigned int              rpc2_max_message_size;

    char                     *tls_cert_file;
    char                     *tls_key_file;
    char                     *tls_ca_file;
    char                     *tls_cipher_list;
    int                       tls_verify_peer;
    int                       tls_ktls_enabled;

    unsigned int              http_max_header_size;
};

/* Read the configured HTTP header block limit from the live global config.
 * Exported so the http module (a separate library that cannot see the
 * hidden evpl_shared symbol) can fetch it at agent init. */
unsigned int
evpl_global_config_get_http_max_header_size(
    void);

typedef void (*evpl_accept_callback_t)(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *remote_addr,
    void                *accepted,
    void                *private_data);

struct evpl {
    struct evpl_core              core; /* must be first */

    uint64_t                      poll_iters;

    uint64_t                      last_activity_ticks;
    uint64_t                      spin_ticks;
    uint64_t                      activity;
    uint64_t                      last_activity;
    uint64_t                      poll_iterations;

    struct evpl_poll             *poll;
    int                           num_poll;
    int                           max_poll;

    struct evpl_wakeup            run_wakeup;
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
    int                           poll_pin_count;

    struct evpl_doorbell         *doorbells;


    struct evpl_timer           **timers;
    int                           num_timers;
    int                           max_timers;

    struct evpl_deferral        **active_deferrals;
    int                           num_active_deferrals;
    int                           max_active_deferrals;

    struct evpl_buffer           *current_buffer;
    struct evpl_buffer           *shared_buffer;
    struct evpl_buffer           *datagram_buffer;
    struct evpl_buffer           *free_local_buffers;
    struct evpl_buffer           *free_shared_buffers;
    struct evpl_buffer           *free_shared_buffers_tail;
    struct evpl_buffer           *free_shared_buffers_low_prev;
    struct evpl_buffer           *free_shared_buffers_low_head;
    int                           free_shared_buffer_count;
    struct evpl_bind             *free_binds;
    struct evpl_bind             *binds;
    struct evpl_bind             *pending_close_binds;

    struct evpl_listener_binding *listener_bindings;

    struct evpl_thread_config     config;

    struct evpl_loop_hooks        loop_hooks;

    void                         *protocol_private[EVPL_NUM_PROTO];
    void                         *framework_private[EVPL_NUM_FRAMEWORK];
};

struct evpl_listen_request {
    enum evpl_protocol_id protocol_id;
    pthread_mutex_t             lock;
    pthread_cond_t              cond;
    int                         complete;
    /* Result of the protocol's listen callback, carried back to the thread
     * blocked in evpl_listen().  The bind happens on the listener thread, so
     * this is the only channel a backend failure has. */
    int                         status;
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
void * evpl_realloc(
    void        *p,
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

/* Exported (defined in poll.c); also declared in the public evpl/evpl_poll.h so
 * out-of-tree consumers can use them.  See evpl_poll.h for semantics. */
void
evpl_activity(
    struct evpl *evpl);

void
evpl_poll_pin(
    struct evpl *evpl);

void
evpl_poll_unpin(
    struct evpl *evpl);

