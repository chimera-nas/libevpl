// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <liburing.h>
#include <stdatomic.h>
#include <string.h>
#include <utlist.h>

#include "core/allocator.h"
#include "core/event_fn.h"
#include "core/evpl.h"
#include "core/evpl_shared.h"
#include "core/protocol.h"

#define EVPL_IO_URING_BUFGROUP_ID            1

#define EVPL_IO_URING_REQ_TCP                1
#define EVPL_IO_URING_REQ_BLOCK              2

/* Capacity for the per-ring registered buffer table. Each slab is one entry.
 * Default slab size is 1 GiB, so 1024 entries == 1 TiB of registered memory.
 */
#define EVPL_IO_URING_MAX_REGISTERED_BUFFERS 1024

/* Capacity for the per-ring registered file (direct fd) table. Each accepted
 * socket consumes one entry; pick something well above max_pending.
 */
#define EVPL_IO_URING_MAX_REGISTERED_FILES   4096

struct evpl_io_uring_caps {
    unsigned have_register_ifq       : 1;
    unsigned have_op_recv_zc         : 1;
    unsigned have_op_send_zc         : 1;
    unsigned have_recvsend_bundle    : 1;
    unsigned have_recvsend_fixed_buf : 1;
    unsigned have_iosqe_fixed_file   : 1;
    unsigned have_register_buffers   : 1;
    unsigned have_register_files     : 1;
};

struct evpl_io_uring_effective {
    unsigned fixed_file : 1;
    unsigned fixed_buf  : 1;
    unsigned send_zc    : 1;
    unsigned recv_bundle: 1;
    unsigned zcrx       : 1;
};

#define evpl_io_uring_debug(...) evpl_debug("io_uring", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_io_uring_info(...)  evpl_info("io_uring", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_io_uring_error(...) evpl_error("io_uring", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_io_uring_fatal(...) evpl_fatal("io_uring", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_io_uring_abort(...) evpl_abort("io_uring", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_io_uring_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "io_uring", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_io_uring_abort_if(cond, ...) \
        evpl_abort_if(cond, "io_uring", __FILE__, __LINE__, __VA_ARGS__)

struct evpl_io_uring_reg_slab {
    void  *addr;
    size_t len;
};

struct evpl_io_uring_shared {
    struct io_uring               ring;
    pthread_mutex_t               buf_lock;
    unsigned int                  buf_count;
    struct evpl_io_uring_reg_slab buf_slabs[EVPL_IO_URING_MAX_REGISTERED_BUFFERS];
};

struct evpl_io_uring_socket;

struct evpl_io_uring_request {
    uint16_t                      req_type;
    uint8_t                       on_freelist;
    uint8_t                       _pad;
    int                           res;
    int                           flags;
    uint64_t                      cqe_extra[2]; /* CQE32 second 16 bytes */

    void                          (*callback)(
        struct evpl                  *evpl,
        struct evpl_io_uring_request *req);

    struct evpl_io_uring_request *next;

    union {
        struct {
            struct evpl_io_uring_socket *socket;
            uint32_t                     msgs_sent;
            uint8_t                      is_send_zc;
            uint8_t                      use_fixed_buf;
            uint16_t                     send_buffer_id;
            uint32_t                     sent_bytes;
            struct evpl_iovec            send_iov;
        } tcp;

        struct {
            int64_t      length;
            uint32_t     need_debounce;
            uint32_t     niov;
            struct iovec bounce_iov;
            void        *bounce;


            void         (*callback)(
                struct evpl *evpl,
                int          status,
                void        *private_data);
            void        *private_data;


            struct iovec iov[64];
        } block;
    };

};

struct evpl_io_uring_device {
    int fd;
};

struct evpl_io_uring_zcrx_frag {
    struct evpl_iovec_ref            ref;       /* must be first */
    struct evpl_io_uring_zcrx_state *zcrx;
    uint64_t                         area_off;  /* offset within area */
    uint32_t                         length;
    struct evpl_io_uring_zcrx_frag  *next;
};

struct evpl_io_uring_zcrx_state {
    void                           *area;
    size_t                          area_size;
    void                           *rq_ring;
    size_t                          rq_ring_size;
    uint32_t                       *rq_khead;
    uint32_t                       *rq_ktail;
    struct io_uring_zcrx_rqe       *rq_rqes;
    unsigned int                    rq_entries;
    unsigned int                    rq_mask;
    uint32_t                        zcrx_id;
    uint32_t                        napi_id;
    struct evpl_io_uring_zcrx_frag *free_frags;

    /* Cached rq_ktail. Frag releases write rqes and bump this value
     * with normal stores; we publish to the kernel-visible *rq_ktail
     * via a single atomic_store_release at poll-loop end (see
     * evpl_io_uring_zcrx_flush_tail). Collapses 256 release-fences
     * per 1 MiB recv segment down to 1.
     */
    uint32_t                        tail_cached;
};

struct evpl_io_uring_context {
    struct io_uring                  ring;
    int                              eventfd;
    int                              recv_ring_size;
    int                              recv_ring_mask;
    int                              recv_buffer_size;
    int                              next_send_group_id;
    uint64_t                        *recv_ring_iov_empty;
    struct evpl_iovec               *recv_ring_iov;
    struct evpl_event                event;
    struct evpl_deferral             flush;
    struct evpl_io_uring_request    *free_requests;
    struct io_uring_buf_ring        *recv_ring;
    struct evpl_poll                *poll;

    struct evpl_io_uring_caps        caps;
    struct evpl_io_uring_effective   effective;

    /* Registered buffers (FIXED_BUF) — slabs are registered into this
     * ring's table lazily on first use (see evpl_io_uring_ensure_buf
     * in pump). One bit per slab index; 1024 bits =
     * EVPL_IO_URING_MAX_REGISTERED_BUFFERS.
     */
    uint64_t                         buf_registered[
        (EVPL_IO_URING_MAX_REGISTERED_BUFFERS + 63) / 64];

    /* Registered files (FIXED_FILE) — direct-fd table */
    int                             *direct_fd_slot;
    unsigned int                     direct_fd_count;
    int                             *direct_fd_free;

    /* Scratch iovec array for evpl_io_uring_recv_deliver — sized to the
     * worst-case fragment count of any segment we've delivered. Grows
     * monotonically; freed at ctx teardown. Replaces the previous fixed-
     * cap alloca which overflowed when a single segment had more
     * fragments than max_num_iovec (e.g. 1 MiB segment over 4 KiB ZCRX
     * pages = 256 frags > 128 default).
     */
    struct evpl_iovec               *deliver_iov;
    unsigned int                     deliver_iov_capacity;
    unsigned int                     direct_fd_free_top;

    /* ZCRX state, valid only when effective.zcrx == 1 */
    struct evpl_io_uring_zcrx_state *zcrx;
};

struct evpl_io_uring_queue {
    struct evpl_io_uring_context *ctx;
    int                           fd;
    struct io_uring_sqe          *pending_sqe;
};

static inline int
evpl_io_uring_fill_recv_ring(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx)
{
    int i, j, k, m,  n, offset = 0;

    n = ctx->recv_ring_size >> 6;

    for (i = 0; i < n; i++) {

        while ((m = __builtin_ffsll(ctx->recv_ring_iov_empty[i])) > 0) {

            j = m - 1;

            k = (i << 6) + j;

            if (!(ctx->recv_ring_iov_empty[i] & (1ULL << j))) {
                continue;
            }

            evpl_iovec_alloc(evpl, ctx->recv_buffer_size, 4096, 1, 0, &ctx->recv_ring_iov[k]);

            io_uring_buf_ring_add(
                ctx->recv_ring,
                evpl_iovec_data(&ctx->recv_ring_iov[k]),
                evpl_iovec_length(&ctx->recv_ring_iov[k]),
                k,
                ctx->recv_ring_mask,
                offset);

            ctx->recv_ring_iov_empty[i] &= ~(1ULL << j);

            offset++;
        }
    }

    return offset;

} /* evpl_io_uring_fill_recv_ring */


static inline struct evpl_io_uring_request *
evpl_io_uring_request_alloc(
    struct evpl_io_uring_context *ctx,
    int                           req_type)
{
    struct evpl_io_uring_request *req;

    req = ctx->free_requests;

    if (req) {
        LL_DELETE(ctx->free_requests, req);
    } else {
        req = evpl_zalloc(sizeof(*req));
    }

    req->req_type    = req_type;
    req->on_freelist = 0;

    switch (req_type) {
        case EVPL_IO_URING_REQ_TCP:
            req->tcp.socket          = NULL;
            req->tcp.msgs_sent       = 0;
            req->tcp.is_send_zc      = 0;
            req->tcp.use_fixed_buf   = 0;
            req->tcp.send_buffer_id  = 0;
            req->tcp.sent_bytes      = 0;
            req->tcp.send_iov.data   = NULL;
            req->tcp.send_iov.length = 0;
            req->tcp.send_iov.ref    = NULL;
            break;
        case EVPL_IO_URING_REQ_BLOCK:
            req->block.bounce        = NULL;
            req->block.need_debounce = 0;
            break;
    } /* switch */

    return req;
} /* evpl_io_uring_request_alloc */

static inline void
evpl_io_uring_request_free(
    struct evpl_io_uring_context *ctx,
    struct evpl_io_uring_request *req)
{
    if (req->on_freelist) {
        return;
    }
    req->on_freelist = 1;
    LL_PREPEND(ctx->free_requests, req);
} /* evpl_io_uring_request_free */

/* Test whether slab index N has been registered into this ring's
 * FIXED_BUF table.
 */
static inline int
evpl_io_uring_buf_is_registered(
    const struct evpl_io_uring_context *ctx,
    unsigned int                        idx)
{
    return (ctx->buf_registered[idx >> 6] & (1ULL << (idx & 63))) != 0;
} // evpl_io_uring_buf_is_registered

/* Register a specific slab into this ring's FIXED_BUF table on first use.
 * Returns 1 on success (or already registered), 0 if registration failed
 * (caller falls back to the legacy non-FIXED send path). The first call
 * for a given slab pins its pages (an O(slab_size) blocking syscall);
 * subsequent calls are O(1) via the buf_registered bitmap.
 */
static inline int
evpl_io_uring_ensure_buf_registered(
    struct evpl_io_uring_context *ctx,
    unsigned int                  idx)
{
#ifdef HAVE_IO_URING_REGISTER_BUFFERS_SPARSE
    struct evpl_io_uring_shared *shared;
    struct iovec                 iov;
    int                          rc;

    if (evpl_io_uring_buf_is_registered(ctx, idx)) {
        return 1;
    }

    shared = evpl_shared->framework_private[EVPL_FRAMEWORK_IO_URING];
    if (!shared || idx >= shared->buf_count) {
        return 0;
    }

    iov.iov_base = shared->buf_slabs[idx].addr;
    iov.iov_len  = shared->buf_slabs[idx].len;

    rc = io_uring_register_buffers_update_tag(&ctx->ring, idx, &iov, NULL, 1);

    if (rc < 0) {
        evpl_io_uring_info(
            "io_uring_register_buffers_update_tag(idx=%u) failed: %s — "
            "disabling fixed_buf for this ring (check RLIMIT_MEMLOCK)",
            idx, strerror(-rc));
        ctx->effective.fixed_buf = 0;
        ctx->effective.send_zc   = 0;
        return 0;
    }

    ctx->buf_registered[idx >> 6] |= (1ULL << (idx & 63));
    return 1;
#else /* HAVE_IO_URING_REGISTER_BUFFERS_SPARSE */
    (void) ctx; (void) idx;
    return 0;
#endif // ifdef HAVE_IO_URING_REGISTER_BUFFERS_SPARSE
} // evpl_io_uring_ensure_buf_registered

/* Resolve an evpl_iovec to a (buf_index, offset) for IORING_RECVSEND_FIXED_BUF.
 * Returns 1 on success, 0 if the iovec is not backed by a registered slab.
 */
static inline int
evpl_io_uring_iov_to_fixed(
    const struct evpl_iovec *iov,
    unsigned int            *buf_index,
    uint64_t                *offset)
{
    struct evpl_io_uring_shared *shared = evpl_shared->framework_private[
        EVPL_FRAMEWORK_IO_URING];
    void                        *fp;
    unsigned int                 idx;

    if (!shared) {
        return 0;
    }

    fp = evpl_memory_framework_private(iov, EVPL_FRAMEWORK_IO_URING);

    if (!fp) {
        return 0;
    }

    idx = (unsigned int) ((uintptr_t) fp - 1);

    if (idx >= shared->buf_count) {
        return 0;
    }

    *buf_index = idx;
    *offset    = (uint64_t) ((uintptr_t) iov->data -
                             (uintptr_t) shared->buf_slabs[idx].addr);
    return 1;
} // evpl_io_uring_iov_to_fixed
