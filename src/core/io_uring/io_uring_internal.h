// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <liburing.h>
#include <utlist.h>

#include "core/event_fn.h"
#include "core/evpl.h"
#include "core/protocol.h"

#define EVPL_IO_URING_BUFGROUP_ID 1

#define EVPL_IO_URING_REQ_TCP     1
#define EVPL_IO_URING_REQ_BLOCK   2

#define evpl_io_uring_debug(...) evpl_debug("io_uring", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_io_uring_info(...)  evpl_info("io_uring", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_io_uring_error(...) evpl_error("io_uring", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_io_uring_fatal(...) evpl_fatal("io_uring", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_io_uring_abort(...) evpl_abort("io_uring", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_io_uring_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "io_uring", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_io_uring_abort_if(cond, ...) \
        evpl_abort_if(cond, "io_uring", __FILE__, __LINE__, __VA_ARGS__)

struct evpl_io_uring_shared {
    struct io_uring ring;
};

struct evpl_io_uring_socket;

struct evpl_io_uring_request {
    uint16_t                      req_type;
    int                           res;
    int                           flags;

    void                          (*callback)(
        struct evpl                  *evpl,
        struct evpl_io_uring_request *req);

    struct evpl_io_uring_request *next;

    union {
        struct {
            struct evpl_io_uring_socket *socket;
            uint32_t                     msgs_sent;

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

struct evpl_io_uring_context {
    struct io_uring               ring;
    int                           eventfd;
    int                           recv_ring_size;
    int                           recv_ring_mask;
    int                           recv_buffer_size;
    int                           next_send_group_id;
    uint64_t                     *recv_ring_iov_empty;
    struct evpl_iovec            *recv_ring_iov;
    struct evpl_event             event;
    struct evpl_deferral          flush;
    struct evpl_io_uring_request *free_requests;
    struct io_uring_buf_ring     *recv_ring;
    struct evpl_poll             *poll;
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

    req->req_type = req_type;

    switch (req_type) {
        case EVPL_IO_URING_REQ_TCP:
            req->tcp.socket = NULL;
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
    LL_PREPEND(ctx->free_requests, req);
} /* evpl_io_uring_request_free */
