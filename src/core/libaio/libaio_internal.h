// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <libaio.h>
#include <utlist.h>

#include "core/event_fn.h"
#include "core/evpl.h"
#include "core/protocol.h"

#define evpl_libaio_debug(...) evpl_debug("libaio", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_libaio_info(...)  evpl_info("libaio", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_libaio_error(...) evpl_error("libaio", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_libaio_fatal(...) evpl_fatal("libaio", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_libaio_abort(...) evpl_abort("libaio", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_libaio_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "libaio", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_libaio_abort_if(cond, ...) \
        evpl_abort_if(cond, "libaio", __FILE__, __LINE__, __VA_ARGS__)

struct evpl_libaio_request {
    struct iocb                 iocb;
    int                         res;

    void                        (*callback)(
        struct evpl *evpl,
        int          status,
        void        *private_data);
    void                       *private_data;

    int64_t                     length;
    uint32_t                    need_debounce;
    uint32_t                    niov;
    struct iovec                bounce_iov;
    void                       *bounce;
    struct iovec                iov[64];

    struct evpl_libaio_request *next;
};

struct evpl_libaio_context {
    io_context_t                io_ctx;
    int                         eventfd;
    struct evpl_event           event;
    struct evpl_deferral        flush;
    struct evpl_libaio_request *free_requests;
    struct iocb               **pending_iocbs;
    int                         max_pending;      /* aio ring depth (io_setup nr_events) */
    int                         pending_capacity; /* allocated slots in pending_iocbs */
    int                         num_pending;
    struct evpl_poll           *poll;
};

struct evpl_libaio_device {
    int fd;
};

static inline struct evpl_libaio_request *
evpl_libaio_request_alloc(struct evpl_libaio_context *ctx)
{
    struct evpl_libaio_request *req;

    req = ctx->free_requests;

    if (req) {
        LL_DELETE(ctx->free_requests, req);
    } else {
        req = evpl_zalloc(sizeof(*req));
    }

    req->bounce        = NULL;
    req->need_debounce = 0;

    return req;
} /* evpl_libaio_request_alloc */

static inline void
evpl_libaio_request_free(
    struct evpl_libaio_context *ctx,
    struct evpl_libaio_request *req)
{
    LL_PREPEND(ctx->free_requests, req);
} /* evpl_libaio_request_free */

/*
 * Stage an iocb for the next deferred io_submit().
 *
 * The staging array is not the ring.  evpl_defer() only arms the flush, so
 * nothing submits or completes until the current callback chain returns: a
 * caller that issues a batch in one event-loop iteration stages all of it
 * first.  Callers legitimately exceed the ring depth doing so -- diskfs' tail
 * pusher caps home writes per device, so its in-flight budget is (per-device
 * cap x device count) -- which makes a full staging array ordinary
 * backpressure rather than a caller error.
 *
 * Grow instead of failing, and let evpl_libaio_flush_submit() feed the ring at
 * its own depth.  Draining is already handled: a short or -EAGAIN io_submit()
 * keeps its unsubmitted tail queued, and evpl_libaio_complete() re-arms this
 * deferral after any completion batch, so the surplus always goes out.
 */
static inline void
evpl_libaio_enqueue(
    struct evpl                *evpl,
    struct evpl_libaio_context *ctx,
    struct evpl_libaio_request *req)
{
    if (ctx->num_pending == ctx->pending_capacity) {
        ctx->pending_capacity *= 2;

        ctx->pending_iocbs = evpl_realloc(ctx->pending_iocbs,
                                          ctx->pending_capacity *
                                          sizeof(struct iocb *));
    }

    ctx->pending_iocbs[ctx->num_pending++] = &req->iocb;

    evpl_defer(evpl, &ctx->flush);
} /* evpl_libaio_enqueue */
