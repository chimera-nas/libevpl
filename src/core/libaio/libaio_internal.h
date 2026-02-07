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
    int                         max_pending;
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
