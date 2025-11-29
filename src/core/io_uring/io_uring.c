// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdatomic.h>
#include <unistd.h>

#include "io_uring_internal.h"

#include "core/io_uring/io_uring.h"
#include "core/poll.h"

static void
evpl_io_uring_flush_sqe(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;

    unsigned int                  flags = atomic_load_explicit((_Atomic unsigned int *) &ctx->ring.flags,
                                                               memory_order_relaxed);

    if (flags & IORING_SQ_NEED_WAKEUP) {
        io_uring_enter(ctx->ring.ring_fd, 0, 0, IORING_ENTER_SQ_WAKEUP, NULL);
        evpl_io_uring_info("had to wake up the kernel sqpoll thread");
    }

    io_uring_submit(&ctx->ring);
} /* evpl_io_uring_flush */


static void *
evpl_io_uring_init(void)
{
    struct evpl_io_uring_shared *shared;
    struct io_uring_params       params;
    int                          rc;

    memset(&params, 0, sizeof(params));

    params.flags         |= IORING_SETUP_SQPOLL;
    params.sq_thread_idle = 1000;

    shared = evpl_zalloc(sizeof(*shared));

    rc = io_uring_queue_init_params(256, &shared->ring, &params);

    if (rc < 0) {
        evpl_free(shared);
        return NULL;
    }

    return shared;
} /* evpl_io_uring_init */

static void
evpl_io_uring_cleanup(void *private_data)
{
    struct evpl_io_uring_shared *shared = private_data;

    io_uring_queue_exit(&shared->ring);

    evpl_free(shared);

} /* evpl_io_uring_cleanup */

static inline int
evpl_io_uring_complete(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx)
{
    uint64_t                      debounce_offset;
    struct evpl_io_uring_request *req;
    int                           buf_count = 0, cq_count = 0;
    struct io_uring_cqe          *cqes[64], *cqe;

    cq_count = io_uring_peek_batch_cqe(&ctx->ring, cqes, 64);

    for (int i = 0; i < cq_count; i++) {
        cqe =   cqes[i];

        req = (struct evpl_io_uring_request *) io_uring_cqe_get_data64(cqe);

        req->res   = cqe->res;
        req->flags = cqe->flags;

        if (req->res < 0) {
            evpl_io_uring_error("io_uring_complete res %d", req->res);
        }

        switch (req->req_type) {
            case EVPL_IO_URING_REQ_BLOCK:

                if (req->block.need_debounce) {
                    debounce_offset = 0;

                    for (int i = 0; i < req->block.niov; i++) {
                        memcpy(req->block.iov[i].iov_base, req->block.bounce + debounce_offset, req->block.iov[i].
                               iov_len);
                        debounce_offset += req->block.iov[i].iov_len;
                    }
                }

                req->callback(evpl, req);

                if (req->block.bounce) {
                    evpl_free(req->block.bounce);
                }
                break;
            case EVPL_IO_URING_REQ_TCP:
                req->callback(evpl, req);
                break;
        } /* switch */

        if (!(cqe->flags & IORING_CQE_F_MORE)) {
            evpl_io_uring_request_free(ctx, req);
        }
    }

    if (cq_count) {

        buf_count = evpl_io_uring_fill_recv_ring(evpl, ctx);

        //__io_uring_buf_ring_cq_advance(&ctx->ring, ctx->recv_ring, cq_count, buf_count);

        io_uring_buf_ring_advance(ctx->recv_ring, buf_count);
        io_uring_cq_advance(&ctx->ring, cq_count);

        evpl_activity(evpl);
    }

    return cq_count;
} /* evpl_io_uring_complete */

static void
evpl_io_uring_poll_enter(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;

    io_uring_unregister_eventfd(&ctx->ring);
    evpl_io_uring_complete(evpl, ctx);
} /* evpl_io_uring_poll_enter */

static void
evpl_io_uring_poll_exit(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;

    io_uring_register_eventfd(&ctx->ring, ctx->eventfd);
    evpl_io_uring_complete(evpl, ctx);
} /* evpl_io_uring_poll_exit */

static void
evpl_io_uring_poll(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;

    evpl_io_uring_complete(evpl, ctx);
} /* evpl_io_uring_poll */

static void
evpl_io_uring_complete_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    uint64_t                      value;
    int                           rc, n;

    rc = read(ctx->eventfd, &value, sizeof(value));

    if (rc != sizeof(value)) {
        evpl_event_mark_unreadable(evpl, &ctx->event);
        return;
    }

    do {
        n = evpl_io_uring_complete(evpl, ctx);
    } while (n);
} /* evpl_io_uring_complete */

static void *
evpl_io_uring_create(
    struct evpl *evpl,
    void        *private_data)
{
    //struct evpl_io_uring_shared  *shared = private_data;
    struct evpl_io_uring_context *ctx;
    int                           ret;
    struct io_uring_params        params;
    int                           sqpoll = 1;

    memset(&params, 0, sizeof(params));

    params.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_SQE128 | IORING_SETUP_CQE32;

    if (sqpoll) {
        params.flags |= IORING_SETUP_SQPOLL;

        params.sq_thread_idle = 1000;
    } else {
        //params.flags |= IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
        params.flags |= IORING_SETUP_DEFER_TASKRUN;
    }

#if 0
    params.flags |= IORING_SETUP_ATTACH_WQ;
    params.wq_fd  = shared->ring.ring_fd;
    #endif /* if 0 */

    ctx = evpl_zalloc(sizeof(*ctx));

    ctx->next_send_group_id = EVPL_IO_URING_BUFGROUP_ID + 1;

    ret = io_uring_queue_init_params(8192, &ctx->ring, &params);

    evpl_io_uring_abort_if(ret < 0, "io_uring_queue_init_params() failed: %s (%d)", strerror(-ret), ret);

    ctx->eventfd = eventfd(0, EFD_NONBLOCK);

    evpl_io_uring_abort_if(ctx->eventfd < 0, "eventfd");

    io_uring_register_eventfd(&ctx->ring, ctx->eventfd);

    evpl_add_event(evpl, &ctx->event, ctx->eventfd,
                   evpl_io_uring_complete_event, NULL, NULL);

    evpl_event_read_interest(evpl, &ctx->event);

    evpl_deferral_init(&ctx->flush, evpl_io_uring_flush_sqe, ctx);

    ctx->recv_ring_size   = 8192;
    ctx->recv_buffer_size = 2 * 1024 * 1024;

    ctx->recv_ring = io_uring_setup_buf_ring(&ctx->ring, ctx->recv_ring_size,
                                             EVPL_IO_URING_BUFGROUP_ID,
                                             0, &ret);

    ctx->recv_ring_mask = io_uring_buf_ring_mask(ctx->recv_ring_size);

    ctx->recv_ring_iov_empty = evpl_zalloc((ctx->recv_ring_size / 64) * sizeof(uint64_t));
    memset(ctx->recv_ring_iov_empty, 0xff, (ctx->recv_ring_size / 64) * sizeof(uint64_t));

    ctx->recv_ring_iov = evpl_zalloc(ctx->recv_ring_size * sizeof(struct evpl_iovec));

    evpl_io_uring_abort_if(ret < 0, "io_uring_setup_buf_ring");

    ctx->poll = evpl_add_poll(evpl, evpl_io_uring_poll_enter, evpl_io_uring_poll_exit, evpl_io_uring_poll, ctx);

    return ctx;
} /* evpl_io_uring_create */

static void
evpl_io_uring_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;
    struct evpl_io_uring_request *req;
    int                           n;

    while (ctx->free_requests) {
        req = ctx->free_requests;
        LL_DELETE(ctx->free_requests, req);
        evpl_free(req);
    }

    n = evpl_io_uring_fill_recv_ring(evpl, ctx);

    if (n) {
        io_uring_buf_ring_advance(ctx->recv_ring, n);
    }

    io_uring_free_buf_ring(&ctx->ring, ctx->recv_ring, ctx->recv_ring_size, 0);

    io_uring_queue_exit(&ctx->ring);

    close(ctx->eventfd);

    evpl_iovecs_release(ctx->recv_ring_iov, ctx->recv_ring_size);

    evpl_free(ctx->recv_ring_iov_empty);
    evpl_free(ctx->recv_ring_iov);

    evpl_free(ctx);
} /* evpl_io_uring_destroy */

struct evpl_framework evpl_framework_io_uring = {
    .id      = EVPL_FRAMEWORK_IO_URING,
    .name    = "IO_URING",
    .init    = evpl_io_uring_init,
    .cleanup = evpl_io_uring_cleanup,
    .create  = evpl_io_uring_create,
    .destroy = evpl_io_uring_destroy,
};