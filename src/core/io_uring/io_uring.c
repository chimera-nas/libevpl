#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "io_uring_internal.h"

#include "core/io_uring/io_uring.h"

static void
evpl_io_uring_flush_sqe(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;

    io_uring_submit(&ctx->ring);
} /* evpl_io_uring_flush */


static void *
evpl_io_uring_init(void)
{
    struct evpl_io_uring_shared *shared;
    struct io_uring_params       params = { 0 };

    shared = evpl_zalloc(sizeof(*shared));

    io_uring_queue_init_params(256, &shared->ring, &params);

    return shared;
} /* evpl_io_uring_init */

static void
evpl_io_uring_cleanup(void *private_data)
{
    struct evpl_io_uring_shared *shared = private_data;

    io_uring_queue_exit(&shared->ring);

    evpl_free(shared);

} /* evpl_io_uring_cleanup */

static void
evpl_io_uring_complete(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx)
{
    uint64_t                      debounce_offset;
    struct io_uring_cqe          *cqe;
    struct evpl_io_uring_request *req;


    while (io_uring_peek_cqe(&ctx->ring, &cqe) == 0) {
        req = (struct evpl_io_uring_request *) io_uring_cqe_get_data64(cqe);

        req->res   = cqe->res;
        req->flags = cqe->flags;

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

        io_uring_cqe_seen(&ctx->ring, cqe);

        if (!(cqe->flags & IORING_CQE_F_MORE)) {
            evpl_io_uring_request_free(ctx, req);
        }
    }

    evpl_io_uring_fill_recv_ring(evpl, ctx);


} /* evpl_io_uring_complete */


static void
evpl_io_uring_complete_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    uint64_t                      value;
    int                           rc;

    rc = read(ctx->eventfd, &value, sizeof(value));

    if (rc != sizeof(value)) {
        evpl_event_mark_unreadable(evpl, &ctx->event);
        return;
    }

    evpl_io_uring_complete(evpl, ctx);
} /* evpl_io_uring_complete */

static void *
evpl_io_uring_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_shared  *shared = private_data;
    struct evpl_io_uring_context *ctx;
    int                           ret;
    struct io_uring_params        params = { 0 };

    params.flags  = IORING_SETUP_SINGLE_ISSUER;
    params.flags |= IORING_SETUP_COOP_TASKRUN;

    params.flags |= IORING_SETUP_ATTACH_WQ;
    params.wq_fd  = shared->ring.ring_fd;

    ctx = evpl_zalloc(sizeof(*ctx));

    ret = io_uring_queue_init_params(8192, &ctx->ring, &params);

    evpl_io_uring_abort_if(ret < 0, "io_uring_queue_init");

    ctx->eventfd = eventfd(0, EFD_NONBLOCK);

    evpl_io_uring_abort_if(ctx->eventfd < 0, "eventfd");

    io_uring_register_eventfd(&ctx->ring, ctx->eventfd);

    evpl_add_event(evpl, &ctx->event, ctx->eventfd,
                   evpl_io_uring_complete_event, NULL, NULL);

    evpl_event_read_interest(evpl, &ctx->event);

    evpl_deferral_init(&ctx->flush, evpl_io_uring_flush_sqe, ctx);

    ctx->recv_ring_size = 1024;

    ctx->recv_ring = io_uring_setup_buf_ring(&ctx->ring, ctx->recv_ring_size,
                                             EVPL_IO_URING_BUFGROUP_ID,
                                             0, &ret);

    ctx->recv_ring_mask = io_uring_buf_ring_mask(ctx->recv_ring_size);

    ctx->recv_ring_iov_empty = evpl_zalloc((ctx->recv_ring_size / 64) * sizeof(uint64_t));
    memset(ctx->recv_ring_iov_empty, 0xff, (ctx->recv_ring_size / 64) * sizeof(uint64_t));

    ctx->recv_ring_iov = evpl_zalloc(ctx->recv_ring_size * sizeof(struct evpl_iovec));

    evpl_io_uring_abort_if(ret < 0, "io_uring_setup_buf_ring");

    return ctx;
} /* evpl_io_uring_create */

static void
evpl_io_uring_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;
    struct evpl_io_uring_request *req;
    int                           i;

    while (ctx->free_requests) {
        req = ctx->free_requests;
        LL_DELETE(ctx->free_requests, req);
        evpl_free(req);
    }

    evpl_io_uring_fill_recv_ring(evpl, ctx);

    io_uring_free_buf_ring(&ctx->ring, ctx->recv_ring, ctx->recv_ring_size, 0);

    io_uring_queue_exit(&ctx->ring);

    close(ctx->eventfd);

    for (i = 0; i < ctx->recv_ring_size; i++) {
        evpl_iovec_release(&ctx->recv_ring_iov[i]);
    }

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