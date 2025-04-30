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
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    uint64_t                      value, debounce_offset;
    int                           rc;
    struct io_uring_cqe          *cqe;
    struct evpl_io_uring_request *req;

    evpl_io_uring_debug("io_uring_complete");

    rc = read(ctx->eventfd, &value, sizeof(value));

    if (rc != sizeof(value)) {
        evpl_event_mark_unreadable(evpl, &ctx->event);
        return;
    }

    while (io_uring_peek_cqe(&ctx->ring, &cqe) == 0) {
        req = (struct evpl_io_uring_request *) io_uring_cqe_get_data64(cqe);

        if (cqe->res >= 0 && cqe->res !=  req->length) {
            rc = EIO;
        } else if (cqe->res < 0) {
            rc = -cqe->res;
        } else {
            rc = 0;
        }

        if (req->need_debounce) {
            debounce_offset = 0;

            for (int i = 0; i < req->niov; i++) {
                memcpy(req->iov[i].iov_base, req->block.bounce + debounce_offset, req->iov[i].iov_len);
                debounce_offset += req->iov[i].iov_len;
            }
        }

        req->callback(evpl, rc, req->private_data);

        if (req->block.bounce) {
            evpl_free(req->block.bounce);
        }

        io_uring_cqe_seen(&ctx->ring, cqe);

        evpl_io_uring_request_free(ctx, req);
    } /* evpl_io_uring_complete */


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

    evpl_io_uring_debug("io_uring_create");


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
                   evpl_io_uring_complete, NULL, NULL);

    evpl_event_read_interest(evpl, &ctx->event);

    evpl_deferral_init(&ctx->flush, evpl_io_uring_flush_sqe, ctx);

    return ctx;
} /* evpl_io_uring_create */

static void
evpl_io_uring_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;
    struct evpl_io_uring_request *req;

    while (ctx->free_requests) {
        req = ctx->free_requests;
        LL_DELETE(ctx->free_requests, req);
        evpl_free(req);
    }

    io_uring_queue_exit(&ctx->ring);

    close(ctx->eventfd);

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