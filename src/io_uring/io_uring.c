#define _GNU_SOURCE
#include <string.h>
#include <liburing.h>
#include <sys/eventfd.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>

#include "utlist.h"

#include "core/internal.h"
#include "core/evpl.h"
#include "core/event.h"
#include "core/protocol.h"
#include "core/deferral.h"
#include "io_uring/io_uring.h"

#define evpl_io_uring_debug(...) evpl_debug("io_uring", __VA_ARGS__)
#define evpl_io_uring_info(...)  evpl_info("io_uring", __VA_ARGS__)
#define evpl_io_uring_error(...) evpl_error("io_uring", __VA_ARGS__)
#define evpl_io_uring_fatal(...) evpl_fatal("io_uring", __VA_ARGS__)
#define evpl_io_uring_abort(...) evpl_abort("io_uring", __VA_ARGS__)

#define evpl_io_uring_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "io_uring", __VA_ARGS__)

#define evpl_io_uring_abort_if(cond, ...) \
        evpl_abort_if(cond, "io_uring", __VA_ARGS__)

struct evpl_io_uring_request {
    void                          (*callback)(
        int64_t status,
        void   *private_data);
    void                         *private_data;
    int                           niov;
    struct iovec                  iov[64];
    struct evpl_io_uring_request *next;
};

struct evpl_io_uring_device {
    int fd;
};

struct evpl_io_uring_context {
    struct io_uring               ring;
    int                           eventfd;
    struct evpl_event             event;
    struct evpl_deferral          flush;
    struct evpl_io_uring_request *free_requests;
};

struct evpl_io_uring_queue {
    struct evpl_io_uring_context *ctx;
    int                           fd;
    struct io_uring_sqe          *pending_sqe;
};

static struct evpl_io_uring_request *
evpl_io_uring_request_alloc(struct evpl_io_uring_context *ctx)
{
    struct evpl_io_uring_request *req;

    req = ctx->free_requests;

    if (req) {
        ctx->free_requests = req->next;
        LL_DELETE(ctx->free_requests, req);
    } else {
        req = evpl_zalloc(sizeof(*req));
    }

    return req;
} /* evpl_io_uring_request_alloc */

static void
evpl_io_uring_request_free(
    struct evpl_io_uring_context *ctx,
    struct evpl_io_uring_request *req)
{
    LL_APPEND(ctx->free_requests, req);
} /* evpl_io_uring_request_free */

static void *
evpl_io_uring_init(void)
{
    return NULL;
} /* evpl_io_uring_init */

static void
evpl_io_uring_cleanup(void *private_data)
{
} /* evpl_io_uring_cleanup */

static void
evpl_io_uring_flush_sqe(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;

    io_uring_submit(&ctx->ring);
} /* evpl_io_uring_flush */

static void
evpl_io_uring_complete(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    uint64_t                      value;
    int                           rc;
    struct io_uring_cqe          *cqe;
    struct evpl_io_uring_request *req;

    rc = read(ctx->eventfd, &value, sizeof(value));

    if (rc != sizeof(value)) {
        evpl_event_mark_unreadable(&ctx->event);
        return;
    }

    while (io_uring_peek_cqe(&ctx->ring, &cqe) == 0) {
        req = (struct evpl_io_uring_request *) io_uring_cqe_get_data64(cqe);

        req->callback(cqe->res, req->private_data);

        io_uring_cqe_seen(&ctx->ring, cqe);

        evpl_io_uring_request_free(ctx, req);
    }


} /* evpl_io_uring_complete */

static void *
evpl_io_uring_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx;
    int                           ret;

    ctx = evpl_zalloc(sizeof(*ctx));

    ret = io_uring_queue_init(256, &ctx->ring, 0);

    evpl_io_uring_abort_if(ret < 0, "io_uring_queue_init");

    ctx->eventfd = eventfd(0, EFD_NONBLOCK);

    evpl_io_uring_abort_if(ctx->eventfd < 0, "eventfd");

    io_uring_register_eventfd(&ctx->ring, ctx->eventfd);

    ctx->event.fd            = ctx->eventfd;
    ctx->event.read_callback = evpl_io_uring_complete;

    evpl_add_event(evpl, &ctx->event);

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

static void
evpl_io_uring_read(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    void ( *callback )(int64_t status, void *private_data),
    void *private_data)
{
    struct evpl_io_uring_device  *dev = queue->private_data;
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *req;
    struct io_uring_sqe          *sqe;
    int                           i;

    req = evpl_io_uring_request_alloc(ctx);

    req->callback     = callback;
    req->private_data = private_data;
    req->niov         = niov;

    for (i = 0; i < niov; i++) {
        req->iov[i].iov_base = iov[i].data;
        req->iov[i].iov_len  = iov[i].length;
    }

    sqe = io_uring_get_sqe(&ctx->ring);

    evpl_io_uring_abort_if(!sqe, "io_uring_get_sqe");

    io_uring_sqe_set_data64(sqe, (uint64_t) req);

    io_uring_prep_readv(sqe, dev->fd, req->iov, req->niov, offset);

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_read */

static void
evpl_io_uring_write(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    int sync,
    void ( *callback )(int64_t status, void *private_data),
    void *private_data)
{
    struct evpl_io_uring_device  *dev = queue->private_data;
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct io_uring_sqe          *sqe;
    struct evpl_io_uring_request *req;
    int                           i, flags = 0;

    if (sync) {
        flags |= RWF_SYNC;
    }

    req = evpl_io_uring_request_alloc(ctx);

    req->callback     = callback;
    req->private_data = private_data;
    req->niov         = niov;

    for (i = 0; i < niov; i++) {
        req->iov[i].iov_base = iov[i].data;
        req->iov[i].iov_len  = iov[i].length;
    }

    sqe = io_uring_get_sqe(&ctx->ring);

    evpl_io_uring_abort_if(!sqe, "io_uring_get_sqe");

    io_uring_sqe_set_data64(sqe, (uint64_t) req);

    io_uring_prep_writev2(sqe, dev->fd, req->iov, req->niov, offset, flags);

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_write */

static void
evpl_io_uring_flush(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    void ( *callback )(int64_t status, void *private_data),
    void *private_data)
{
    struct evpl_io_uring_device  *dev = queue->private_data;
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *req;
    struct io_uring_sqe          *sqe;

    req = evpl_io_uring_request_alloc(ctx);

    req->callback     = callback;
    req->private_data = private_data;

    sqe = io_uring_get_sqe(&ctx->ring);

    evpl_io_uring_abort_if(!sqe, "io_uring_get_sqe");

    io_uring_sqe_set_data64(sqe, (uint64_t) req);
    io_uring_prep_fsync(sqe, dev->fd, 0);

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_flush */

static void
evpl_io_uring_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *queue)
{
    evpl_free(queue);
} /* evpl_io_uring_close_queue */

static struct evpl_block_queue *
evpl_io_uring_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *bdev)
{
    struct evpl_block_queue *q;

    q = evpl_zalloc(sizeof(*q));

    q->private_data = bdev->private_data;
    q->close_queue  = evpl_io_uring_close_queue;
    q->read         = evpl_io_uring_read;
    q->write        = evpl_io_uring_write;
    q->flush        = evpl_io_uring_flush;

    return q;
} /* evpl_io_uring_open_queue */

static void
evpl_io_uring_close_device(struct evpl_block_device *bdev)
{
    struct evpl_io_uring_device *dev = bdev->private_data;

    close(dev->fd);
    evpl_free(dev);
    evpl_free(bdev);
} /* evpl_io_uring_close_device */

static struct evpl_block_device *
evpl_io_uring_open_device(const char *uri)
{
    struct evpl_block_device    *bdev;
    struct evpl_io_uring_device *dev;

    bdev = evpl_zalloc(sizeof(*bdev));

    dev = evpl_zalloc(sizeof(*dev));

    dev->fd = open(uri, O_RDWR | O_DIRECT);

    if (dev->fd < 0) {
        evpl_free(dev);
        return NULL;
    }

    bdev->private_data = dev;
    bdev->open_queue   = evpl_io_uring_open_queue;
    bdev->close_device = evpl_io_uring_close_device;

    return bdev;
} /* evpl_io_uring_open_device */

struct evpl_framework      evpl_framework_io_uring = {
    .id      = EVPL_FRAMEWORK_IO_URING,
    .name    = "IO_URING",
    .init    = evpl_io_uring_init,
    .cleanup = evpl_io_uring_cleanup,
    .create  = evpl_io_uring_create,
    .destroy = evpl_io_uring_destroy,
};

struct evpl_block_protocol evpl_block_protocol_io_uring = {
    .id          = EVPL_BLOCK_PROTOCOL_IO_URING,
    .name        = "io_uring",
    .framework   = &evpl_framework_io_uring,
    .open_device = evpl_io_uring_open_device,
};
