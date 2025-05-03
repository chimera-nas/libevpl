// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#define _GNU_SOURCE
#include <string.h>
#include <liburing.h>
#include <sys/eventfd.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>

#include "core/io_uring/io_uring.h"
#include "core/io_uring/io_uring_internal.h"

static void
evpl_io_uring_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    int rc;

    if (req->res < 0) {
        rc = -req->res;
    } else if (req->res != req->block.length) {
        rc = EIO;
    } else {
        rc = 0;
    }

    req->block.callback(evpl, rc, req->block.private_data);
} /* evpl_io_uring_callback */

static void
evpl_io_uring_read(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_io_uring_device  *dev = queue->private_data;
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *req;
    struct io_uring_sqe          *sqe;
    int                           i, bounce_needed = 0;

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_BLOCK);

    req->callback           = evpl_io_uring_callback;
    req->block.callback     = callback;
    req->block.private_data = private_data;
    req->block.niov         = niov;
    req->block.length       = 0;
    sqe                     = io_uring_get_sqe(&ctx->ring);

    evpl_io_uring_abort_if(!sqe, "io_uring_get_sqe");

    io_uring_sqe_set_data64(sqe, (uint64_t) req);

    for (i = 0; i < niov; i++) {
        req->block.iov[i].iov_base = iov[i].data;
        req->block.iov[i].iov_len  = iov[i].length;
        req->block.length         += iov[i].length;

        if (((uint64_t) iov[i].data & 4095) || (iov[i].length & 4095)) {
            bounce_needed = 1;
        }
    }

    if (bounce_needed) {
        req->block.bounce = evpl_valloc(req->block.length, 4096);

        req->block.bounce_iov.iov_base = req->block.bounce;
        req->block.bounce_iov.iov_len  = req->block.length;

        req->block.need_debounce = 1;

        io_uring_prep_readv(sqe, dev->fd, &req->block.bounce_iov, 1, offset);
    } else {
        io_uring_prep_readv(sqe, dev->fd, req->block.iov, req->block.niov, offset);
    }

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_read */

static void
evpl_io_uring_write(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    int sync,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_io_uring_device  *dev = queue->private_data;
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct io_uring_sqe          *sqe;
    struct evpl_io_uring_request *req;
    int                           i, need_bounce = 0, flags = 0;
    uint64_t                      bounce_offset;

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_BLOCK);

    req->callback           = evpl_io_uring_callback;
    req->block.callback     = callback;
    req->block.private_data = private_data;
    req->block.niov         = niov;
    req->block.length       = 0;


    for (i = 0; i < niov; i++) {
        req->block.iov[i].iov_base = iov[i].data;
        req->block.iov[i].iov_len  = iov[i].length;
        req->block.length         += iov[i].length;

        if (((uint64_t) iov[i].data & 4095) || (iov[i].length & 4095)) {
            need_bounce = 1;
        }
    }

    sqe = io_uring_get_sqe(&ctx->ring);

    evpl_io_uring_abort_if(!sqe, "io_uring_get_sqe");

    io_uring_sqe_set_data64(sqe, (uint64_t) req);

    if (need_bounce) {
        req->block.bounce = evpl_valloc(req->block.length, 4096);

        bounce_offset = 0;

        for (i = 0; i < niov; i++) {
            memcpy(req->block.bounce + bounce_offset, iov[i].data, iov[i].length);
            bounce_offset += iov[i].length;
        }

        req->block.bounce_iov.iov_base = req->block.bounce;
        req->block.bounce_iov.iov_len  = req->block.length;

        io_uring_prep_writev2(sqe, dev->fd, &req->block.bounce_iov, 1, offset, flags);
    } else {
        io_uring_prep_writev2(sqe, dev->fd, req->block.iov, req->block.niov, offset, flags);
    }

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_write */

static void
evpl_io_uring_flush(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_io_uring_device  *dev = queue->private_data;
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *req;
    struct io_uring_sqe          *sqe;

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_BLOCK);

    req->callback           = evpl_io_uring_callback;
    req->block.callback     = callback;
    req->block.private_data = private_data;

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
evpl_io_uring_open_device(
    const char *uri,
    void       *private_data)
{
    struct evpl_block_device    *bdev;
    struct evpl_io_uring_device *dev;
    struct stat                  st;

    bdev = evpl_zalloc(sizeof(*bdev));
    dev  = evpl_zalloc(sizeof(*dev));

    dev->fd = open(uri, O_RDWR | O_DIRECT);

    if (dev->fd < 0) {
        evpl_free(dev);
        return NULL;
    }

    if (fstat(dev->fd, &st) < 0) {
        close(dev->fd);
        evpl_free(dev);
        evpl_free(bdev);
        return NULL;
    }

    bdev->private_data = dev;
    bdev->open_queue   = evpl_io_uring_open_queue;
    bdev->close_device = evpl_io_uring_close_device;

    if (S_ISBLK(st.st_mode)) {
        uint64_t bytes;
        if (ioctl(dev->fd, BLKGETSIZE64, &bytes) < 0) {
            close(dev->fd);
            evpl_free(dev);
            evpl_free(bdev);
            return NULL;
        }
        bdev->size = bytes;
    } else {
        bdev->size = st.st_size;
    }

    bdev->max_request_size = 4 * 1024 * 1024;

    return bdev;
} /* evpl_io_uring_open_device */

struct evpl_block_protocol evpl_block_protocol_io_uring = {
    .id          = EVPL_BLOCK_PROTOCOL_IO_URING,
    .name        = "io_uring",
    .framework   = &evpl_framework_io_uring,
    .open_device = evpl_io_uring_open_device,
};
