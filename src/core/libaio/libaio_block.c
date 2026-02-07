// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE
#include <string.h>
#include <libaio.h>
#include <sys/eventfd.h>
#include <sys/fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <linux/fs.h>

#include "core/libaio/libaio.h"
#include "core/libaio/libaio_internal.h"

static void
evpl_libaio_read(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_libaio_device  *dev = queue->private_data;
    struct evpl_libaio_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_LIBAIO);
    struct evpl_libaio_request *req;
    int                         i, bounce_needed = 0;

    req = evpl_libaio_request_alloc(ctx);

    req->callback     = callback;
    req->private_data = private_data;
    req->niov         = niov;
    req->length       = 0;

    for (i = 0; i < niov; i++) {
        req->iov[i].iov_base = iov[i].data;
        req->iov[i].iov_len  = iov[i].length;
        req->length         += iov[i].length;

        if (((uint64_t) iov[i].data & 4095) || (iov[i].length & 4095)) {
            bounce_needed = 1;
        }
    }

    if (bounce_needed) {
        req->bounce = evpl_valloc(req->length, 4096);

        req->bounce_iov.iov_base = req->bounce;
        req->bounce_iov.iov_len  = req->length;

        req->need_debounce = 1;

        io_prep_preadv(&req->iocb, dev->fd, &req->bounce_iov, 1, offset);
    } else {
        io_prep_preadv(&req->iocb, dev->fd, req->iov, req->niov, offset);
    }

    io_set_eventfd(&req->iocb, ctx->eventfd);
    req->iocb.data = req;

    evpl_libaio_abort_if(ctx->num_pending >= ctx->max_pending, "too many pending iocbs");

    ctx->pending_iocbs[ctx->num_pending++] = &req->iocb;

    evpl_defer(evpl, &ctx->flush);
} /* evpl_libaio_read */

static void
evpl_libaio_write(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    int sync,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_libaio_device  *dev = queue->private_data;
    struct evpl_libaio_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_LIBAIO);
    struct evpl_libaio_request *req;
    int                         i, need_bounce = 0;
    uint64_t                    bounce_offset;

    req = evpl_libaio_request_alloc(ctx);

    req->callback     = callback;
    req->private_data = private_data;
    req->niov         = niov;
    req->length       = 0;

    for (i = 0; i < niov; i++) {
        req->iov[i].iov_base = iov[i].data;
        req->iov[i].iov_len  = iov[i].length;
        req->length         += iov[i].length;

        if (((uint64_t) iov[i].data & 4095) || (iov[i].length & 4095)) {
            need_bounce = 1;
        }
    }

    if (need_bounce) {
        req->bounce = evpl_valloc(req->length, 4096);

        bounce_offset = 0;

        for (i = 0; i < niov; i++) {
            memcpy(req->bounce + bounce_offset, iov[i].data, iov[i].length);
            bounce_offset += iov[i].length;
        }

        req->bounce_iov.iov_base = req->bounce;
        req->bounce_iov.iov_len  = req->length;

        io_prep_pwritev(&req->iocb, dev->fd, &req->bounce_iov, 1, offset);
    } else {
        io_prep_pwritev(&req->iocb, dev->fd, req->iov, req->niov, offset);
    }

    io_set_eventfd(&req->iocb, ctx->eventfd);
    req->iocb.data = req;

    evpl_libaio_abort_if(ctx->num_pending >= ctx->max_pending, "too many pending iocbs");

    ctx->pending_iocbs[ctx->num_pending++] = &req->iocb;

    evpl_defer(evpl, &ctx->flush);
} /* evpl_libaio_write */

static void
evpl_libaio_flush(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_libaio_device  *dev = queue->private_data;
    struct evpl_libaio_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_LIBAIO);
    struct evpl_libaio_request *req;

    req = evpl_libaio_request_alloc(ctx);

    req->callback     = callback;
    req->private_data = private_data;
    req->length       = 0;

    io_prep_fsync(&req->iocb, dev->fd);
    io_set_eventfd(&req->iocb, ctx->eventfd);
    req->iocb.data = req;

    evpl_libaio_abort_if(ctx->num_pending >= ctx->max_pending, "too many pending iocbs");

    ctx->pending_iocbs[ctx->num_pending++] = &req->iocb;

    evpl_defer(evpl, &ctx->flush);
} /* evpl_libaio_flush */

static void
evpl_libaio_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *queue)
{
    evpl_free(queue);
} /* evpl_libaio_close_queue */

static struct evpl_block_queue *
evpl_libaio_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *bdev)
{
    struct evpl_block_queue *q;

    q = evpl_zalloc(sizeof(*q));

    q->private_data = bdev->private_data;
    q->close_queue  = evpl_libaio_close_queue;
    q->read         = evpl_libaio_read;
    q->write        = evpl_libaio_write;
    q->flush        = evpl_libaio_flush;

    return q;
} /* evpl_libaio_open_queue */

static void
evpl_libaio_close_device(struct evpl_block_device *bdev)
{
    struct evpl_libaio_device *dev = bdev->private_data;

    close(dev->fd);
    evpl_free(dev);
    evpl_free(bdev);
} /* evpl_libaio_close_device */

static struct evpl_block_device *
evpl_libaio_open_device(
    const char *uri,
    void       *private_data)
{
    struct evpl_block_device  *bdev;
    struct evpl_libaio_device *dev;
    struct stat                st;

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
    bdev->open_queue   = evpl_libaio_open_queue;
    bdev->close_device = evpl_libaio_close_device;

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
} /* evpl_libaio_open_device */

struct evpl_block_protocol evpl_block_protocol_libaio = {
    .id          = EVPL_BLOCK_PROTOCOL_LIBAIO,
    .name        = "libaio",
    .framework   = &evpl_framework_libaio,
    .open_device = evpl_libaio_open_device,
};
