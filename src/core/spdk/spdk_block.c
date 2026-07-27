// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * EVPL_BLOCK_PROTOCOL_SPDK_BDEV: block protocol backed by SPDK bdevs.
 *
 * Guest-mode contract: the host application owns the SPDK env and the bdev
 * layer; the uri is a bdev name registered there.  Device open/close run on
 * the calling evpl's thread -- an spdk_thread under EVPL_CORE_MECH_SPDK --
 * which becomes the device's owner: bdev events (hot-remove, resize) are
 * delivered to it, and close must run on it (enforced).
 *
 * Queues wrap a per-thread spdk_io_channel and need no event-loop hookup of
 * their own: completions are delivered by the channel's bdev pollers on the
 * owning spdk_thread, outside evpl_continue -- the completion path bumps
 * evpl_activity() and kicks the loop if callbacks armed deferrals, so a
 * sleeping interrupt-mode reactor cannot strand work.
 *
 * evpl slab buffers are pre-registered with spdk_mem_register (see
 * spdk_framework.c), so evpl iovec addresses are directly DMA-usable; a
 * bounce through a registered slab buffer covers the rare bdev with an
 * alignment requirement the caller's iovecs do not meet.
 */

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <errno.h>

#include <spdk/thread.h>
#include <spdk/bdev.h>

#include "core/evpl.h"
#include "evpl/evpl.h"
#include "core/protocol.h"
#include "core/evpl_shared.h"
#include "core/spdk/evpl_spdk.h"

#define evpl_spdk_bdev_debug(...) evpl_debug("spdk_bdev", __FILE__, \
                                             __LINE__, __VA_ARGS__)
#define evpl_spdk_bdev_info(...)  evpl_info("spdk_bdev", __FILE__, \
                                            __LINE__, __VA_ARGS__)
#define evpl_spdk_bdev_error(...) evpl_error("spdk_bdev", __FILE__, \
                                             __LINE__, __VA_ARGS__)
#define evpl_spdk_bdev_abort_if(cond, ...) \
        evpl_abort_if(cond, "spdk_bdev", __FILE__, __LINE__, __VA_ARGS__)

#define EVPL_SPDK_BDEV_MAX_IOV 64

struct evpl_spdk_bdev_device {
    struct evpl              *owner;        /* evpl that opened the device  */
    struct spdk_thread       *owner_thread;
    struct spdk_bdev_desc    *desc;
    struct spdk_bdev         *bdev;
    struct evpl_block_device *bdev_pub;     /* backpointer for RESIZE       */
    uint32_t                  block_size;
    uint64_t                  num_blocks;
    size_t                    buf_align;
    unsigned int              supports_unmap        : 1;
    unsigned int              supports_write_zeroes : 1;
    unsigned int              supports_flush        : 1;
    unsigned int              has_write_cache       : 1;
    unsigned int              dead                  : 1;
};

struct evpl_spdk_bdev_queue;

struct evpl_spdk_bdev_request {
    struct evpl_spdk_bdev_queue   *queue;
    enum evpl_block_op_kind        kind;
    evpl_block_callback_t          callback;     /* core evpl_block_complete */
    void                          *private_data;
    struct iovec                   iov[EVPL_SPDK_BDEV_MAX_IOV];
    int                            niov;
    uint64_t                       offset;       /* bytes */
    uint64_t                       length;       /* bytes */
    unsigned int                   need_flush : 1; /* sync write: chain flush */
    unsigned int                   in_flush   : 1; /* chained flush in flight */
    unsigned int                   bounced    : 1;
    unsigned int                   debounce   : 1; /* read: scatter back      */
    struct evpl_iovec              bounce;
    struct spdk_bdev_io_wait_entry wait;
    struct evpl_spdk_bdev_request *next;
};

struct evpl_spdk_bdev_queue {
    struct evpl                   *evpl;
    struct evpl_spdk_bdev_device  *dev;
    struct evpl_block_queue       *bq;
    struct spdk_io_channel        *ch;
    uint64_t                       outstanding;
    unsigned int                   closing;
    struct evpl_spdk_bdev_request *free_requests;
};

static void evpl_spdk_bdev_submit(
    struct evpl_spdk_bdev_queue   *queue,
    struct evpl_spdk_bdev_request *request);

static void evpl_spdk_bdev_io_done(
    struct spdk_bdev_io *bdev_io,
    bool                 success,
    void                *cb_arg);

/*
 * Completion epilogue shared by real completions and synthetic failures.
 * Runs on the queue's own spdk_thread but OUTSIDE evpl_continue: bump
 * activity for honest busy accounting, and kick the loop if the callback
 * chain armed deferrals so a sleeping interrupt-mode reactor wakes to run
 * them.
 */
static void
evpl_spdk_bdev_request_complete(
    struct evpl_spdk_bdev_request *request,
    int                            status)
{
    struct evpl_spdk_bdev_queue *queue = request->queue;
    struct evpl                 *evpl  = queue->evpl;
    evpl_block_callback_t        callback;
    void                        *callback_private;
    int                          deferrals_before;

    if (request->bounced) {
        if (request->debounce && status == 0) {
            const char *src = request->bounce.data;
            int         i;

            for (i = 0; i < request->niov; i++) {
                memcpy(request->iov[i].iov_base, src,
                       request->iov[i].iov_len);
                src += request->iov[i].iov_len;
            }
        }

        evpl_iovec_release_internal(evpl, &request->bounce);
    }

    /* Recycle before the callback: it may submit again (reusing this
     * request) or close the queue. */
    callback         = request->callback;
    callback_private = request->private_data;

    request->next        = queue->free_requests;
    queue->free_requests = request;

    evpl_activity(evpl);

    deferrals_before = evpl->num_active_deferrals;

    callback(evpl, status, callback_private);

    if (--queue->outstanding == 0 && queue->closing) {
        struct evpl_spdk_bdev_request *req;

        spdk_put_io_channel(queue->ch);

        while ((req = queue->free_requests)) {
            queue->free_requests = req->next;
            evpl_free(req);
        }

        evpl_free(queue->bq);
        evpl_free(queue);
    }

    if (evpl->num_active_deferrals > deferrals_before) {
        evpl_kick(evpl);
    }
} /* evpl_spdk_bdev_request_complete */

static void
evpl_spdk_bdev_io_done(
    struct spdk_bdev_io *bdev_io,
    bool                 success,
    void                *cb_arg)
{
    struct evpl_spdk_bdev_request *request = cb_arg;
    struct evpl_spdk_bdev_queue   *queue   = request->queue;

    if (bdev_io) {
        spdk_bdev_free_io(bdev_io);
    }

    if (success && request->kind == EVPL_BLOCK_OP_WRITE &&
        request->need_flush && !request->in_flush) {
        /* Durable write on a write-back device: chain a flush before
         * completing the operation. */
        request->in_flush = 1;
        evpl_spdk_bdev_submit(queue, request);
        return;
    }

    evpl_spdk_bdev_request_complete(request, success ? 0 : EIO);
} /* evpl_spdk_bdev_io_done */

static void
evpl_spdk_bdev_io_wait_retry(void *cb_arg)
{
    struct evpl_spdk_bdev_request *request = cb_arg;

    evpl_spdk_bdev_submit(request->queue, request);
} /* evpl_spdk_bdev_io_wait_retry */

static void
evpl_spdk_bdev_submit(
    struct evpl_spdk_bdev_queue   *queue,
    struct evpl_spdk_bdev_request *request)
{
    struct evpl_spdk_bdev_device *dev = queue->dev;
    int                           rc;

    if (request->in_flush) {
        rc = spdk_bdev_flush(dev->desc, queue->ch,
                             0, dev->num_blocks * dev->block_size,
                             evpl_spdk_bdev_io_done, request);
    } else {
        switch (request->kind) {
            case EVPL_BLOCK_OP_READ:
                rc = spdk_bdev_readv(dev->desc, queue->ch,
                                     request->iov, request->niov,
                                     request->offset, request->length,
                                     evpl_spdk_bdev_io_done, request);
                break;
            case EVPL_BLOCK_OP_WRITE:
                rc = spdk_bdev_writev(dev->desc, queue->ch,
                                      request->iov, request->niov,
                                      request->offset, request->length,
                                      evpl_spdk_bdev_io_done, request);
                break;
            case EVPL_BLOCK_OP_FLUSH:
                rc = spdk_bdev_flush(dev->desc, queue->ch,
                                     0, dev->num_blocks * dev->block_size,
                                     evpl_spdk_bdev_io_done, request);
                break;
            case EVPL_BLOCK_OP_DISCARD:
                if (request->length == 0) {
                    rc = 0;
                    evpl_spdk_bdev_io_done(NULL, true, request);
                    break;
                }
                rc = spdk_bdev_unmap(dev->desc, queue->ch,
                                     request->offset, request->length,
                                     evpl_spdk_bdev_io_done, request);
                break;
            default:
                /* write_zeroes rides EVPL_BLOCK_OP_WRITE accounting but is
                 * distinguished by niov == 0. */
                rc = spdk_bdev_write_zeroes(dev->desc, queue->ch,
                                            request->offset, request->length,
                                            evpl_spdk_bdev_io_done, request);
                break;
        } /* switch */
    }

    if (rc == 0) {
        return;
    }

    if (rc == -ENOMEM) {
        /* bdev_io pool exhausted: park until the channel frees one.  The
         * request stays counted in outstanding, so queue close cannot
         * finalize under it. */
        request->wait.bdev   = dev->bdev;
        request->wait.cb_fn  = evpl_spdk_bdev_io_wait_retry;
        request->wait.cb_arg = request;

        rc = spdk_bdev_queue_io_wait(dev->bdev, queue->ch, &request->wait);

        if (rc == 0) {
            return;
        }
    }

    evpl_spdk_bdev_request_complete(request, -rc);
} /* evpl_spdk_bdev_submit */

static struct evpl_spdk_bdev_request *
evpl_spdk_bdev_request_alloc(struct evpl_spdk_bdev_queue *queue)
{
    struct evpl_spdk_bdev_request *request = queue->free_requests;

    if (request) {
        queue->free_requests = request->next;
        memset(request, 0, sizeof(*request));
    } else {
        request = evpl_zalloc(sizeof(*request));
    }

    request->queue = queue;

    return request;
} /* evpl_spdk_bdev_request_alloc */

/*
 * Validate and stage a data op.  Returns 0 and completes the op with an
 * error itself when the request cannot be issued.
 */
static int
evpl_spdk_bdev_prepare(
    struct evpl_spdk_bdev_queue   *queue,
    struct evpl_spdk_bdev_request *request,
    const struct evpl_iovec       *iov,
    int                            niov,
    uint64_t                       offset,
    int                            is_write)
{
    struct evpl_spdk_bdev_device *dev        = queue->dev;
    uint64_t                      length     = 0;
    int                           misaligned = 0;
    int                           i;

    for (i = 0; i < niov; i++) {
        length += iov[i].length;

        if ((uintptr_t) iov[i].data & (dev->buf_align - 1)) {
            misaligned = 1;
        }

        if (i + 1 < niov && (iov[i].length & (dev->buf_align - 1))) {
            misaligned = 1;
        }
    }

    request->offset = offset;
    request->length = length;

    if (dev->dead) {
        evpl_spdk_bdev_request_complete(request, ENODEV);
        return -1;
    }

    if (length == 0 ||
        (offset & (dev->block_size - 1)) ||
        (length & (dev->block_size - 1)) ||
        offset + length > dev->num_blocks * (uint64_t) dev->block_size) {
        evpl_spdk_bdev_request_complete(request, EINVAL);
        return -1;
    }

    if (!misaligned && niov <= EVPL_SPDK_BDEV_MAX_IOV) {
        for (i = 0; i < niov; i++) {
            request->iov[i].iov_base = iov[i].data;
            request->iov[i].iov_len  = iov[i].length;
        }
        request->niov = niov;
        return 0;
    }

    /* Bounce through a single registered slab buffer (a plain heap buffer
     * would not be spdk_mem_register'ed and could not DMA). */
    if (niov > EVPL_SPDK_BDEV_MAX_IOV || length > evpl_shared->config->buffer_size) {
        evpl_spdk_bdev_error(
            "request (%d iov, %lu bytes) cannot be bounced for bdev "
            "alignment %zu", niov, (unsigned long) length, dev->buf_align);
        evpl_spdk_bdev_request_complete(request, EINVAL);
        return -1;
    }

    if (evpl_iovec_alloc(queue->evpl, length,
                         dev->buf_align < 4096 ? 4096 : dev->buf_align,
                         1, 0, &request->bounce) < 1) {
        evpl_spdk_bdev_request_complete(request, ENOMEM);
        return -1;
    }

    request->bounced = 1;

    if (is_write) {
        char *dst = request->bounce.data;

        for (i = 0; i < niov; i++) {
            memcpy(dst, iov[i].data, iov[i].length);
            dst += iov[i].length;
        }
    } else {
        /* Keep the caller's layout for the completion-side scatter. */
        for (i = 0; i < niov; i++) {
            request->iov[i].iov_base = iov[i].data;
            request->iov[i].iov_len  = iov[i].length;
        }
        request->niov     = niov;
        request->debounce = 1;
    }

    if (is_write) {
        request->iov[0].iov_base = request->bounce.data;
        request->iov[0].iov_len  = length;
        request->niov            = 1;
    }

    return 0;
} /* evpl_spdk_bdev_prepare */

static void
evpl_spdk_bdev_read(
    struct evpl             *evpl,
    struct evpl_block_queue *bq,
    struct evpl_iovec       *iov,
    int                      niov,
    uint64_t                 offset,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    struct evpl_spdk_bdev_queue   *queue = bq->private_data;
    struct evpl_spdk_bdev_request *request;

    evpl_activity(evpl);

    request = evpl_spdk_bdev_request_alloc(queue);

    request->kind         = EVPL_BLOCK_OP_READ;
    request->callback     = callback;
    request->private_data = private_data;

    queue->outstanding++;

    if (evpl_spdk_bdev_prepare(queue, request, iov, niov, offset, 0)) {
        return;
    }

    /* A bounced read submits into the bounce buffer, not the caller iovs. */
    if (request->bounced) {
        struct iovec                  bounce_iov = {
            .iov_base = request->bounce.data,
            .iov_len  = request->length,
        };
        struct evpl_spdk_bdev_device *dev = queue->dev;
        int                           rc;

        rc = spdk_bdev_readv(dev->desc, queue->ch, &bounce_iov, 1,
                             request->offset, request->length,
                             evpl_spdk_bdev_io_done, request);

        if (rc == -ENOMEM) {
            request->wait.bdev   = dev->bdev;
            request->wait.cb_fn  = evpl_spdk_bdev_io_wait_retry;
            request->wait.cb_arg = request;
            rc                   = spdk_bdev_queue_io_wait(dev->bdev, queue->ch, &request->wait);
        }

        if (rc) {
            evpl_spdk_bdev_request_complete(request, -rc);
        }
        return;
    }

    evpl_spdk_bdev_submit(queue, request);
} /* evpl_spdk_bdev_read */

static void
evpl_spdk_bdev_write(
    struct evpl             *evpl,
    struct evpl_block_queue *bq,
    const struct evpl_iovec *iov,
    int                      niov,
    uint64_t                 offset,
    int                      sync,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    struct evpl_spdk_bdev_queue   *queue = bq->private_data;
    struct evpl_spdk_bdev_device  *dev   = queue->dev;
    struct evpl_spdk_bdev_request *request;

    evpl_activity(evpl);

    request = evpl_spdk_bdev_request_alloc(queue);

    request->kind         = EVPL_BLOCK_OP_WRITE;
    request->callback     = callback;
    request->private_data = private_data;

    if (sync && dev->has_write_cache) {
        if (dev->supports_flush) {
            request->need_flush = 1;
        } else {
            static int warned;
            if (!warned) {
                warned = 1;
                evpl_spdk_bdev_error(
                    "bdev has a write cache but no flush support; sync "
                    "writes cannot be made durable");
            }
        }
    }

    queue->outstanding++;

    if (evpl_spdk_bdev_prepare(queue, request, iov, niov, offset, 1)) {
        return;
    }

    evpl_spdk_bdev_submit(queue, request);
} /* evpl_spdk_bdev_write */

static void
evpl_spdk_bdev_flush(
    struct evpl             *evpl,
    struct evpl_block_queue *bq,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    struct evpl_spdk_bdev_queue   *queue = bq->private_data;
    struct evpl_spdk_bdev_request *request;

    evpl_activity(evpl);

    request = evpl_spdk_bdev_request_alloc(queue);

    request->kind         = EVPL_BLOCK_OP_FLUSH;
    request->callback     = callback;
    request->private_data = private_data;

    queue->outstanding++;

    if (queue->dev->dead) {
        evpl_spdk_bdev_request_complete(request, ENODEV);
        return;
    }

    if (!queue->dev->supports_flush) {
        /* Nothing to flush (e.g. a RAM-backed bdev): succeed as a no-op. */
        evpl_spdk_bdev_io_done(NULL, true, request);
        return;
    }

    evpl_spdk_bdev_submit(queue, request);
} /* evpl_spdk_bdev_flush */

static void
evpl_spdk_bdev_range_op(
    struct evpl_block_queue *bq,
    enum evpl_block_op_kind  kind,
    uint64_t                 offset,
    uint64_t                 length,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    struct evpl_spdk_bdev_queue   *queue = bq->private_data;
    struct evpl_spdk_bdev_device  *dev   = queue->dev;
    struct evpl_spdk_bdev_request *request;

    evpl_activity(queue->evpl);

    request = evpl_spdk_bdev_request_alloc(queue);

    request->kind         = kind;
    request->callback     = callback;
    request->private_data = private_data;
    request->offset       = offset;
    request->length       = length;

    queue->outstanding++;

    if (dev->dead) {
        evpl_spdk_bdev_request_complete(request, ENODEV);
        return;
    }

    if ((offset & (dev->block_size - 1)) ||
        (length & (dev->block_size - 1)) ||
        offset + length > dev->num_blocks * (uint64_t) dev->block_size) {
        evpl_spdk_bdev_request_complete(request, EINVAL);
        return;
    }

    evpl_spdk_bdev_submit(queue, request);
} /* evpl_spdk_bdev_range_op */

static void
evpl_spdk_bdev_discard(
    struct evpl             *evpl,
    struct evpl_block_queue *bq,
    uint64_t                 offset,
    uint64_t                 length,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    evpl_spdk_bdev_range_op(bq, EVPL_BLOCK_OP_DISCARD, offset, length,
                            callback, private_data);
} /* evpl_spdk_bdev_discard */

static void
evpl_spdk_bdev_write_zeroes(
    struct evpl             *evpl,
    struct evpl_block_queue *bq,
    uint64_t                 offset,
    uint64_t                 length,
    evpl_block_callback_t    callback,
    void                    *private_data)
{
    /* niov == 0 distinguishes write_zeroes in the submit switch; the core
     * accounts it as EVPL_BLOCK_OP_WRITE. */
    evpl_spdk_bdev_range_op(bq, EVPL_BLOCK_NUM_OP_KIND, offset, length,
                            callback, private_data);
} /* evpl_spdk_bdev_write_zeroes */

static void
evpl_spdk_bdev_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *bq)
{
    struct evpl_spdk_bdev_queue *queue = bq->private_data;

    queue->closing = 1;

    if (queue->outstanding) {
        /* The last completion finalizes: put the channel and free. */
        return;
    }

    struct evpl_spdk_bdev_request *request;

    spdk_put_io_channel(queue->ch);

    while ((request = queue->free_requests)) {
        queue->free_requests = request->next;
        evpl_free(request);
    }

    evpl_free(queue);
    evpl_free(bq);
} /* evpl_spdk_bdev_close_queue */

static struct evpl_block_queue *
evpl_spdk_bdev_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *bdev_pub)
{
    struct evpl_spdk_bdev_device *dev = bdev_pub->private_data;
    struct evpl_spdk_bdev_queue  *queue;
    struct evpl_block_queue      *bq;

    evpl_spdk_bdev_abort_if(spdk_get_thread() == NULL,
                            "SPDK bdev queues require the evpl thread to be "
                            "an spdk_thread (EVPL_CORE_MECH_SPDK)");

    evpl_spdk_bdev_abort_if(dev->dead,
                            "cannot open a queue on hot-removed bdev");

    bq    = evpl_zalloc(sizeof(*bq));
    queue = evpl_zalloc(sizeof(*queue));

    queue->evpl = evpl;
    queue->dev  = dev;
    queue->bq   = bq;
    queue->ch   = spdk_bdev_get_io_channel(dev->desc);

    evpl_spdk_bdev_abort_if(!queue->ch,
                            "spdk_bdev_get_io_channel failed");

    bq->private_data = queue;
    bq->close_queue  = evpl_spdk_bdev_close_queue;
    bq->read         = evpl_spdk_bdev_read;
    bq->write        = evpl_spdk_bdev_write;
    bq->flush        = evpl_spdk_bdev_flush;

    if (dev->supports_unmap) {
        bq->discard = evpl_spdk_bdev_discard;
    }

    if (dev->supports_write_zeroes) {
        bq->write_zeroes = evpl_spdk_bdev_write_zeroes;
    }

    return bq;
} /* evpl_spdk_bdev_open_queue */

static void
evpl_spdk_bdev_event_cb(
    enum spdk_bdev_event_type type,
    struct spdk_bdev         *bdev,
    void                     *event_ctx)
{
    struct evpl_spdk_bdev_device *dev = event_ctx;

    switch (type) {
        case SPDK_BDEV_EVENT_REMOVE:
            evpl_spdk_bdev_error(
                "bdev hot-removed; device marked dead, in-flight and future "
                "I/O will fail; close its queues and the device to release "
                "it");
            dev->dead = 1;
            break;
        case SPDK_BDEV_EVENT_RESIZE:
            dev->num_blocks     = spdk_bdev_get_num_blocks(dev->bdev);
            dev->bdev_pub->size = dev->num_blocks *
                (uint64_t) dev->block_size;
            evpl_spdk_bdev_info("bdev resized to %lu bytes",
                                (unsigned long) dev->bdev_pub->size);
            break;
        default:
            evpl_spdk_bdev_info("ignoring bdev event %d", type);
            break;
    } /* switch */
} /* evpl_spdk_bdev_event_cb */

static void
evpl_spdk_bdev_close_device(
    struct evpl                 *evpl,
    struct evpl_block_device    *bdev_pub,
    evpl_block_device_complete_t complete,
    void                        *ctx)
{
    struct evpl_spdk_bdev_device *dev = bdev_pub->private_data;

    evpl_spdk_bdev_abort_if(evpl != dev->owner ||
                            spdk_get_thread() != dev->owner_thread,
                            "evpl_block_close_device must be called on the "
                            "evpl that opened the SPDK bdev device");

    spdk_bdev_close(dev->desc);

    evpl_free(dev);
    evpl_free(bdev_pub);

    complete(evpl, NULL, 0, ctx);
} /* evpl_spdk_bdev_close_device */

static void
evpl_spdk_bdev_open_device(
    struct evpl                 *evpl,
    const char                  *uri,
    void                        *private_data,
    evpl_block_device_complete_t complete,
    void                        *ctx)
{
    struct evpl_spdk_bdev_device *dev;
    struct evpl_block_device     *bdev_pub;
    int                           rc;

    if (evpl_shared->config->core_mech != EVPL_CORE_MECH_SPDK ||
        spdk_get_thread() == NULL) {
        evpl_spdk_bdev_error(
            "EVPL_BLOCK_PROTOCOL_SPDK_BDEV requires EVPL_CORE_MECH_SPDK; "
            "the opening evpl must be running on an spdk_thread");
        complete(evpl, NULL, ENOTSUP, ctx);
        return;
    }

    bdev_pub = evpl_zalloc(sizeof(*bdev_pub));
    dev      = evpl_zalloc(sizeof(*dev));

    rc = spdk_bdev_open_ext(uri, true, evpl_spdk_bdev_event_cb, dev,
                            &dev->desc);

    if (rc) {
        evpl_spdk_bdev_error("spdk_bdev_open_ext(%s) failed: %s",
                             uri, strerror(-rc));
        evpl_free(dev);
        evpl_free(bdev_pub);
        complete(evpl, NULL, -rc, ctx);
        return;
    }

    dev->owner        = evpl;
    dev->owner_thread = spdk_get_thread();
    dev->bdev         = spdk_bdev_desc_get_bdev(dev->desc);
    dev->bdev_pub     = bdev_pub;
    dev->block_size   = spdk_bdev_get_block_size(dev->bdev);
    dev->num_blocks   = spdk_bdev_get_num_blocks(dev->bdev);
    dev->buf_align    = spdk_bdev_get_buf_align(dev->bdev);

    if (dev->buf_align < 1) {
        dev->buf_align = 1;
    }

    dev->supports_unmap =
        spdk_bdev_io_type_supported(dev->bdev, SPDK_BDEV_IO_TYPE_UNMAP);
    dev->supports_write_zeroes =
        spdk_bdev_io_type_supported(dev->bdev, SPDK_BDEV_IO_TYPE_WRITE_ZEROES);
    dev->supports_flush =
        spdk_bdev_io_type_supported(dev->bdev, SPDK_BDEV_IO_TYPE_FLUSH);
    dev->has_write_cache = spdk_bdev_has_write_cache(dev->bdev);

    bdev_pub->private_data     = dev;
    bdev_pub->size             = dev->num_blocks * (uint64_t) dev->block_size;
    bdev_pub->max_request_size = 4 * 1024 * 1024;
    bdev_pub->open_queue       = evpl_spdk_bdev_open_queue;
    bdev_pub->close_device     = evpl_spdk_bdev_close_device;

    complete(evpl, bdev_pub, 0, ctx);
} /* evpl_spdk_bdev_open_device */

struct evpl_block_protocol evpl_block_protocol_spdk_bdev = {
    .id          = EVPL_BLOCK_PROTOCOL_SPDK_BDEV,
    .name        = "spdk_bdev",
    .framework   = &evpl_framework_spdk,
    .open_device = evpl_spdk_bdev_open_device,
};
