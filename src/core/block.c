// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <pthread.h>
#include <time.h>
#include <string.h>

#include "core/evpl_shared.h"
#include "core/macros.h"
#include "core/evpl.h"
#include "core/timing.h"

/* Completion-tracking record threaded through a block request so the
 * core can measure latency and request size and maintain queue depth
 * without the protocol's help.  Allocated from a per-queue freelist and
 * touched only on the queue's own thread, so no locking is required.
 */
struct evpl_block_op {
    struct prometheus_stopwatch start;
    uint64_t                    size;
    enum evpl_block_op_kind kind;
    struct evpl_block_queue    *queue;
    evpl_block_callback_t       callback;
    void                       *private_data;
    struct evpl_block_op       *next;
};

/* "op" label values, indexed by enum evpl_block_op_kind. */
static const char *const evpl_block_op_names[EVPL_BLOCK_NUM_OP_KIND] = {
    [EVPL_BLOCK_OP_READ]    = "read",
    [EVPL_BLOCK_OP_WRITE]   = "write",
    [EVPL_BLOCK_OP_FLUSH]   = "flush",
    [EVPL_BLOCK_OP_DISCARD] = "discard",
};

static inline uint64_t
evpl_block_iov_size(
    const struct evpl_iovec *iov,
    int                      niov)
{
    uint64_t total = 0;
    int      i;

    for (i = 0; i < niov; i++) {
        total += evpl_iovec_length(&iov[i]);
    }

    return total;
} /* evpl_block_iov_size */

static inline struct evpl_block_op *
evpl_block_op_get(struct evpl_block_queue *queue)
{
    struct evpl_block_op *op = queue->op_freelist;

    if (op) {
        queue->op_freelist = op->next;
    } else {
        op = evpl_zalloc(sizeof(*op));
    }

    return op;
} /* evpl_block_op_get */

static void
evpl_block_complete(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    struct evpl_block_op    *op    = private_data;
    struct evpl_block_queue *queue = op->queue;
    evpl_block_callback_t    callback;
    void                    *callback_private;

    prometheus_time_histogram_sample(queue->m_latency[op->kind], &op->start);

    if (op->size) {
        prometheus_histogram_sample(queue->m_request_size[op->kind], op->size);
    }

    prometheus_gauge_add(queue->m_queue_depth, -1);

    /* Capture the user callback before recycling op: the callback may
     * issue another request (and thus reuse this op) or close the queue.
     */
    callback         = op->callback;
    callback_private = op->private_data;

    op->next           = queue->op_freelist;
    queue->op_freelist = op;

    callback(evpl, status, callback_private);
} /* evpl_block_complete */

SYMBOL_EXPORT struct evpl_block_device *
evpl_block_open_device(
    enum evpl_block_protocol_id protocol_id,
    const char                 *uri)
{
    struct evpl_block_protocol *protocol;
    struct evpl_block_device   *blockdev;
    void                       *protocol_private_data;

    __evpl_init();

    if (protocol_id >= EVPL_NUM_BLOCK_PROTOCOL) {
        return NULL;
    }


    protocol = evpl_shared->block_protocol[protocol_id];

    if (!protocol) {
        /* In-range id but the backend was not registered (e.g. gated out at
         * build time, such as the NVMe uring_cmd backend on older liburing).
         * Report failure rather than dereferencing a NULL protocol. */
        return NULL;
    }

    evpl_attach_framework_shared(protocol->framework->id);

    protocol_private_data = evpl_shared->framework_private[protocol->framework->
                                                           id];

    blockdev = protocol->open_device(uri, protocol_private_data);

    if (!blockdev) {
        return NULL;
    }

    blockdev->protocol = protocol;

    /* Per-device metric series, labelled with the device URI and the
     * protocol type so callers can aggregate across all devices or
     * break out by device/type.  The histograms additionally carry an
     * "op" label, so one series is created per operation class.
     */
    for (int k = 0; k < EVPL_BLOCK_NUM_OP_KIND; k++) {
        blockdev->m_latency[k] = prometheus_histogram_create_series(
            evpl_shared->block_latency,
            (const char *[]) { "device", "type", "op" },
            (const char *[]) { uri, protocol->name, evpl_block_op_names[k] }, 3);

        blockdev->m_request_size[k] = prometheus_histogram_create_series(
            evpl_shared->block_request_size,
            (const char *[]) { "device", "type", "op" },
            (const char *[]) { uri, protocol->name, evpl_block_op_names[k] }, 3);
    }

    blockdev->m_queue_depth = prometheus_gauge_create_series(
        evpl_shared->block_queue_depth,
        (const char *[]) { "device", "type" },
        (const char *[]) { uri, protocol->name }, 2);

    return blockdev;
} /* evpl_block_open_device */

SYMBOL_EXPORT void
evpl_block_close_device(struct evpl_block_device *bdev)
{
    for (int k = 0; k < EVPL_BLOCK_NUM_OP_KIND; k++) {
        prometheus_histogram_destroy_series(evpl_shared->block_latency,
                                            bdev->m_latency[k]);
        prometheus_histogram_destroy_series(evpl_shared->block_request_size,
                                            bdev->m_request_size[k]);
    }
    prometheus_gauge_destroy_series(evpl_shared->block_queue_depth,
                                    bdev->m_queue_depth);

    bdev->close_device(bdev);
} /* evpl_block_close_device */

SYMBOL_EXPORT uint64_t
evpl_block_size(struct evpl_block_device *bdev)
{
    return bdev->size;
} /* evpl_block_size */

SYMBOL_EXPORT uint64_t
evpl_block_max_request_size(struct evpl_block_device *bdev)
{
    return bdev->max_request_size;
} /* evpl_block_max_request_size */

SYMBOL_EXPORT struct evpl_block_queue *
evpl_block_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *blockdev)
{
    struct evpl_block_queue *queue;

    evpl_attach_framework(evpl, blockdev->protocol->framework->id);

    queue = blockdev->open_queue(evpl, blockdev);

    queue->protocol    = blockdev->protocol;
    queue->device      = blockdev;
    queue->op_freelist = NULL;

    /* Each queue gets its own instance of the device's series so the
     * I/O path mutates them lock-free; the scrape sums instances.
     */
    for (int k = 0; k < EVPL_BLOCK_NUM_OP_KIND; k++) {
        queue->m_latency[k] = prometheus_histogram_series_create_instance(
            blockdev->m_latency[k]);
        queue->m_request_size[k] = prometheus_histogram_series_create_instance(
            blockdev->m_request_size[k]);
    }
    queue->m_queue_depth = prometheus_gauge_series_create_instance(
        blockdev->m_queue_depth);

    return queue;
} /* evpl_block_open_queue */

SYMBOL_EXPORT void
evpl_block_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *queue)
{
    struct evpl_block_device *bdev = queue->device;
    struct evpl_block_op     *op;

    for (int k = 0; k < EVPL_BLOCK_NUM_OP_KIND; k++) {
        prometheus_histogram_series_destroy_instance(bdev->m_latency[k],
                                                     queue->m_latency[k]);
        prometheus_histogram_series_destroy_instance(bdev->m_request_size[k],
                                                     queue->m_request_size[k]);
    }
    prometheus_gauge_series_destroy_instance(bdev->m_queue_depth,
                                             queue->m_queue_depth);

    while ((op = queue->op_freelist)) {
        queue->op_freelist = op->next;
        evpl_free(op);
    }

    queue->close_queue(evpl, queue);
} /* evpl_block_close_queue */


SYMBOL_EXPORT void
evpl_block_read(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_block_op *op = evpl_block_op_get(queue);

    op->queue        = queue;
    op->callback     = callback;
    op->private_data = private_data;
    op->size         = evpl_block_iov_size(iov, niov);
    op->kind         = EVPL_BLOCK_OP_READ;

    prometheus_stopwatch_start(&op->start);
    prometheus_gauge_add(queue->m_queue_depth, 1);

    queue->read(evpl, queue, iov, niov, offset, evpl_block_complete, op);
} /* evpl_block_read */

SYMBOL_EXPORT void
evpl_block_write(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    int sync,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_block_op *op = evpl_block_op_get(queue);

    op->queue        = queue;
    op->callback     = callback;
    op->private_data = private_data;
    op->size         = evpl_block_iov_size(iov, niov);
    op->kind         = EVPL_BLOCK_OP_WRITE;

    prometheus_stopwatch_start(&op->start);
    prometheus_gauge_add(queue->m_queue_depth, 1);

    queue->write(evpl, queue, iov, niov, offset, sync, evpl_block_complete, op);
} /* evpl_block_write */

SYMBOL_EXPORT void
evpl_block_flush(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_block_op *op = evpl_block_op_get(queue);

    op->queue        = queue;
    op->callback     = callback;
    op->private_data = private_data;
    op->size         = 0;
    op->kind         = EVPL_BLOCK_OP_FLUSH;

    prometheus_stopwatch_start(&op->start);
    prometheus_gauge_add(queue->m_queue_depth, 1);

    queue->flush(evpl, queue, evpl_block_complete, op);
} /* evpl_block_flush */

SYMBOL_EXPORT void
evpl_block_discard(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    uint64_t offset,
    uint64_t length,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_block_op *op;

    if (!queue->discard) {
        /* Advisory hint; a backend that cannot discard succeeds as a no-op. */
        callback(evpl, 0, private_data);
        return;
    }

    op               = evpl_block_op_get(queue);
    op->queue        = queue;
    op->callback     = callback;
    op->private_data = private_data;
    op->size         = length;
    op->kind         = EVPL_BLOCK_OP_DISCARD;

    prometheus_stopwatch_start(&op->start);
    prometheus_gauge_add(queue->m_queue_depth, 1);

    queue->discard(evpl, queue, offset, length, evpl_block_complete, op);
} /* evpl_block_discard */

/* Emulated write-zeroes: an ordinary write from an internal zero buffer, for
 * backends without a native zeroing op.  One reusable zero chunk is written
 * across the range; the chunk's view length is trimmed for a short final
 * write.  Serial (one write outstanding) -- this is a cold/setup path. */
struct evpl_block_wz_emul {
    struct evpl_block_queue *queue;
    struct evpl_iovec        zero;
    uint64_t                 offset;
    uint64_t                 remaining;
    unsigned int             chunk;
    int                      status;
    evpl_block_callback_t    callback;
    void                    *private_data;
};

static void evpl_block_wz_emul_step(
    struct evpl               *evpl,
    struct evpl_block_wz_emul *e);

static void
evpl_block_wz_emul_done(
    struct evpl *evpl,
    int          status,
    void        *private_data)
{
    struct evpl_block_wz_emul *e = private_data;

    if (status) {
        e->status = status;
    }

    if (e->status || e->remaining == 0) {
        evpl_block_callback_t callback     = e->callback;
        void                 *cb_private   = e->private_data;
        int                   final_status = e->status;

        evpl_iovec_release_internal(evpl, &e->zero);
        evpl_free(e);
        callback(evpl, final_status, cb_private);
        return;
    }

    evpl_block_wz_emul_step(evpl, e);
} /* evpl_block_wz_emul_done */

static void
evpl_block_wz_emul_step(
    struct evpl               *evpl,
    struct evpl_block_wz_emul *e)
{
    uint64_t n   = e->remaining < e->chunk ? e->remaining : e->chunk;
    uint64_t off = e->offset;

    e->zero.length = (unsigned int) n;
    e->offset     += n;
    e->remaining  -= n;

    evpl_block_write(evpl, e->queue, &e->zero, 1, off, 0,
                     evpl_block_wz_emul_done, e);
} /* evpl_block_wz_emul_step */

SYMBOL_EXPORT void
evpl_block_write_zeroes(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    uint64_t offset,
    uint64_t length,
    void ( *callback )(struct evpl *evpl, int status, void *private_data),
    void *private_data)
{
    struct evpl_block_op      *op;
    struct evpl_block_wz_emul *e;
    unsigned int               chunk;

    if (queue->write_zeroes) {
        op               = evpl_block_op_get(queue);
        op->queue        = queue;
        op->callback     = callback;
        op->private_data = private_data;
        op->size         = length;
        op->kind         = EVPL_BLOCK_OP_WRITE;

        prometheus_stopwatch_start(&op->start);
        prometheus_gauge_add(queue->m_queue_depth, 1);

        queue->write_zeroes(evpl, queue, offset, length,
                            evpl_block_complete, op);
        return;
    }

    if (length == 0) {
        callback(evpl, 0, private_data);
        return;
    }

    /* No native support: write a zero buffer through the ordinary write path,
     * chunked at the device's maximum request size.  The underlying writes
     * carry their own op-tracking/metrics, so no block_op is taken here. */
    chunk = (unsigned int) (length < queue->device->max_request_size ?
                            length : queue->device->max_request_size);

    e               = evpl_zalloc(sizeof(*e));
    e->queue        = queue;
    e->offset       = offset;
    e->remaining    = length;
    e->chunk        = chunk;
    e->status       = 0;
    e->callback     = callback;
    e->private_data = private_data;

    evpl_iovec_alloc(evpl, chunk, 4096, 1, 0, &e->zero);
    memset(e->zero.data, 0, chunk);

    evpl_block_wz_emul_step(evpl, e);
} /* evpl_block_write_zeroes */
