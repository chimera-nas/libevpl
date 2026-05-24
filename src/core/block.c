// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <pthread.h>
#include <time.h>

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
    struct timespec          start;
    uint64_t                 size;
    struct evpl_block_queue *queue;
    evpl_block_callback_t    callback;
    void                    *private_data;
    struct evpl_block_op    *next;
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
    struct timespec          now;
    int64_t                  elapsed;

    evpl_get_hf_monotonic_time(evpl, &now);
    elapsed = evpl_ts_interval(&now, &op->start);

    /* prometheus_histogram_sample() bucketizes via clz, which is
     * undefined at zero, so floor the latency at one nanosecond.
     */
    prometheus_histogram_sample(queue->m_latency, elapsed > 0 ? elapsed : 1);

    if (op->size) {
        prometheus_histogram_sample(queue->m_request_size, op->size);
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

    evpl_attach_framework_shared(protocol->framework->id);

    protocol_private_data = evpl_shared->framework_private[protocol->framework->
                                                           id];

    blockdev = protocol->open_device(uri, protocol_private_data);

    blockdev->protocol = protocol;

    /* Per-device metric series, labelled with the device URI and the
     * protocol type so callers can aggregate across all devices or
     * break out by device/type.
     */
    blockdev->m_latency = prometheus_histogram_create_series(
        evpl_shared->block_latency,
        (const char *[]) { "device", "type" },
        (const char *[]) { uri, protocol->name }, 2);

    blockdev->m_request_size = prometheus_histogram_create_series(
        evpl_shared->block_request_size,
        (const char *[]) { "device", "type" },
        (const char *[]) { uri, protocol->name }, 2);

    blockdev->m_queue_depth = prometheus_gauge_create_series(
        evpl_shared->block_queue_depth,
        (const char *[]) { "device", "type" },
        (const char *[]) { uri, protocol->name }, 2);

    return blockdev;
} /* evpl_block_open_device */

SYMBOL_EXPORT void
evpl_block_close_device(struct evpl_block_device *bdev)
{
    prometheus_histogram_destroy_series(evpl_shared->block_latency,
                                        bdev->m_latency);
    prometheus_histogram_destroy_series(evpl_shared->block_request_size,
                                        bdev->m_request_size);
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
    queue->m_latency = prometheus_histogram_series_create_instance(
        blockdev->m_latency);
    queue->m_request_size = prometheus_histogram_series_create_instance(
        blockdev->m_request_size);
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

    prometheus_histogram_series_destroy_instance(bdev->m_latency,
                                                 queue->m_latency);
    prometheus_histogram_series_destroy_instance(bdev->m_request_size,
                                                 queue->m_request_size);
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

    evpl_get_hf_monotonic_time(evpl, &op->start);
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

    evpl_get_hf_monotonic_time(evpl, &op->start);
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

    evpl_get_hf_monotonic_time(evpl, &op->start);
    prometheus_gauge_add(queue->m_queue_depth, 1);

    queue->flush(evpl, queue, evpl_block_complete, op);
} /* evpl_block_flush */
