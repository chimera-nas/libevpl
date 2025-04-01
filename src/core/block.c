
#include <pthread.h>

#include "core/evpl_shared.h"
#include "core/macros.h"
#include "core/evpl.h"

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

    return blockdev;
} /* evpl_block_open_device */

SYMBOL_EXPORT void
evpl_block_close_device(struct evpl_block_device *bdev)
{
    bdev->close_device(bdev);
} /* evpl_block_close_device */

uint64_t
evpl_block_size(struct evpl_block_device *bdev)
{
    return bdev->size;
} /* evpl_block_size */

uint64_t
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

    queue->protocol = blockdev->protocol;

    return queue;
} /* evpl_block_open_queue */

SYMBOL_EXPORT void
evpl_block_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *queue)
{
    queue->close_queue(evpl, queue);
} /* evpl_block_close_queue */


SYMBOL_EXPORT void
evpl_block_read(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    queue->read(evpl, queue, iov, niov, offset, callback, private_data);
} /* evpl_block_read */

SYMBOL_EXPORT void
evpl_block_write(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int niov,
    uint64_t offset,
    int sync,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    queue->write(evpl, queue, iov, niov, offset, sync, callback, private_data);
} /* evpl_block_write */

SYMBOL_EXPORT void
evpl_block_flush(
    struct evpl *evpl,
    struct evpl_block_queue *queue,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    queue->flush(evpl, queue, callback, private_data);
} /* evpl_block_flush */
