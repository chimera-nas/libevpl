// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once
#include "evpl/evpl_export.h"

#ifndef EVPL_INCLUDED
#error "Do not include evpl_block.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

#include <stdint.h>

struct evpl_block_device;
struct evpl_block_queue;

typedef void (*evpl_block_callback_t)(
    struct evpl *evpl,
    int          status,
    void        *private_data);

/*
 * Completion for evpl_block_open_device.  blockdev is the opened device, or
 * NULL on failure; status is 0 on success or a positive errno.
 */
typedef void (*evpl_block_open_callback_t)(
    struct evpl              *evpl,
    struct evpl_block_device *blockdev,
    int                       status,
    void                     *private_data);

/*
 * Open a block device asynchronously.  Like all libevpl operations this runs
 * in the context of an event loop: the callback fires from a later iteration
 * of `evpl`'s loop (never inline from this call), including for failures.
 *
 * The opening evpl owns the device for lifecycle purposes: it must outlive
 * the device, backend device events (e.g. hot-remove) are handled on its
 * thread, and evpl_block_close_device must be called with this same evpl.
 * Queues may still be opened against the device from any evpl thread.
 */
EVPL_API void evpl_block_open_device(
    struct evpl                *evpl,
    enum evpl_block_protocol_id protocol,
    const char                 *uri,
    evpl_block_open_callback_t  callback,
    void                       *private_data);

/*
 * Close a block device asynchronously.  Must be called on the evpl that
 * opened the device, after all of its queues have been closed.  The callback
 * (which may be NULL) fires from a later loop iteration once the backend has
 * released the device; blockdev is invalid as soon as this is called.
 */
EVPL_API void evpl_block_close_device(
    struct evpl              *evpl,
    struct evpl_block_device *blockdev,
    evpl_block_callback_t     callback,
    void                     *private_data);

EVPL_API uint64_t evpl_block_size(
    struct evpl_block_device *blockdev);

EVPL_API uint64_t evpl_block_max_request_size(
    struct evpl_block_device *blockdev);

EVPL_API struct evpl_block_queue *
evpl_block_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *blockdev);

EVPL_API void evpl_block_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *queue);

EVPL_API void evpl_block_read(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec       *iov,
    int                      niov,
    uint64_t                 offset,
    evpl_block_callback_t    callback,
    void                    *private_data);

EVPL_API void evpl_block_write(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int                      niov,
    uint64_t                 offset,
    int                      sync,
    evpl_block_callback_t    callback,
    void                    *private_data);

EVPL_API void evpl_block_flush(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    evpl_block_callback_t    callback,
    void                    *private_data);

/*
 * Discard (deallocate / unmap / TRIM) the byte range [offset, offset+length).
 * This is an advisory hint that the range is no longer needed: the backend may
 * drop its mappings for it (NVMe Dataset Management Deallocate), but is not
 * required to, and the data read back afterwards is unspecified.  Backends that
 * cannot discard treat it as a successful no-op.
 */
EVPL_API void evpl_block_discard(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    uint64_t                 offset,
    uint64_t                 length,
    evpl_block_callback_t    callback,
    void                    *private_data);

/*
 * Write zeros to the byte range [offset, offset+length).  Unlike discard this
 * is a data guarantee: the range reads back as zeros afterwards.  Backends with
 * native support use it (NVMe Write Zeroes); the rest emulate it with an
 * ordinary write from an internal zero buffer.
 */
EVPL_API void evpl_block_write_zeroes(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    uint64_t                 offset,
    uint64_t                 length,
    evpl_block_callback_t    callback,
    void                    *private_data);
enum evpl_block_event {
    EVPL_BLOCK_EVENT_REMOVE,
    EVPL_BLOCK_EVENT_RESIZE
};
typedef void (*evpl_block_event_callback_t)(
    struct evpl              *evpl,
    struct evpl_block_device *device,
    enum evpl_block_event     event,
    void                     *private_data);
/* Register on the opener's context; notifications run there. On removal,
 * close every queue, then the device. Size is readable from other threads. */
EVPL_API void evpl_block_set_event_callback(
    struct evpl_block_device   *device,
    evpl_block_event_callback_t callback,
    void                       *private_data);
