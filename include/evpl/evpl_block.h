// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_block.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

#include <stdint.h>

struct evpl_block_device;
struct evpl_block_queue;

struct evpl_block_device *
evpl_block_open_device(
    enum evpl_block_protocol_id protocol,
    const char                 *uri);

void evpl_block_close_device(
    struct evpl_block_device *blockdev);

uint64_t evpl_block_size(
    struct evpl_block_device *blockdev);

uint64_t evpl_block_max_request_size(
    struct evpl_block_device *blockdev);

struct evpl_block_queue *
evpl_block_open_queue(
    struct evpl              *evpl,
    struct evpl_block_device *blockdev);

void evpl_block_close_queue(
    struct evpl             *evpl,
    struct evpl_block_queue *queue);

typedef void (*evpl_block_callback_t)(
    struct evpl *evpl,
    int          status,
    void        *private_data);

void evpl_block_read(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    struct evpl_iovec       *iov,
    int                      niov,
    uint64_t                 offset,
    evpl_block_callback_t    callback,
    void                    *private_data);

void evpl_block_write(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    const struct evpl_iovec *iov,
    int                      niov,
    uint64_t                 offset,
    int                      sync,
    evpl_block_callback_t    callback,
    void                    *private_data);

void evpl_block_flush(
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
void evpl_block_discard(
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
void evpl_block_write_zeroes(
    struct evpl             *evpl,
    struct evpl_block_queue *queue,
    uint64_t                 offset,
    uint64_t                 length,
    evpl_block_callback_t    callback,
    void                    *private_data);