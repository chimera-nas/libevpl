// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <pthread.h>

#define EVPL_INTERNAL 1

#include "core/allocator.h"
#include "core/logging.h"

#include "evpl/evpl.h"


struct evpl_allocator {
    struct evpl_slab   *slabs;
    struct evpl_buffer *free_buffers;
    int                 hugepages;
    pthread_mutex_t     lock;
};

struct evpl_buffer {
    void                 *data;
    unsigned int          used;
    unsigned int          size;

    struct evpl_iovec_ref ref;

    struct evpl_buffer   *next;
} __attribute__((aligned(64)));


struct evpl_allocator *
evpl_allocator_create();

void
evpl_allocator_destroy(
    struct evpl_allocator *allocator);

void
evpl_allocator_reregister(
    struct evpl_allocator *allocator);

struct evpl_buffer *
evpl_allocator_alloc(
    struct evpl_allocator *allocator);

void *
evpl_allocator_alloc_slab(
    struct evpl_allocator *allocator,
    void                 **slab_private);

void
evpl_allocator_free(
    struct evpl_allocator *allocator,
    struct evpl_buffer    *buffer);

void *
evpl_memory_framework_private(
    const struct evpl_iovec *iov,
    int                      framework_id);


static inline void
evpl_buffer_release(struct evpl_buffer *buffer)
{

    buffer->ref.refcnt--;

    if (buffer->ref.refcnt == 0) {
        buffer->ref.flags = EVPL_IOVEC_REC_FLAG_FREE;
        buffer->ref.release(&buffer->ref);
    }

} /* evpl_buffer_release */

struct evpl_buffer *
evpl_buffer_alloc(
    struct evpl *evpl);

static inline unsigned int
evpl_buffer_left(struct evpl_buffer *buffer)
{
    return buffer->size - buffer->used;
} // evpl_buffer_left

static inline unsigned int
evpl_buffer_pad(
    struct evpl_buffer *buffer,
    unsigned int        alignment)
{
    if (alignment == 0) {
        return 0;
    }

    return (alignment - (buffer->used & (alignment - 1))) & (alignment - 1);
} // evpl_buffer_pad
