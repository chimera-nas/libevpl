// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <pthread.h>

#include "core/buffer.h"
#include "core/logging.h"


struct evpl_allocator {
    struct evpl_slab   *slabs;
    struct evpl_buffer *free_buffers;
    int                 hugepages;
    pthread_mutex_t     lock;
};

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
    struct evpl_allocator *allocator);

void
evpl_allocator_free(
    struct evpl_allocator *allocator,
    struct evpl_buffer    *buffer);

void *
evpl_buffer_framework_private(
    struct evpl_buffer *buffer,
    int                 framework_id);


static inline void
evpl_buffer_release(struct evpl_buffer *buffer)
{
    int refset;

    refset = atomic_fetch_sub_explicit(&buffer->refcnt, 1, memory_order_relaxed);

    evpl_core_abort_if(refset < 0, "refcnt underflow for buffer %p", buffer);

    if (refset == 1) {
        if (buffer->external1) {
            buffer->release(buffer);
        } else {
            buffer->used = 0;
            evpl_allocator_free(buffer->allocator, buffer);
        }
    }

} /* evpl_buffer_release */
