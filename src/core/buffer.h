/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

#include <string.h>
#include <sys/uio.h>

#include "core/evpl.h"
#include "core/internal.h"

struct evpl_slab {
    void             *data;
    uint64_t          size;
    void             *framework_private[EVPL_NUM_FRAMEWORK];
    struct evpl_slab *next;
};

struct evpl_buffer {
    void               *data;
    int                 refcnt;
    unsigned int        used;
    unsigned int        size;

    struct evpl_slab   *slab;

    void               *external;
    void                (*release)(
        struct evpl *evpl,
        struct evpl_buffer *);

    struct evpl_buffer *next;
};

struct evpl_allocator {
    struct evpl_slab   *slabs;
    struct evpl_buffer *free_buffers;
    pthread_mutex_t     lock;
};

void evpl_buffer_release(
    struct evpl        *evpl,
    struct evpl_buffer *buffer);

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

void
evpl_allocator_free(
    struct evpl_allocator *allocator,
    struct evpl_buffer    *buffers);

static inline void *
evpl_buffer_framework_private(
    struct evpl_buffer *buffer,
    int                 framework_id)
{
    return buffer->slab->framework_private[framework_id];
} // evpl_buffer_framework_private


/*
 * Copy 'length' bytes of data from 'buffer' into
 * an array of byte vectors 'bvecs'.
 * Sufficient vectors or space is not checked.
 */

static inline void
evpl_bvec_memcpy(
    struct evpl_bvec *bvecs,
    const void       *buffer,
    unsigned int      length)
{
    struct evpl_bvec *bvec = bvecs;
    const void       *ptr  = buffer;
    unsigned int      left = length, chunk;

    while (left) {

        chunk = left;

        if (bvec->length < chunk) {
            chunk = bvec->length;
        }

        memcpy(bvec->data, ptr, chunk);

        ptr  += chunk;
        left -= chunk;
        bvec++;
    }

} // evpl_bvec_memcpy

static inline void
evpl_bvec_decref(
    struct evpl      *evpl,
    struct evpl_bvec *bvec)
{
    struct evpl_buffer *buffer = bvec->buffer;

    evpl_core_abort_if(buffer->refcnt == 0,
                       "Released bvec %p with zero refcnt", bvec);


    evpl_buffer_release(evpl, buffer);

} // evpl_bvec_decref

static inline void
evpl_bvec_incref(
    struct evpl      *evpl,
    struct evpl_bvec *bvec)
{
    struct evpl_buffer *buffer = bvec->buffer;

    ++buffer->refcnt;

} // evpl_bvec_incref



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
