// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdatomic.h>

struct evpl;
struct evpl_slab;
struct evpl_allocator;

struct evpl_buffer {
    void                  *data;
    atomic_int             refcnt;
    unsigned int           used;
    unsigned int           size;

    struct evpl_slab      *slab;
    struct evpl_allocator *allocator;

    void                  *external1;
    void                  *external2;
    void                   (*release)(
        struct evpl_buffer *);

    struct evpl_buffer    *next;
};

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