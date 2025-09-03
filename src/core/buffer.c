// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/buffer.h"
#include "core/allocator.h"
#include "core/logging.h"
#include "core/macros.h"
#include "core/evpl_shared.h"

struct evpl_buffer *
evpl_buffer_alloc(struct evpl *evpl)
{
    struct evpl_buffer *buffer;

    buffer = evpl_allocator_alloc(evpl_shared->allocator);

    atomic_store(&buffer->refcnt, 1);
    buffer->used      = 0;
    buffer->external1 = NULL;
    buffer->external2 = NULL;

    return buffer;
} /* evpl_buffer_alloc */