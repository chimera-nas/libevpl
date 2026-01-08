// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/evpl.h"
#include "core/iovec.h"
#include "core/allocator.h"
#include "core/macros.h"
#include "core/evpl_shared.h"
#include "evpl/evpl.h"

SYMBOL_EXPORT int
evpl_iovec_reserve(
    struct evpl       *evpl,
    unsigned int       length,
    unsigned int       alignment,
    unsigned int       max_iovecs,
    struct evpl_iovec *r_iovec)
{
    struct evpl_buffer *buffer;
    int                 pad, left = length, chunk;
    int                 niovs = 0;
    struct evpl_iovec  *iovec;

    do{

        if (evpl->current_buffer == NULL) {
            evpl->current_buffer = evpl_buffer_alloc(evpl, 0);
        }

        buffer = evpl->current_buffer;

        pad = evpl_buffer_pad(buffer, alignment);

        chunk = (buffer->size - buffer->used);

        if (chunk < pad + left && niovs + 1 <= max_iovecs) {
            evpl_buffer_release(evpl, buffer);
            evpl->current_buffer = NULL;
            continue;
        }

        if (chunk > pad + left) {
            chunk = pad + left;
        }

        if (unlikely(niovs + 1 > max_iovecs)) {
            return -1;
        }

        iovec = &r_iovec[niovs++];

        iovec->data   = buffer->data + buffer->used + pad;
        iovec->length = chunk - pad;

        evpl_iovec_take_ref(iovec, &buffer->ref);

        left -= chunk - pad;

        if (left) {
            evpl_buffer_release(evpl, buffer);
            evpl->current_buffer = NULL;
        }

    } while (left);

    return niovs;
} /* evpl_iovec_reserve */

SYMBOL_EXPORT void
evpl_iovec_commit(
    struct evpl       *evpl,
    unsigned int       alignment,
    struct evpl_iovec *iovecs,
    int                niovs)
{
    int                 i;
    struct evpl_iovec  *iovec;
    struct evpl_buffer *buffer;

    for (i = 0; i < niovs; ++i) {

        iovec = &iovecs[i];

        buffer = container_of(evpl_iovec_get_ref(iovec), struct evpl_buffer, ref);

        buffer->used  = (iovec->data + iovec->length) - buffer->data;
        buffer->used += evpl_buffer_pad(buffer, alignment);
    }

} /* evpl_iovec_commit */

SYMBOL_EXPORT int
evpl_iovec_alloc(
    struct evpl       *evpl,
    unsigned int       length,
    unsigned int       alignment,
    unsigned int       max_iovecs,
    unsigned int       flags,
    struct evpl_iovec *r_iovec)
{
    struct evpl_buffer **bufferp;
    struct evpl_buffer  *buffer;
    int                  pad, left = length, chunk;
    int                  niovs = 0;
    struct evpl_iovec   *iovec;

    /* Select between local and shared buffer based on flags */
    if (flags & EVPL_IOVEC_FLAG_SHARED) {
        bufferp = &evpl->shared_buffer;
    } else {
        bufferp = &evpl->current_buffer;
    }

    do {

        if (*bufferp == NULL) {
            *bufferp = evpl_buffer_alloc(evpl, flags);
        }

        buffer = *bufferp;

        pad = evpl_buffer_pad(buffer, alignment);

        chunk = (buffer->size - buffer->used);

        if (chunk < pad + left && niovs + 1 <= max_iovecs) {
            evpl_buffer_release(evpl, buffer);
            *bufferp = NULL;
            continue;
        }

        if (chunk > pad + left) {
            chunk = pad + left;
        }

        if (unlikely(niovs + 1 > max_iovecs)) {
            return -1;
        }

        iovec = &r_iovec[niovs++];

        iovec->data   = buffer->data + buffer->used + pad;
        iovec->length = chunk - pad;

        evpl_iovec_take_ref(iovec, &buffer->ref);

        buffer->used += chunk;
        buffer->used += evpl_buffer_pad(buffer, alignment);

        left -= chunk - pad;

        if (left) {
            evpl_buffer_release(evpl, buffer);
            *bufferp = NULL;
        }

    } while (left);

    return niovs;
} /* evpl_iovec_alloc */

void
evpl_iovec_alloc_whole(
    struct evpl       *evpl,
    struct evpl_iovec *r_iovec)
{
    struct evpl_buffer *buffer;

    buffer = evpl_buffer_alloc(evpl, 0);

    r_iovec->data   = buffer->data;
    r_iovec->length = buffer->size;
    evpl_iovec_set_ref(r_iovec, &buffer->ref);
} /* evpl_iovec_alloc_whole */

void
evpl_iovec_alloc_datagram(
    struct evpl       *evpl,
    struct evpl_iovec *r_iovec,
    int                size)
{
    struct evpl_buffer *buffer;

    if (!evpl->datagram_buffer) {
        evpl->datagram_buffer = evpl_buffer_alloc(evpl, 0);
    }

    buffer = evpl->datagram_buffer;

    r_iovec->data   = buffer->data + buffer->used;
    r_iovec->length = size;

    buffer->used += size;

    evpl_iovec_take_ref(r_iovec, &buffer->ref);

    if (buffer->size - buffer->used < evpl_shared->config->max_datagram_size) {
        evpl_buffer_release(evpl, evpl->datagram_buffer);
        evpl->datagram_buffer = NULL;
    }

} /* evpl_iovec_alloc_datagram */