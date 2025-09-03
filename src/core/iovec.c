// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/evpl.h"
#include "core/iovec.h"
#include "core/buffer.h"
#include "core/macros.h"
#include "core/evpl_shared.h"
#include "evpl/evpl.h"

SYMBOL_EXPORT void
evpl_iovec_release(struct evpl_iovec *iovec)
{
    evpl_iovec_decref(iovec);
} /* evpl_iovec_release */

SYMBOL_EXPORT void
evpl_iovec_addref(struct evpl_iovec *iovec)
{
    evpl_iovec_incref(iovec);
} /* evpl_iovec_addref */


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
            evpl->current_buffer = evpl_buffer_alloc(evpl);
        }

        buffer = evpl->current_buffer;

        pad = evpl_buffer_pad(buffer, alignment);

        chunk = (buffer->size - buffer->used);

        if (chunk < pad + left && niovs + 1 <= max_iovecs) {
            evpl_buffer_release(buffer);
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

        iovec->private_data = buffer;
        iovec->data         = buffer->data + buffer->used + pad;
        iovec->length       = chunk - pad;

        left -= chunk - pad;

        if (left) {
            evpl_buffer_release(buffer);
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

        buffer = evpl_iovec_buffer(iovec);

        if (buffer) {

        }
        atomic_fetch_add_explicit(&buffer->refcnt, 1, memory_order_relaxed);

        buffer->used  = (iovec->data + iovec->length) - buffer->data;
        buffer->used += evpl_buffer_pad(buffer, alignment);
    }

    buffer = evpl->current_buffer;

    if (buffer && buffer->size - buffer->used < 64) {
        evpl_buffer_release(buffer);
        evpl->current_buffer = NULL;
    }
} /* evpl_iovec_commit */

SYMBOL_EXPORT int
evpl_iovec_alloc(
    struct evpl       *evpl,
    unsigned int       length,
    unsigned int       alignment,
    unsigned int       max_iovecs,
    struct evpl_iovec *r_iovec)
{
    int niovs;

    niovs = evpl_iovec_reserve(evpl, length, alignment, max_iovecs, r_iovec);

    if (unlikely(niovs < 0)) {
        return niovs;
    }

    evpl_iovec_commit(evpl, alignment, r_iovec, niovs);

    return niovs;
} /* evpl_iovec_alloc */

void
evpl_iovec_alloc_whole(
    struct evpl       *evpl,
    struct evpl_iovec *r_iovec)
{
    struct evpl_buffer *buffer;

    buffer = evpl_buffer_alloc(evpl);

    r_iovec->data         = buffer->data;
    r_iovec->length       = buffer->size;
    r_iovec->private_data = buffer;
} /* evpl_iovec_alloc_whole */

void
evpl_iovec_alloc_datagram(
    struct evpl       *evpl,
    struct evpl_iovec *r_iovec,
    int                size)
{
    struct evpl_buffer *buffer;

    if (!evpl->datagram_buffer) {
        evpl->datagram_buffer = evpl_buffer_alloc(evpl);
    }

    buffer = evpl->datagram_buffer;

    r_iovec->data         = buffer->data + buffer->used;
    r_iovec->length       = size;
    r_iovec->private_data = buffer;

    buffer->used += size;
    atomic_fetch_add_explicit(&buffer->refcnt, 1, memory_order_relaxed);

    if (buffer->size - buffer->used < evpl_shared->config->max_datagram_size) {
        evpl_buffer_release(evpl->datagram_buffer);
        evpl->datagram_buffer = NULL;
    }

} /* evpl_iovec_alloc_datagram */