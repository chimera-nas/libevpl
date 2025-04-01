#pragma once

#include <string.h>

#include "core/buffer.h"
#include "core/allocator.h"
#include "core/iovec.h"
#include "evpl/evpl.h"

#define evpl_iovec_buffer(iov) ((struct evpl_buffer *) (iov)->private)


/* Allocate a iovec representing an entire evpl_buffer
 * guaranteed to be contiguous
 */

void evpl_iovec_alloc_whole(
    struct evpl       *evpl,
    struct evpl_iovec *r_iovec);

/*
 * Allocate a iovec to hold one datagram of maximal size
 * guaranteed to be contiguous
 */
void evpl_iovec_alloc_datagram(
    struct evpl       *evpl,
    struct evpl_iovec *r_iovec,
    int                size);

/*
 * Copy 'length' bytes of data from 'buffer' into
 * an array of byte vectors 'iovecs'.
 * Sufficient vectors or space is not checked.
 */

static inline void
evpl_iovec_memcpy(
    struct evpl_iovec *iovecs,
    const void        *buffer,
    unsigned int       length)
{
    struct evpl_iovec *iovec = iovecs;
    const void        *ptr   = buffer;
    unsigned int       left = length, chunk;

    while (left) {

        chunk = left;

        if (iovec->length < chunk) {
            chunk = iovec->length;
        }

        memcpy(iovec->data, ptr, chunk);

        ptr  += chunk;
        left -= chunk;
        iovec++;
    }

} // evpl_iovec_memcpy

static inline void
evpl_iovec_decref(struct evpl_iovec *iovec)
{
    struct evpl_buffer *buffer = evpl_iovec_buffer(iovec);

    if (!buffer) {
        return;
    }

    evpl_buffer_release(buffer);

} // evpl_iovec_decref

static inline void
evpl_iovec_incref(struct evpl_iovec *iovec)
{
    struct evpl_buffer *buffer = evpl_iovec_buffer(iovec);

    atomic_fetch_add_explicit(&buffer->refcnt, 1, memory_order_relaxed);

} // evpl_iovec_incref