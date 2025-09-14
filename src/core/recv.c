// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <errno.h>

#include "core/macros.h"
#include "core/bind.h"
#include "core/protocol.h"
#include "core/evpl.h"

SYMBOL_EXPORT int
evpl_peek(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length)
{
    int                left = length, chunk;
    struct evpl_iovec *cur;
    void              *ptr = buffer;

    if (unlikely(!evpl || !bind || !buffer || length <= 0)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(!bind->protocol->stream)) {
        errno = EINVAL;
        return -1;
    }

    cur = evpl_iovec_ring_tail(&bind->iovec_recv);

    if (cur == NULL) {
        return 0;
    }

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }
        memcpy(ptr, cur->data, chunk);

        left -= chunk;
        ptr  += chunk;

        cur = evpl_iovec_ring_next(&bind->iovec_recv, cur);

        if (cur == NULL) {
            return length - left;
        }
    }

    return length;
} /* evpl_peek */

SYMBOL_EXPORT int
evpl_peekv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                maxiovecs,
    int                length)
{
    int                left = length, chunk, niovs = 0;
    struct evpl_iovec *cur, *out;

    if (unlikely(!evpl || !bind || !iovecs || maxiovecs <= 0 || length <= 0)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(!bind->protocol->stream)) {
        errno = EINVAL;
        return -1;
    }

    cur = evpl_iovec_ring_tail(&bind->iovec_recv);

    if (!cur) {
        return 0;
    }

    while (cur && left && niovs < maxiovecs) {
        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        out               = &iovecs[niovs++];
        out->data         = cur->data;
        out->length       = chunk;
        out->private_data = cur->private_data;

        left -= chunk;
        cur   = evpl_iovec_ring_next(&bind->iovec_recv, cur);
    }

    return niovs;
} /* evpl_peekv */


SYMBOL_EXPORT void
evpl_consume(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    int               length)
{
    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, length);
} /* evpl_consume */

SYMBOL_EXPORT int
evpl_read(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length)
{
    int                copied = 0, chunk;
    struct evpl_iovec *cur;

    if (unlikely(!evpl || !bind || !buffer || length <= 0)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(!bind->protocol->stream)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(bind->segment_callback)) {
        errno = EINVAL;
        return -1;
    }

    while (copied < length) {

        cur = evpl_iovec_ring_tail(&bind->iovec_recv);

        if (!cur) {
            break;
        }

        chunk = cur->length;

        if (chunk > length - copied) {
            chunk = length - copied;
        }

        memcpy(buffer + copied, cur->data, chunk);

        copied += chunk;

        evpl_iovec_ring_consume(evpl, &bind->iovec_recv, chunk);
    }

    return copied;

} /* evpl_read */

SYMBOL_EXPORT int
evpl_readv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                maxiovecs,
    int                length)
{
    int                left = length, chunk, niovs = 0;
    struct evpl_iovec *cur, *out;

    if (unlikely(!evpl || !bind || !iovecs || maxiovecs <= 0 || length <= 0)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(!bind->protocol->stream)) {
        errno = EINVAL;
        return -1;
    }

    if (unlikely(bind->segment_callback)) {
        errno = EINVAL;
        return -1;
    }

    while (left && niovs < maxiovecs) {

        cur = evpl_iovec_ring_tail(&bind->iovec_recv);

        if (!cur) {
            break;
        }

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        out = &iovecs[niovs++];

        out->data         = cur->data;
        out->length       = chunk;
        out->private_data = cur->private_data;
        atomic_fetch_add_explicit(&evpl_iovec_buffer(out)->refcnt, 1,
                                  memory_order_relaxed)
        ;

        left -= chunk;

        evpl_iovec_ring_consume(evpl, &bind->iovec_recv, chunk);
    }

    return niovs;

} /* evpl_readv */

SYMBOL_EXPORT int
evpl_recv(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *buffer,
    int               length)
{
    int                left = length, chunk;
    struct evpl_iovec *cur;
    void              *ptr   = buffer;
    uint64_t           avail = evpl_iovec_ring_bytes(&bind->iovec_recv);

    if (avail < length) {
        return -1;
    }

    cur = evpl_iovec_ring_tail(&bind->iovec_recv);

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        memcpy(ptr, cur->data, chunk);

        left -= chunk;

        cur = evpl_iovec_ring_next(&bind->iovec_recv, cur);
    }

    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, length);

    return length;

} /* evpl_recv */

int
evpl_recvv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                maxiovecs,
    int                length)
{
    int                left = length, chunk, niovs = 0;
    struct evpl_iovec *cur, *out;
    uint64_t           avail = evpl_iovec_ring_bytes(&bind->iovec_recv);

    if (avail < length) {
        return -1;
    }

    cur = evpl_iovec_ring_tail(&bind->iovec_recv);

    while (cur && left) {

        chunk = cur->length;

        if (chunk > left) {
            chunk = left;
        }

        if (niovs == maxiovecs) {
            return -1;
        }

        out = &iovecs[niovs++];

        out->data         = cur->data;
        out->length       = chunk;
        out->private_data = cur->private_data;
        atomic_fetch_add_explicit(&evpl_iovec_buffer(out)->refcnt, 1,
                                  memory_order_relaxed)
        ;

        left -= chunk;

        cur = evpl_iovec_ring_next(&bind->iovec_recv, cur);
    }

    if (left) {
        return -1;
    }

    evpl_iovec_ring_consume(evpl, &bind->iovec_recv, length);

    return niovs;
} /* evpl_recvv */

int
evpl_recv_peek_iovec(
    struct evpl       *evpl,
    struct evpl_bind  *conn,
    struct evpl_iovec *iovecs,
    int                nbufvecs,
    int                length)
{
    int niovs = 0, left = length;

    do{

    } while (left);

    return niovs;

} /* evpl_recv_peek_iovec */