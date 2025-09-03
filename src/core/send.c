// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/macros.h"
#include "core/bind.h"
#include "core/evpl.h"

SYMBOL_EXPORT void
evpl_send(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    const void       *buffer,
    unsigned int      length)
{
    struct evpl_iovec iovecs[4];
    int               niov;

    niov = evpl_iovec_alloc(evpl, length, 0, 4, iovecs);

    evpl_core_abort_if(niov < 1, "failed to allocate bounce space");

    evpl_iovec_memcpy(iovecs, buffer, length);

    evpl_sendv(evpl, bind, iovecs, niov, length);

} /* evpl_send */

SYMBOL_EXPORT void
evpl_sendto(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *address,
    const void          *buffer,
    unsigned int         length)
{
    struct evpl_iovec iovecs[4];
    int               niov;

    niov = evpl_iovec_alloc(evpl, length, 0, 4, iovecs);

    evpl_core_abort_if(niov < 1, "failed to allocate bounce space");

    evpl_iovec_memcpy(iovecs, buffer, length);

    evpl_sendtov(evpl, bind, address, iovecs, niov, length);

} /* evpl_sendto */

SYMBOL_EXPORT void
evpl_sendtoep(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    const void           *buffer,
    unsigned int          length)
{
    struct evpl_iovec iovecs[4];
    int               niov;

    niov = evpl_iovec_alloc(evpl, length, 0, 4, iovecs);

    evpl_core_abort_if(niov < 1, "failed to allocate bounce space");

    evpl_iovec_memcpy(iovecs, buffer, length);

    evpl_sendtoepv(evpl, bind, endpoint, iovecs, niov, length);

} /* evpl_sendto */

SYMBOL_EXPORT void
evpl_sendv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                niovs,
    int                length)
{
    struct evpl_dgram *dgram;
    struct evpl_iovec *iovec;
    int                i, left = length;

    if (unlikely(niovs == 0)) {
        return;
    }

    for (i = 0; left && i < niovs; ++i) {
        iovec = evpl_iovec_ring_add(&bind->iovec_send, &iovecs[i]);

        if (iovec->length <= left) {
            left -= iovec->length;
        } else {
            bind->iovec_send.length -= iovec->length - left;
            iovec->length            = left;
            left                     = 0;
        }
    }

    evpl_core_abort_if(left,
                       "evpl_send provided iov %d bytes short of covering length of %d",
                       left, length);

    dgram         = evpl_dgram_ring_add(&bind->dgram_send);
    dgram->niov   = i;
    dgram->length = length;
    dgram->addr   = bind->remote;

    evpl_defer(evpl, &bind->flush_deferral);

    for (; i < niovs; ++i) {
        evpl_iovec_decref(&iovecs[i]);
    }

} /* evpl_sendv */

SYMBOL_EXPORT void
evpl_sendtov(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *address,
    struct evpl_iovec   *iovecs,
    int                  niovs,
    int                  length)
{
    struct evpl_dgram *dgram;
    struct evpl_iovec *iovec;
    int                i, left = length;

    if (unlikely(niovs == 0)) {
        return;
    }

    for (i = 0; left && i < niovs; ++i) {
        iovec = evpl_iovec_ring_add(&bind->iovec_send, &iovecs[i]);

        if (iovec->length <= left) {
            left -= iovec->length;
        } else {
            bind->iovec_send.length -= iovec->length - left;
            iovec->length            = left;
            left                     = 0;
        }
    }

    evpl_core_abort_if(left,
                       "evpl_send provided iov %d bytes short of covering length of %d",
                       left, length);

    dgram = evpl_dgram_ring_add(&bind->dgram_send);

    dgram->niov   = i;
    dgram->length = length;
    dgram->addr   = address;

    evpl_defer(evpl, &bind->flush_deferral);

    for (; i < niovs; ++i) {
        evpl_iovec_decref(&iovecs[i]);
    }

} /* evpl_sendtov */

SYMBOL_EXPORT void
evpl_sendtoepv(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    struct evpl_iovec    *iovecs,
    int                   nbufvecs,
    int                   length)
{
    evpl_sendtov(evpl, bind, evpl_endpoint_resolve(endpoint), iovecs, nbufvecs, length);
} /* evpl_sendtoepv */