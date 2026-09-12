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
    evpl_sendto(evpl, bind, bind->remote, buffer, length);
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

    niov = evpl_iovec_alloc(evpl, length, 0, 4, 0, iovecs);

    evpl_core_abort_if(niov < 1, "failed to allocate bounce space");

    evpl_iovec_memcpy(iovecs, buffer, length);

    evpl_sendtov(evpl, bind, address, iovecs, niov, length, EVPL_SEND_FLAG_TAKE_REF);

} /* evpl_sendto */

SYMBOL_EXPORT void
evpl_sendtoep(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    const void           *buffer,
    unsigned int          length)
{
    struct evpl_address *address = evpl_endpoint_resolve(endpoint);

    evpl_sendto(evpl, bind, address, buffer, length);
    evpl_address_release(address);
} /* evpl_sendto */

SYMBOL_EXPORT void
evpl_sendv(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovecs,
    int                niovs,
    int                length,
    unsigned int       flags)
{
    evpl_sendtov(evpl, bind, bind->remote, iovecs, niovs, length, flags);
} /* evpl_sendv */

SYMBOL_EXPORT void
evpl_sendtov(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct evpl_address *address,
    struct evpl_iovec   *iovecs,
    int                  niovs,
    int                  length,
    unsigned int         flags)
{
    struct evpl_dgram *dgram;
    struct evpl_iovec *iovec;
    int                i, left = length;

    if (unlikely(niovs == 0)) {
        return;
    }

    for (i = 0; left && i < niovs; ++i) {
        if (flags & EVPL_SEND_FLAG_TAKE_REF) {
            iovec = evpl_iovec_ring_add(&bind->iovec_send, &iovecs[i]);
        } else {
            iovec = evpl_iovec_ring_add_clone(&bind->iovec_send, &iovecs[i]);
        }

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

    dgram->dgram_type = EVPL_DGRAM_TYPE_SEND;
    dgram->bind       = bind;
    dgram->niov       = i;
    dgram->length     = length;
    dgram->addr       = address;
    /* Datagram backends release the destination after sending (or closing).
     * A received peer address is borrowed only for the notify callback, so
     * the queued send needs its own reference. Connected binds own theirs. */
    if (!bind->protocol->connected) {
        evpl_address_incref(address);
    }
    dgram->callback     = NULL;
    dgram->private_data = NULL;

    evpl_defer(evpl, &bind->flush_deferral);

    if (flags & EVPL_SEND_FLAG_TAKE_REF) {
        evpl_iovecs_release_internal(evpl, &iovecs[i], niovs - i);
    }

} /* evpl_sendtov */

SYMBOL_EXPORT void
evpl_sendtoepv(
    struct evpl          *evpl,
    struct evpl_bind     *bind,
    struct evpl_endpoint *endpoint,
    struct evpl_iovec    *iovecs,
    int                   nbufvecs,
    int                   length,
    unsigned int          flags)
{
    struct evpl_address *address = evpl_endpoint_resolve(endpoint);

    evpl_sendtov(evpl, bind, address, iovecs, nbufvecs, length, flags);
    evpl_address_release(address);
} /* evpl_sendtoepv */