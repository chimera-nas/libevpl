// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <errno.h>

#include "core/macros.h"
#include "core/bind.h"
#include "core/protocol.h"
#include "core/evpl.h"

SYMBOL_EXPORT void
evpl_rdma_get_address(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovec,
    uint32_t          *r_key,
    uint64_t          *r_address)
{
    struct evpl_protocol  *protocol  = bind->protocol;
    struct evpl_framework *framework = protocol->framework;

    if (unlikely(!protocol->rdma)) {
        *r_key     = 0;
        *r_address = 0;
        return;
    }

    framework->get_rdma_address(bind, iovec, r_key, r_address);
} /* evpl_rdma_get_address */

SYMBOL_EXPORT void
evpl_rdma_read(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    struct evpl_protocol *protocol = bind->protocol;
    int                   i, length = 0;
    struct evpl_dgram    *dgram;
    struct evpl_iovec    *iovec;

    if (unlikely(!protocol->rdma)) {
        callback(ENOTSUP, private_data);
        return;
    }

    for (i = 0; i < niov; ++i) {
        iovec = evpl_iovec_ring_add(&bind->iovec_rdma_read, &iov[i]);

        length += iovec->length;
    }

    dgram = evpl_dgram_ring_add(&bind->dgram_read);

    dgram->dgram_type     = EVPL_DGRAM_TYPE_RDMA_READ;
    dgram->bind           = bind;
    dgram->niov           = niov;
    dgram->length         = length;
    dgram->addr           = bind->remote;
    dgram->remote_key     = remote_key;
    dgram->remote_address = remote_address;
    dgram->callback       = callback;
    dgram->private_data   = private_data;

    evpl_defer(evpl, &bind->flush_deferral);
} /* evpl_rdma_read */

SYMBOL_EXPORT void
evpl_rdma_write(
    struct evpl *evpl,
    struct evpl_bind *bind,
    uint32_t remote_key,
    uint64_t remote_address,
    struct evpl_iovec *iov,
    int niov,
    unsigned int flags,
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    struct evpl_dgram    *dgram;
    struct evpl_iovec    *iovec;
    int                   i, length = 0;
    struct evpl_protocol *protocol = bind->protocol;

    if (unlikely(!protocol->rdma)) {
        callback(ENOTSUP, private_data);
        return;
    }

    if (unlikely(niov == 0)) {
        return;
    }

    for (i = 0; i < niov; ++i) {
        if (flags & EVPL_RDMA_FLAG_TAKE_REF) {
            iovec = evpl_iovec_ring_add(&bind->iovec_send, &iov[i]);
        } else {
            iovec = evpl_iovec_ring_add_clone(&bind->iovec_send, &iov[i]);
        }

        length += iovec->length;
    }

    dgram = evpl_dgram_ring_add(&bind->dgram_send);

    dgram->dgram_type     = EVPL_DGRAM_TYPE_RDMA_WRITE;
    dgram->bind           = bind;
    dgram->niov           = niov;
    dgram->length         = length;
    dgram->addr           = bind->remote;
    dgram->remote_key     = remote_key;
    dgram->remote_address = remote_address;
    dgram->callback       = callback;
    dgram->private_data   = private_data;

    evpl_defer(evpl, &bind->flush_deferral);
} /* evpl_rdma_write */