// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <errno.h>

#include "core/macros.h"
#include "core/bind.h"
#include "core/protocol.h"
#include "core/evpl.h"
#include "core/rdma_request.h"


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

    if (unlikely(!protocol->rdma)) {
        callback(ENOTSUP, private_data);
        return;
    }

    evpl_rdma_request_ring_add(
        &bind->rdma_rw,
        EVPL_RDMA_READ,
        remote_key,
        remote_address,
        iov,
        niov,
        callback,
        private_data);


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
    void ( *callback )(int status, void *private_data),
    void *private_data)
{
    struct evpl_protocol *protocol = bind->protocol;

    if (unlikely(!protocol->rdma)) {
        callback(ENOTSUP, private_data);
        return;
    }

    evpl_rdma_request_ring_add(
        &bind->rdma_rw,
        EVPL_RDMA_WRITE,
        remote_key,
        remote_address,
        iov,
        niov,
        callback,
        private_data);

    evpl_defer(evpl, &bind->flush_deferral);
} /* evpl_rdma_write */