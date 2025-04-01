#include <errno.h>

#include "core/macros.h"
#include "core/bind.h"
#include "core/protocol.h"
#include "core/evpl.h"

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

    if (unlikely(!protocol->rdma_read)) {
        callback(ENOTSUP, private_data);
        return;
    }

    protocol->rdma_read(evpl, bind, remote_key, remote_address, iov, niov,
                        callback, private_data);
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

    if (unlikely(!protocol->rdma_write)) {
        callback(ENOTSUP, private_data);
        return;
    }

    protocol->rdma_write(evpl, bind, remote_key, remote_address, iov, niov,
                         callback, private_data);
} /* evpl_rdma_write */