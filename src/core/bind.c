// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <utlist.h>

#include "core/macros.h"
#include "core/evpl_shared.h"
#include "core/bind.h"
#include "core/evpl.h"

SYMBOL_EXPORT struct evpl_bind *
evpl_connect(
    struct evpl            *evpl,
    enum evpl_protocol_id   protocol_id,
    struct evpl_endpoint   *local_endpoint,
    struct evpl_endpoint   *remote_endpoint,
    evpl_notify_callback_t  notify_callback,
    evpl_segment_callback_t segment_callback,
    void                   *private_data)
{
    struct evpl_bind     *bind;
    struct evpl_protocol *protocol = evpl_shared->protocol[protocol_id];

    if (!protocol) {
        return NULL;
    }

    evpl_core_abort_if(!protocol->connect,
                       "Called evpl_connect with non-connection oriented protocol");

    bind = evpl_bind_prepare(evpl, protocol,
                             local_endpoint ? evpl_endpoint_resolve(local_endpoint) : NULL,
                             evpl_endpoint_resolve(remote_endpoint));
    bind->notify_callback  = notify_callback;
    bind->segment_callback = segment_callback;
    bind->private_data     = private_data;

    bind->protocol->connect(evpl, bind);

    return bind;
} /* evpl_connect */

SYMBOL_EXPORT struct evpl_bind *
evpl_bind(
    struct evpl           *evpl,
    enum evpl_protocol_id  protocol_id,
    struct evpl_endpoint  *endpoint,
    evpl_notify_callback_t callback,
    void                  *private_data)
{
    struct evpl_bind     *bind;
    struct evpl_protocol *protocol = evpl_shared->protocol[protocol_id];

    evpl_core_abort_if(!protocol->bind,
                       "Called evpl_bind with connection oriented protocol");

    bind = evpl_bind_prepare(evpl, protocol, evpl_endpoint_resolve(endpoint), NULL);

    bind->notify_callback  = callback;
    bind->segment_callback = NULL;
    bind->private_data     = private_data;

    bind->protocol->bind(evpl, bind);

    return bind;
} /* evpl_bind */


static void
evpl_bind_close_deferral(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_bind *bind = private_data;

    evpl_core_abort_if(bind->flags & EVPL_BIND_CLOSED,
                       "bind %p already closed", bind);

    evpl_core_abort_if(!(bind->flags & EVPL_BIND_PENDING_CLOSED),
                       "bind %p in close deferral but not pending close ", bind)
    ;

    DL_DELETE(evpl->binds, bind);
    DL_APPEND(evpl->pending_close_binds, bind);

    bind->protocol->pending_close(evpl, bind);
} /* evpl_bind_close_deferral */

static void
evpl_bind_flush_deferral(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_bind *conn = private_data;

    if (unlikely(evpl->running == 0)) {
        return;
    }

    if (conn->protocol->flush) {
        conn->protocol->flush(evpl, conn);
    }
} /* evpl_bind_flush_deferral */


struct evpl_bind *
evpl_bind_prepare(
    struct evpl          *evpl,
    struct evpl_protocol *protocol,
    struct evpl_address  *local,
    struct evpl_address  *remote)
{
    struct evpl_framework *framework = protocol->framework;
    struct evpl_bind      *bind;

    if (framework) {
        evpl_attach_framework(evpl, framework->id);
    }

    if (evpl->free_binds) {
        bind = evpl->free_binds;
        DL_DELETE(evpl->free_binds, bind);
    } else {

        bind = evpl_zalloc(sizeof(*bind) + EVPL_MAX_PRIVATE);

        evpl_iovec_ring_alloc(
            &bind->iovec_send,
            evpl_shared->config->iovec_ring_size,
            evpl_shared->config->page_size);

        evpl_dgram_ring_alloc(
            &bind->dgram_send,
            evpl_shared->config->dgram_ring_size,
            evpl_shared->config->page_size);

        evpl_iovec_ring_alloc(
            &bind->iovec_rdma_read,
            evpl_shared->config->iovec_ring_size,
            evpl_shared->config->page_size);

        evpl_iovec_ring_alloc(
            &bind->iovec_send_framed,
            evpl_shared->config->iovec_ring_size,
            evpl_shared->config->page_size);

        evpl_iovec_ring_alloc(
            &bind->iovec_recv,
            evpl_shared->config->iovec_ring_size,
            evpl_shared->config->page_size);

        evpl_dgram_ring_alloc(
            &bind->dgram_read,
            evpl_shared->config->dgram_ring_size,
            evpl_shared->config->page_size);

        evpl_deferral_init(&bind->close_deferral,
                           evpl_bind_close_deferral, bind);

        evpl_deferral_init(&bind->flush_deferral,
                           evpl_bind_flush_deferral, bind);
    }

    DL_APPEND(evpl->binds, bind);

    bind->notify_callback  = NULL;
    bind->segment_callback = NULL;
    bind->private_data     = NULL;
    bind->flags            = 0;

    bind->protocol = protocol;
    bind->local    = local;
    bind->remote   = remote;

    memset(bind + 1, 0, EVPL_MAX_PRIVATE);

    return bind;
} /* evpl_bind_prepare */

SYMBOL_EXPORT void
evpl_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{

    evpl_core_abort_if(bind->flags & EVPL_BIND_CLOSED,
                       "bind %p already closed", bind);

    if (!(bind->flags & EVPL_BIND_PENDING_CLOSED)) {
        bind->flags |= EVPL_BIND_PENDING_CLOSED;
        evpl_defer(evpl, &bind->close_deferral);
    }
} /* evpl_close */

SYMBOL_EXPORT void
evpl_finish(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{

    bind->flags |= EVPL_BIND_FINISH;

    /* Close once nothing is left to send.  Transports that frame their output
     * (TCP_RDMA) hold ready-to-write bytes in iovec_send_framed, so it must be
     * drained too, not just the raw iovec_send staging ring. */
    if (evpl_iovec_ring_is_empty(&bind->iovec_send) &&
        evpl_iovec_ring_is_empty(&bind->iovec_send_framed)) {
        evpl_close(evpl, bind);
    }

} /* evpl_finish */

void
evpl_bind_destroy(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_notify notify;

    evpl_core_abort_if(!(bind->flags & EVPL_BIND_PENDING_CLOSED),
                       "bind %p not pending closed at destroy", bind);

    if (bind->notify_callback) {
        notify.notify_type   = EVPL_NOTIFY_DISCONNECTED;
        notify.notify_status = 0;

        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

    evpl_iovec_ring_clear(evpl, &bind->iovec_recv);
    evpl_iovec_ring_clear(evpl, &bind->iovec_send);
    evpl_iovec_ring_clear(evpl, &bind->iovec_send_framed);
    evpl_dgram_ring_clear(evpl, &bind->dgram_send);
    evpl_dgram_ring_clear(evpl, &bind->dgram_read);

    bind->flags |= EVPL_BIND_CLOSED;

    if (bind->local) {
        evpl_address_release(bind->local);
    }

    if (bind->remote) {
        evpl_address_release(bind->remote);
    }
    DL_DELETE(evpl->pending_close_binds, bind);
    DL_PREPEND(evpl->free_binds, bind);
} /* evpl_bind_destroy */

SYMBOL_EXPORT void
evpl_bind_get_local_address(
    struct evpl_bind *bind,
    char             *str,
    int               len)
{
    evpl_address_get_address(bind->local, str, len);
} /* evpl_bind_get_local_address */

SYMBOL_EXPORT void
evpl_bind_get_remote_address(
    struct evpl_bind *bind,
    char             *str,
    int               len)
{
    evpl_address_get_address(bind->remote, str, len);
} /* evpl_bind_get_remote_address */

SYMBOL_EXPORT enum evpl_protocol_id
evpl_bind_get_protocol(struct evpl_bind *bind)
{
    return bind->protocol->id;
} /* evpl_bind_get_protocol */

SYMBOL_EXPORT int
evpl_bind_is_rdma(struct evpl_bind *bind)
{
    return bind->protocol->rdma;
} /* evpl_bind_is_rdma */

SYMBOL_EXPORT int
evpl_bind_is_closing(struct evpl_bind *bind)
{
    /* True once the peer's close has been observed on this bind but before the
     * deferred destroy dispatches EVPL_NOTIFY_DISCONNECTED: a read-side FIN
     * (recv returns 0) calls evpl_close, which sets EVPL_BIND_PENDING_CLOSED
     * synchronously and defers the destroy; a half-close (evpl_finish) sets
     * EVPL_BIND_FINISH; the destroy itself sets EVPL_BIND_CLOSED.  A genuinely
     * live bind has none of these set.  Lets a caller distinguish a peer that is
     * on its way out (its reservations will be released once the disconnect
     * callback lands) from one that is still fully connected. */
    return (bind->flags & (EVPL_BIND_PENDING_CLOSED |
                           EVPL_BIND_CLOSED |
                           EVPL_BIND_FINISH)) != 0;
} /* evpl_bind_is_closing */

SYMBOL_EXPORT void
evpl_bind_request_send_notifications(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    bind->flags |= EVPL_BIND_SENT_NOTIFY;
} /* evpl_bind_request_send_notifications */
