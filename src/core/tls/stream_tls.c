// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only

/* TLS records over a libevpl byte stream. The crypto engine never receives a
 * native socket handle; the TCP backend owns asynchronous buffer lifetimes. */
#include "core/os.h"
#include "core/bind.h"
#include "core/endpoint.h"
#include "core/tls/engine.h"
#include "core/tls/tls.h"
#include "core/socket/tcp.h"

struct evpl_stream_tls {
    struct evpl_bind       *wire;
    struct evpl_tls_engine *engine;
    uint64_t                wire_pending;
    unsigned int            plaintext_pending;
    int                     ready;
    int                     driving;
    int                     shutdown;
};

static void evpl_stream_tls_drive(
    struct evpl *,
    struct evpl_bind *);

static int
evpl_stream_tls_closed(struct evpl_bind *bind)
{
    return (bind->flags & EVPL_BIND_PENDING_CLOSED) != 0;
} /* evpl_stream_tls_closed */

static int
evpl_stream_tls_result(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    int               result)
{
    if (result < 0) {
        evpl_close(evpl, bind);
    }
    return result > 0;
} /* evpl_stream_tls_result */

static void
evpl_stream_tls_output(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_stream_tls *t = evpl_bind_private(bind);
    char                    bytes[16384];
    int                     length;

    while ((length = evpl_tls_engine_output(t->engine, bytes, sizeof(bytes))) > 0) {
        t->wire_pending += length;
        evpl_send(evpl, t->wire, bytes, length);
    }
} /* evpl_stream_tls_output */

static void
evpl_stream_tls_deliver(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *plain,
    unsigned int       length)
{
    struct evpl_notify notify = { 0 };
    struct evpl_iovec *iov;
    int                frame_length;

    evpl_iovec_ring_append(evpl, &bind->iovec_recv, plain, length);
    if (!bind->segment_callback) {
        notify.notify_type = EVPL_NOTIFY_RECV_DATA;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
        return;
    }
    iov = alloca(sizeof(*iov) * evpl_shared->config->max_num_iovec);
    while (!evpl_stream_tls_closed(bind)) {
        frame_length = bind->segment_callback(evpl, bind, bind->private_data);
        if (evpl_stream_tls_closed(bind)) {
            break;
        }
        if (frame_length < 0) {
            evpl_close(evpl, bind); break;
        }
        if (!frame_length || evpl_iovec_ring_bytes(&bind->iovec_recv) < (uint64_t) frame_length) {
            break;
        }
        notify.notify_type   = EVPL_NOTIFY_RECV_MSG;
        notify.recv_msg.niov = evpl_iovec_ring_copyv_bounded(evpl, iov, evpl_shared->config->max_num_iovec, &bind->
                                                             iovec_recv, frame_length);
        if (notify.recv_msg.niov < 0) {
            evpl_close(evpl, bind);
            break;
        }
        notify.recv_msg.iovec  = iov;
        notify.recv_msg.length = frame_length;
        notify.recv_msg.addr   = bind->remote;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }
} /* evpl_stream_tls_deliver */

static void
evpl_stream_tls_sent(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_stream_tls *t = evpl_bind_private(bind);
    struct evpl_dgram      *dgram;
    struct evpl_notify      notify = { 0 };
    int                     niov, messages = 0;
    unsigned int            bytes = t->plaintext_pending;

    if (!bytes || t->wire_pending) {
        return;
    }
    t->plaintext_pending = 0;
    niov                 = evpl_iovec_ring_consume(evpl, &bind->iovec_send, bytes);
    while (niov && (dgram = evpl_dgram_ring_tail(&bind->dgram_send)) != NULL) {
        if (dgram->niov > niov) {
            dgram->niov -= niov; break;
        }
        niov -= dgram->niov;
        evpl_dgram_ring_remove(&bind->dgram_send);
        messages++;
    }
    if (bind->flags & EVPL_BIND_SENT_NOTIFY) {
        notify.notify_type = EVPL_NOTIFY_SENT;
        notify.sent.bytes  = bytes;
        notify.sent.msgs   = messages;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }
} /* evpl_stream_tls_sent */

static void
evpl_stream_tls_drive(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_stream_tls *t      = evpl_bind_private(bind);
    struct evpl_notify      notify = { 0 };
    struct evpl_iovec       plain = { 0 }, *iov;
    int                     result;
    size_t                  length;

    if (t->driving || !t->engine || evpl_stream_tls_closed(bind)) {
        return;
    }
    t->driving = 1;
    if (!t->ready) {
        result = evpl_tls_engine_handshake(t->engine);
        if (evpl_stream_tls_result(evpl, bind, result)) {
            t->ready           = 1;
            notify.notify_type = EVPL_NOTIFY_CONNECTED;
            bind->notify_callback(evpl, bind, &notify, bind->private_data);
        }
    }
    if (evpl_stream_tls_closed(bind)) {
        goto out;
    }
    if (t->ready && !t->shutdown) {
        evpl_iovec_alloc_whole(evpl, &plain);
        for (;;) {
            result = evpl_tls_engine_read(t->engine, plain.data, plain.length, &length);
            if (!evpl_stream_tls_result(evpl, bind, result)) {
                break;
            }
            evpl_stream_tls_deliver(evpl, bind, &plain, (unsigned int) length);
            if (evpl_stream_tls_closed(bind)) {
                break;
            }
            if (!plain.length) {
                evpl_iovec_alloc_whole(evpl, &plain);
            }
        }
        if (plain.length) {
            evpl_iovec_release_internal(evpl, &plain);
        }
    }
    if (evpl_stream_tls_closed(bind)) {
        goto out;
    }
    evpl_stream_tls_output(evpl, bind);
    if (t->ready && !t->wire_pending && !t->plaintext_pending && !t->shutdown) {
        iov = evpl_iovec_ring_tail(&bind->iovec_send);
        if (iov) {
            result = evpl_tls_engine_write(t->engine, iov->data, iov->length, &length);
            if (evpl_stream_tls_result(evpl, bind, result)) {
                t->plaintext_pending = (unsigned int) length;
            }
            if (evpl_stream_tls_closed(bind)) {
                goto out;
            }
            evpl_stream_tls_output(evpl, bind);
        } else if (bind->flags & EVPL_BIND_FINISH) {
            t->shutdown = 1;
            evpl_tls_engine_shutdown(t->engine);
            evpl_stream_tls_output(evpl, bind);
            evpl_finish(evpl, t->wire);
        }
    }
 out:
    t->driving = 0;
} /* evpl_stream_tls_drive */

static void
evpl_stream_tls_wire_notify(
    struct evpl        *evpl,
    struct evpl_bind   *wire,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct evpl_bind       *bind = private_data;
    struct evpl_stream_tls *t    = evpl_bind_private(bind);
    char                    bytes[16384];
    int                     length;

    if (notify->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        t->wire = NULL;
        evpl_bind_operation_end(bind);
        evpl_close(evpl, bind);
        return;
    }
    if (evpl_stream_tls_closed(bind)) {
        return;
    }
    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            if (bind->local) {
                evpl_address_release(bind->local);
            }
            bind->local = wire->local;
            evpl_address_incref(bind->local);
            break;
        case EVPL_NOTIFY_RECV_DATA:
            while ((length = evpl_recv(evpl, wire, bytes, sizeof(bytes), 0)) > 0) {
                if (evpl_tls_engine_input(t->engine, bytes, length) != length) {
                    evpl_close(evpl, bind); return;
                }
                evpl_stream_tls_drive(evpl, bind);
                if (evpl_stream_tls_closed(bind)) {
                    return;
                }
            }
            break;
        case EVPL_NOTIFY_SENT:
            evpl_core_assert(notify->sent.bytes <= t->wire_pending);
            t->wire_pending -= notify->sent.bytes;
            evpl_stream_tls_sent(evpl, bind);
            break;
        default:
            return;
    } /* switch */
    evpl_stream_tls_drive(evpl, bind);
} /* evpl_stream_tls_wire_notify */

static struct evpl_bind *
evpl_stream_tls_wire(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    int               server,
    int               listener)
{
    struct evpl_stream_tls *t = evpl_bind_private(bind);

    if (bind->local) {
        evpl_address_incref(bind->local);
    }
    if (bind->remote) {
        evpl_address_incref(bind->remote);
    }
    t->wire                  = evpl_bind_prepare(evpl, &evpl_socket_tcp, bind->local, bind->remote);
    t->wire->notify_callback = evpl_stream_tls_wire_notify;
    t->wire->private_data    = bind;
    t->wire->flags          |= EVPL_BIND_SENT_NOTIFY;
    evpl_bind_operation_begin(bind);
    if (!listener) {
        t->engine = evpl_tls_engine_create(evpl, server);
        evpl_core_abort_if(!t->engine, "TLS engine allocation failed");
    }
    return t->wire;
} /* evpl_stream_tls_wire */

static void
evpl_stream_tls_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    evpl_socket_tcp.connect(evpl, evpl_stream_tls_wire(evpl, bind, 0, 0));
} /* evpl_stream_tls_connect */
static void
evpl_stream_tls_discard(
    struct evpl *evpl,
    void        *accepted)
{
    evpl_socket_tcp.discard_accepted(evpl, accepted);
} /* evpl_stream_tls_discard */

static void
evpl_stream_tls_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    evpl_socket_tcp.attach(evpl, evpl_stream_tls_wire(evpl, bind, 1, 0), accepted);
} /* evpl_stream_tls_attach */
static void
evpl_stream_tls_accept(
    struct evpl         *evpl,
    struct evpl_bind    *wire,
    struct evpl_address *remote,
    void                *accepted,
    void                *private_data)
{
    struct evpl_bind *bind = private_data;

    (void) wire;
    bind->accept_callback(evpl, bind, remote, accepted, bind->private_data);
} /* evpl_stream_tls_accept */
static int
evpl_stream_tls_listen(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_stream_tls *t    = evpl_bind_private(bind);
    struct evpl_bind       *wire = evpl_stream_tls_wire(evpl, bind, 1, 1);

    wire->accept_callback = evpl_stream_tls_accept;
    if (evpl_socket_tcp.listen(evpl, wire)) {
        evpl_bind_abort(evpl, wire);
        t->wire = NULL;
        evpl_bind_operation_end(bind);
        return -1;
    }
    return 0;
} /* evpl_stream_tls_listen */
static void
evpl_stream_tls_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_stream_tls *t = evpl_bind_private(bind);

    if (t->wire) {
        evpl_close(evpl, t->wire);
    }
} /* evpl_stream_tls_pending_close */
static void
evpl_stream_tls_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_stream_tls *t = evpl_bind_private(bind);

    (void) evpl;
    evpl_core_assert(!t->wire && !bind->outstanding);
    evpl_tls_engine_free(t->engine);
} /* evpl_stream_tls_close */
static void
evpl_stream_tls_finish(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    evpl_defer(evpl, &bind->flush_deferral);
} /* evpl_stream_tls_finish */
SYMBOL_EXPORT int
evpl_tls_get_alpn(
    struct evpl_bind *bind,
    char             *buf,
    int               size)
{
    struct evpl_stream_tls *t;

    if (size > 0) {
        buf[0] = 0;
    }
    if (bind->protocol->id != EVPL_STREAM_SOCKET_TLS) {
        return 0;
    }
    t = evpl_bind_private(bind);
    return t->engine && t->ready ? evpl_tls_engine_alpn(t->engine, buf, size) : 0;
} /* evpl_tls_get_alpn */
struct evpl_protocol evpl_socket_tls = {
    .id               = EVPL_STREAM_SOCKET_TLS,
    .connected        = 1,
    .stream           = 1,
    .name             = "STREAM_SOCKET_TLS",
    .framework        = &evpl_framework_tls,
    .connect          = evpl_stream_tls_connect,
    .attach           = evpl_stream_tls_attach,
    .discard_accepted = evpl_stream_tls_discard,
    .listen           = evpl_stream_tls_listen,
    .pending_close    = evpl_stream_tls_pending_close,
    .close            = evpl_stream_tls_close,
    .flush            = evpl_stream_tls_drive,
    .finish           = evpl_stream_tls_finish,
};
