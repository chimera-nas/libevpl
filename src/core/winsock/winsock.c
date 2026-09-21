// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
#include <mswsock.h>
#include <mstcpip.h>
#include "core/bind.h"
#include "core/iocp.h"
#include "core/endpoint.h"

/* Requests own every address, descriptor and receive buffer the kernel may
 * still touch. Send payload stays in the bind's ring until completion; bind
 * retirement cannot clear that ring while a request owns the bind. */
enum evpl_win_operation { WIN_CONNECT, WIN_ACCEPT, WIN_RECV, WIN_SEND };
struct evpl_win_request {
    struct evpl_iocp_request iocp;
    struct evpl_bind        *owner;
    enum evpl_win_operation  operation;
    DWORD                    submit_error;
    DWORD                    flags;
    SOCKET                   accepted;
    struct sockaddr_storage  address;
    int                      address_length;
    char                     accept_addresses[2 * (sizeof(struct sockaddr_storage) + 16)];
    struct evpl_iovec        recv;
    unsigned int             count;
    WSABUF                   buffers[];
};
struct evpl_winsock {
    SOCKET        socket;
    int           connected;
    int           receiving;
    int           sending;
    LPFN_ACCEPTEX accept_ex;
};
struct evpl_win_accepted { SOCKET socket; };

static void evpl_win_receive(
    struct evpl *,
    struct evpl_bind *);
static void evpl_win_flush(
    struct evpl *,
    struct evpl_bind *);
static void evpl_win_accept(
    struct evpl *,
    struct evpl_bind *);
static void evpl_win_complete(
    struct evpl *,
    struct evpl_iocp_request *,
    DWORD,
    DWORD);

static int
evpl_win_closing(struct evpl_bind *bind)
{
    return (bind->flags & EVPL_BIND_PENDING_CLOSED) != 0;
} /* evpl_win_closing */

static struct evpl_win_request *
evpl_win_request(
    struct evpl_bind       *bind,
    enum evpl_win_operation operation,
    unsigned int            count)
{
    struct evpl_win_request *request = evpl_zalloc(sizeof(*request) + sizeof(WSABUF) * count);

    request->iocp.callback = evpl_win_complete;
    request->owner         = bind;
    request->operation     = operation;
    request->accepted      = INVALID_SOCKET;
    request->count         = count;
    evpl_bind_operation_begin(bind);
    return request;
} /* evpl_win_request */

/* Immediate submission errors have no kernel completion. Post our own so
 * neither successful nor failed submissions invoke application callbacks
 * recursively from connect/flush. Immediate success still queues a kernel
 * packet: we never enable FILE_SKIP_COMPLETION_PORT_ON_SUCCESS. */
static void
evpl_win_submitted(
    struct evpl             *evpl,
    struct evpl_win_request *request,
    int                      success)
{
    DWORD error;

    if (success) {
        return;
    }
    error = WSAGetLastError();
    if (error == WSA_IO_PENDING) {
        return;
    }
    request->submit_error = error;
    evpl_core_abort_if(evpl_iocp_post(evpl, &request->iocp), "IOCP error delivery failed");
} /* evpl_win_submitted */

static void
evpl_win_connected(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_winsock *s      = evpl_bind_private(bind);
    struct evpl_notify   notify = { 0 };
    int                  yes    = 1;

    if (!bind->local) {
        bind->local = evpl_address_alloc();
    }
    bind->local->addrlen = sizeof(bind->local->sa);
    if (getsockname(s->socket, bind->local->addr, &bind->local->addrlen)) {
        evpl_close(evpl, bind);
        return;
    }
    setsockopt(s->socket, IPPROTO_TCP, TCP_NODELAY, (const char *) &yes, sizeof(yes));
    s->connected       = 1;
    notify.notify_type = EVPL_NOTIFY_CONNECTED;
    bind->notify_callback(evpl, bind, &notify, bind->private_data);
    if (!evpl_win_closing(bind)) {
        evpl_win_receive(evpl, bind);
        evpl_win_flush(evpl, bind);
    }
} /* evpl_win_connected */

static void
evpl_win_deliver_stream(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    struct evpl_win_request *request,
    DWORD                    bytes)
{
    struct evpl_notify notify = { 0 };
    struct evpl_iovec *iov;
    int                length, niov;

    evpl_iovec_ring_append(evpl, &bind->iovec_recv, &request->recv, bytes);
    if (!bind->segment_callback) {
        notify.notify_type = EVPL_NOTIFY_RECV_DATA;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
        return;
    }
    iov = alloca(sizeof(*iov) * evpl_shared->config->max_num_iovec);
    while (!evpl_win_closing(bind)) {
        length = bind->segment_callback(evpl, bind, bind->private_data);
        if (evpl_win_closing(bind)) {
            break;
        }
        if (length < 0) {
            evpl_close(evpl, bind); break;
        }
        if (!length || evpl_iovec_ring_bytes(&bind->iovec_recv) < (uint64_t) length) {
            break;
        }
        niov = evpl_iovec_ring_copyv_bounded(evpl, iov, evpl_shared->config->max_num_iovec, &bind->iovec_recv, length);
        if (niov < 0) {
            evpl_close(evpl, bind);
            break;
        }
        notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
        notify.recv_msg.iovec  = iov;
        notify.recv_msg.niov   = niov;
        notify.recv_msg.length = length;
        notify.recv_msg.addr   = bind->remote;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }
} /* evpl_win_deliver_stream */

static void
evpl_win_complete(
    struct evpl              *evpl,
    struct evpl_iocp_request *iocp,
    DWORD                     bytes,
    DWORD                     error)
{
    struct evpl_win_request  *request = container_of(iocp, struct evpl_win_request, iocp);
    struct evpl_bind         *bind    = request->owner;
    struct evpl_winsock      *s       = evpl_bind_private(bind);
    struct evpl_notify        notify  = { 0 };
    struct evpl_address      *address;
    struct evpl_win_accepted *accepted;
    struct evpl_dgram        *dgram;
    int                       niov, messages = 0;

    if (request->submit_error) {
        error = request->submit_error;
    }
    if (request->operation == WIN_RECV) {
        s->receiving = 0;
    }
    if (request->operation == WIN_SEND) {
        s->sending = 0;
    }
    if (evpl_win_closing(bind)) {
        goto out;
    }
    /* A truncated UDP packet is discarded in full; a zero-length packet is
     * valid and follows the ordinary receive-message path below. */
    if (error && request->operation == WIN_RECV && !bind->protocol->stream &&
        (error == WSAEMSGSIZE || error == ERROR_MORE_DATA)) {
        evpl_win_receive(evpl, bind);
        goto out;
    }
    if (error) {
        evpl_core_error("Winsock %s operation %d failed: %lu", bind->protocol->name, request->operation, error);
        evpl_close(evpl, bind); goto out;
    }
    switch (request->operation) {
        case WIN_CONNECT:
            if (setsockopt(s->socket, SOL_SOCKET, SO_UPDATE_CONNECT_CONTEXT, NULL, 0)) {
                evpl_close(evpl, bind);
            } else {
                evpl_win_connected(evpl, bind);
            }
            break;
        case WIN_ACCEPT:
            if (setsockopt(request->accepted, SOL_SOCKET, SO_UPDATE_ACCEPT_CONTEXT,
                           (const char *) &s->socket, sizeof(s->socket))) {
                evpl_win_accept(evpl, bind);
                break;
            }
            address          = evpl_address_alloc();
            address->addrlen = sizeof(address->sa);
            if (getpeername(request->accepted, address->addr, &address->addrlen)) {
                evpl_address_release(address);
                evpl_win_accept(evpl, bind);
                break;
            }
            accepted          = evpl_zalloc(sizeof(*accepted));
            accepted->socket  = request->accepted;
            request->accepted = INVALID_SOCKET;
            /* This socket has never been associated with a port. The worker
            * that attaches it chooses its one and only IOCP association. */
            bind->accept_callback(evpl, bind, address, accepted, bind->private_data);
            if (!evpl_win_closing(bind)) {
                evpl_win_accept(evpl, bind);
            }
            break;
        case WIN_RECV:
            if (bind->protocol->stream) {
                if (!bytes) {
                    evpl_close(evpl, bind); break;
                }
                evpl_win_deliver_stream(evpl, bind, request, bytes);
            } else {
                address = evpl_address_init((struct sockaddr *) &request->address, request->
                                            address_length);
                request->recv.length   = bytes;
                notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
                notify.recv_msg.iovec  = &request->recv;
                notify.recv_msg.niov   = 1;
                notify.recv_msg.length = bytes;
                notify.recv_msg.addr   = address;
                bind->notify_callback(evpl, bind, &notify, bind->private_data);
                request->recv.data = NULL; /* callback owns the receive iovec */
                evpl_address_release(address);
            }
            if (!evpl_win_closing(bind)) {
                evpl_win_receive(evpl, bind);
            }
            break;
        case WIN_SEND:
            if (!bind->protocol->stream) {
                dgram = evpl_dgram_ring_tail(&bind->dgram_send);
                evpl_core_assert(dgram && bytes == dgram->length);
                evpl_address_release(dgram->addr);
                evpl_iovec_ring_consumev(evpl, &bind->iovec_send, dgram->niov);
                evpl_dgram_ring_remove(&bind->dgram_send);
                messages = 1;
            } else {
                if (!bytes) {
                    evpl_close(evpl, bind); break;
                }
                niov = evpl_iovec_ring_consume(evpl, &bind->iovec_send, bytes);
                while (niov && (dgram = evpl_dgram_ring_tail(&bind->dgram_send)) != NULL) {
                    if (dgram->niov > niov) {
                        dgram->niov -= niov; break;
                    }
                    niov -= dgram->niov;
                    evpl_dgram_ring_remove(&bind->dgram_send);
                    messages++;
                }
            }
            if (bind->flags & EVPL_BIND_SENT_NOTIFY) {
                notify.notify_type = EVPL_NOTIFY_SENT;
                notify.sent.bytes  = bytes;
                notify.sent.msgs   = messages;
                bind->notify_callback(evpl, bind, &notify, bind->private_data);
            }
            if (!evpl_win_closing(bind)) {
                evpl_win_flush(evpl, bind);
            }
            break;
    } /* switch */
 out:
    if (request->recv.data && request->recv.length) {
        evpl_iovec_release_internal(evpl, &request->recv);
    }
    if (request->accepted != INVALID_SOCKET) {
        closesocket(request->accepted);
    }
    evpl_bind_operation_end(bind);
    evpl_free(request);
} /* evpl_win_complete */

static void
evpl_win_receive(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_winsock     *s = evpl_bind_private(bind);
    struct evpl_win_request *request;
    int                      rc;

    if (s->receiving || evpl_win_closing(bind)) {
        return;
    }
    request = evpl_win_request(bind, WIN_RECV, 1);
    if (bind->protocol->stream) {
        evpl_iovec_alloc_whole(evpl, &request->recv);
    } else {
        evpl_iovec_alloc_datagram(evpl, &request->recv, evpl_shared->config->max_datagram_size);
    }
    request->buffers[0].buf = request->recv.data;
    request->buffers[0].len = request->recv.length;
    s->receiving            = 1;
    if (bind->protocol->stream) {
        rc = WSARecv(s->socket, request->buffers, 1, NULL, &request->flags,
                     &request->iocp.overlapped, NULL);
    } else {
        request->address_length = sizeof(request->address);
        rc                      = WSARecvFrom(s->socket, request->buffers, 1, NULL, &request->flags,
                                              (struct sockaddr *) &request->address, &request->address_length,
                                              &request->iocp.overlapped, NULL);
    }
    evpl_win_submitted(evpl, request, rc == 0);
} /* evpl_win_receive */

static void
evpl_win_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_winsock     *s = evpl_bind_private(bind);
    struct evpl_win_request *request;
    struct evpl_iovec       *iov;
    struct evpl_dgram       *dgram;
    unsigned int             count = 0, limit = evpl_shared->config->max_num_iovec;
    int                      rc;

    if (s->sending || evpl_win_closing(bind) || (bind->protocol->stream && !s->connected)) {
        return;
    }
    dgram = evpl_dgram_ring_tail(&bind->dgram_send);
    if ((!bind->protocol->stream && !dgram) ||
        (bind->protocol->stream && evpl_iovec_ring_is_empty(&bind->iovec_send))) {
        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_close(evpl, bind);
        }
        return;
    }
    if (!bind->protocol->stream) {
        limit = dgram->niov;
    }
    request = evpl_win_request(bind, WIN_SEND, limit ? limit : 1);
    iov     = evpl_iovec_ring_tail(&bind->iovec_send);
    while (iov && count < limit) {
        request->buffers[count].buf = iov->data;
        request->buffers[count].len = iov->length;
        count++;
        iov = evpl_iovec_ring_next(&bind->iovec_send, iov);
    }
    if (!count) {
        request->buffers[0].buf = NULL; request->buffers[0].len = 0; count = 1;
    }
    s->sending = 1;
    if (bind->protocol->stream) {
        rc = WSASend(s->socket, request->buffers, count, NULL, 0, &request->iocp.overlapped, NULL);
    } else {
        memcpy(&request->address, dgram->addr->addr, dgram->addr->addrlen);
        request->address_length = dgram->addr->addrlen;
        rc                      = WSASendTo(s->socket, request->buffers, count, NULL, 0,
                                            (struct sockaddr *) &request->address, request->address_length,
                                            &request->iocp.overlapped, NULL);
    }
    evpl_win_submitted(evpl, request, rc == 0);
} /* evpl_win_flush */

static SOCKET
evpl_win_socket(
    int family,
    int type)
{
    return WSASocketW(family, type, 0, NULL, 0, WSA_FLAG_OVERLAPPED | WSA_FLAG_NO_HANDLE_INHERIT);
} /* evpl_win_socket */

static void
evpl_win_connect(
    struct evpl      *evpl,
    struct evpl_bind *bindp)
{
    struct evpl_winsock     *s = evpl_bind_private(bindp);
    struct evpl_win_request *request;
    struct sockaddr_storage  any  = { 0 };
    GUID                     guid = WSAID_CONNECTEX;
    LPFN_CONNECTEX           connect_ex;
    DWORD                    bytes;

    s->socket = evpl_win_socket(bindp->remote->addr->sa_family, SOCK_STREAM);
    if (s->socket == INVALID_SOCKET) {
        evpl_close(evpl, bindp); return;
    }
    any.ss_family = bindp->remote->addr->sa_family;
    if (bind(s->socket, (struct sockaddr *) &any,
             any.ss_family == AF_INET ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6)) ||
        evpl_iocp_associate(evpl, (HANDLE) s->socket) ||
        WSAIoctl(s->socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid),
                 &connect_ex, sizeof(connect_ex), &bytes, NULL, NULL)) {
        evpl_close(evpl, bindp); return;
    }
    request = evpl_win_request(bindp, WIN_CONNECT, 0);
    evpl_win_submitted(evpl, request, connect_ex(s->socket, bindp->remote->addr,
                                                 bindp->remote->addrlen, NULL, 0, NULL, &request->iocp.overlapped));
} /* evpl_win_connect */

static void
evpl_win_attach_discard(
    struct evpl *evpl,
    void        *accepted)
{
    struct evpl_win_accepted *a = accepted;

    (void) evpl;
    closesocket(a->socket);
    evpl_free(a);
} /* evpl_win_attach_discard */

static void
evpl_win_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *private)
{
    struct evpl_winsock      *s        = evpl_bind_private(bind);
    struct evpl_win_accepted *accepted = private;

    s->socket = accepted->socket;
    evpl_free(accepted);
    if (evpl_iocp_associate(evpl, (HANDLE) s->socket)) {
        evpl_close(evpl, bind);
    } else {
        evpl_win_connected(evpl, bind);
    }
} /* evpl_win_attach */

static void
evpl_win_accept(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_winsock     *s       = evpl_bind_private(bind);
    struct evpl_win_request *request = evpl_win_request(bind, WIN_ACCEPT, 0);
    DWORD                    bytes;

    request->accepted = evpl_win_socket(bind->local->addr->sa_family, SOCK_STREAM);
    if (request->accepted == INVALID_SOCKET) {
        evpl_win_submitted(evpl, request, 0); return;
    }
    evpl_win_submitted(evpl, request, s->accept_ex(s->socket, request->accepted,
                                                   request->accept_addresses, 0, sizeof(struct sockaddr_storage) + 16,
                                                   sizeof(struct sockaddr_storage) + 16, &bytes, &request->iocp.
                                                   overlapped));
} /* evpl_win_accept */

static int
evpl_win_listen(
    struct evpl      *evpl,
    struct evpl_bind *bindp)
{
    struct evpl_winsock *s    = evpl_bind_private(bindp);
    GUID                 guid = WSAID_ACCEPTEX;
    DWORD                bytes;
    int                  yes = 1;

    s->socket = evpl_win_socket(bindp->local->addr->sa_family, SOCK_STREAM);
    if (s->socket == INVALID_SOCKET) {
        return -1;
    }
    /* Windows SO_REUSEADDR permits stealing a live listener's address. */
    if (setsockopt(s->socket, SOL_SOCKET, SO_EXCLUSIVEADDRUSE, (const char *) &yes, sizeof(yes)) ||
        bind(s->socket, bindp->local->addr, bindp->local->addrlen) ||
        listen(s->socket, evpl_shared->config->max_pending) ||
        evpl_iocp_associate(evpl, (HANDLE) s->socket) ||
        WSAIoctl(s->socket, SIO_GET_EXTENSION_FUNCTION_POINTER, &guid, sizeof(guid),
                 &s->accept_ex, sizeof(s->accept_ex), &bytes, NULL, NULL)) {
        closesocket(s->socket); s->socket = INVALID_SOCKET; return -1;
    }
    evpl_win_accept(evpl, bindp);
    return 0;
} /* evpl_win_listen */

static void
evpl_win_bind(
    struct evpl      *evpl,
    struct evpl_bind *bindp)
{
    struct evpl_winsock *s = evpl_bind_private(bindp);

    s->socket = evpl_win_socket(bindp->local->addr->sa_family, SOCK_DGRAM);
    if (s->socket == INVALID_SOCKET ||
        bind(s->socket, bindp->local->addr, bindp->local->addrlen) ||
        evpl_iocp_associate(evpl, (HANDLE) s->socket)) {
        evpl_close(evpl, bindp); return;
    }
    /* An ICMP port-unreachable refers to a previous datagram, not to the
     * lifetime of this unconnected socket. Match BSD UDP semantics. */
    {
        BOOL  report_reset = FALSE;
        DWORD bytes;
        if (WSAIoctl(s->socket, SIO_UDP_CONNRESET, &report_reset, sizeof(report_reset),
                     NULL, 0, &bytes, NULL, NULL)) {
            evpl_close(evpl, bindp);
            return;
        }
    }
    evpl_win_receive(evpl, bindp);
} /* evpl_win_bind */

static void
evpl_win_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_winsock *s = evpl_bind_private(bind);

    (void) evpl;
    if (s->socket != INVALID_SOCKET) {
        CancelIoEx((HANDLE) s->socket, NULL);
        closesocket(s->socket);
        s->socket = INVALID_SOCKET;
    }
} /* evpl_win_pending_close */

static void
evpl_win_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_dgram *dgram;

    (void) evpl;
    evpl_core_assert(bind->outstanding == 0);
    if (!bind->protocol->connected) {
        while ((dgram = evpl_dgram_ring_tail(&bind->dgram_send)) != NULL) {
            evpl_address_release(dgram->addr);
            evpl_dgram_ring_remove(&bind->dgram_send);
        }
    }
} /* evpl_win_close */

struct evpl_protocol evpl_socket_tcp = {
    .id = EVPL_STREAM_SOCKET_TCP, .connected
        = 1,
    .
    stream
          = 1,
    .name = "STREAM_SOCKET_TCP",    .connect                                                                     =
        evpl_win_connect,
    .listen = evpl_win_listen,        .discard_accepted
            =
            evpl_win_attach_discard,
    .attach        = evpl_win_attach,
    .pending_close = evpl_win_pending_close, .close
                   =
            evpl_win_close,
    .flush
        =
            evpl_win_flush,
};
struct evpl_protocol evpl_socket_udp = {
    .id = EVPL_DATAGRAM_SOCKET_UDP, .name
        =
            "DATAGRAM_SOCKET_UDP",
    .bind = evpl_win_bind,            .pending_close
          =
            evpl_win_pending_close,
    .close = evpl_win_close,           .flush
           =
            evpl_win_flush,
};
