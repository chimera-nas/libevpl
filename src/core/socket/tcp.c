// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "core/allocator.h"
#include "core/endpoint.h"
#include "core/bind.h"
#include "core/protocol.h"
#include "core/event_fn.h"
#include "core/evpl.h"
#include "core/socket/common.h"
#include "core/socket/tcp.h"

static inline void
evpl_check_conn(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_socket *s)
{
    struct evpl_notify notify;
    socklen_t          len;
    int                rc, err;

    if (unlikely(!s->connected)) {
        len = sizeof(err);
        rc  = getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &len);
        evpl_socket_fatal_if(rc, "Failed to get SO_ERROR from socket");

        if (err) {
            evpl_close(evpl, bind);
        } else {
            notify.notify_type   = EVPL_NOTIFY_CONNECTED;
            notify.notify_status = 0;
            bind->notify_callback(evpl, bind, &notify, bind->private_data);
        }

        s->connected = 1;
    }

} /* evpl_check_conn */

void
evpl_socket_tcp_read(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_socket *s    = evpl_event_socket(event);
    struct evpl_bind   *bind = evpl_private2bind(s);
    struct evpl_iovec  *iovec;
    struct evpl_notify  notify;
    struct iovec        iov[2];
    ssize_t             res, total, remain;
    int                 length, niov;

    if (unlikely(s->fd < 0)) {
        return;
    }

    evpl_check_conn(evpl, bind, s);

    if (s->recv1.length == 0) {
        if (s->recv2.length) {
            s->recv1        = s->recv2;
            s->recv2.length = 0;
        } else {
            evpl_iovec_alloc_whole(evpl, &s->recv1);
        }
    }

    if (s->recv2.length == 0) {
        evpl_iovec_alloc_whole(evpl, &s->recv2);
    }

    iov[0].iov_base = s->recv1.data;
    iov[0].iov_len  = s->recv1.length;
    iov[1].iov_base = s->recv2.data;
    iov[1].iov_len  = s->recv2.length;

    total = iov[0].iov_len + iov[1].iov_len;

    res = readv(s->fd, iov, 2);

    if (res < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            evpl_close(evpl, bind);
        }
        goto out;
    } else if (res == 0) {
        evpl_close(evpl, bind);
        goto out;
    }

    if (s->recv1.length >= res) {
        evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv1, res);
    } else {
        remain = res - s->recv1.length;
        evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv1,
                               s->recv1.length);
        evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv2, remain);
    }

    if (bind->segment_callback) {

        iovec = alloca(sizeof(struct evpl_iovec) * evpl_shared->config->max_num_iovec);

        while (1) {

            length = bind->segment_callback(evpl, bind, bind->private_data);

            if (length == 0 ||
                evpl_iovec_ring_bytes(&bind->iovec_recv) < length) {
                break;
            }

            if (unlikely(length < 0)) {
                evpl_close(evpl, bind);
                goto out;
            }

            niov = evpl_iovec_ring_copyv(evpl, iovec, &bind->iovec_recv,
                                         length);

            notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
            notify.recv_msg.iovec  = iovec;
            notify.recv_msg.niov   = niov;
            notify.recv_msg.length = length;
            notify.recv_msg.addr   = bind->remote;

            bind->notify_callback(evpl, bind, &notify, bind->private_data);
        }

    } else {
        notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
        notify.notify_status = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

 out:

    if (res < total) {
        evpl_event_mark_unreadable(evpl, event);
    }

} /* evpl_read_tcp */

void
evpl_socket_tcp_write(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_socket *s    = evpl_event_socket(event);
    struct evpl_bind   *bind = evpl_private2bind(s);
    struct evpl_notify  notify;
    struct iovec       *iov;
    int                 maxiov = evpl_shared->config->max_num_iovec;
    int                 niov, niov_sent, msg_sent = 0;
    ssize_t             res, total;

    if (unlikely(s->fd < 0)) {
        return;
    }

    iov = alloca(sizeof(struct iovec) * maxiov);

    evpl_check_conn(evpl, bind, s);

    niov = evpl_iovec_ring_iov(&total, iov, maxiov, &bind->iovec_send);

    if (!niov) {
        res = 0;
        goto out;
    }

    res = writev(s->fd, iov, niov);

    if (res < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            evpl_close(evpl, bind);
        }
        goto out;
    } else if (res == 0) {
        evpl_close(evpl, bind);
        goto out;
    }

    niov_sent = evpl_iovec_ring_consume(evpl, &bind->iovec_send, res);

    if (bind->segment_callback) {
        while (niov_sent) {
            struct evpl_dgram *dgram = evpl_dgram_ring_tail(&bind->dgram_send);

            if (!dgram) {
                break;
            }

            if (dgram->niov > niov_sent) {
                dgram->niov -= niov_sent;
                break;
            }

            niov_sent -= dgram->niov;
            msg_sent++;
            evpl_dgram_ring_remove(&bind->dgram_send);
        }
    }

    if (res != total) {
        evpl_event_mark_unwritable(evpl, event);
    }

    if (res && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = res;
        notify.sent.msgs     = msg_sent;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

 out:

    if (evpl_iovec_ring_is_empty(&bind->iovec_send)) {
        evpl_event_write_disinterest(evpl, event);

        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_close(evpl, bind);
        }
    }

    if (res != total) {
        evpl_event_mark_unwritable(evpl, event);
    }

} /* evpl_write_tcp */

void
evpl_socket_tcp_error(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_socket *s    = evpl_event_socket(event);
    struct evpl_bind   *bind = evpl_private2bind(s);

    if (unlikely(s->fd < 0)) {
        return;
    }

    evpl_close(evpl, bind);
} /* evpl_error_tcp */

void
evpl_socket_tcp_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket *s = evpl_bind_private(bind);
    int                 rc, yes = 1;

    s->fd = socket(bind->remote->addr->sa_family, SOCK_STREAM, 0);

    evpl_socket_abort_if(s->fd < 0, "Failed to create tcp socket: %s", strerror(
                             errno));

    rc = connect(s->fd, bind->remote->addr, bind->remote->addrlen);

    evpl_socket_abort_if(rc < 0 && errno != EINPROGRESS,
                         "Failed to connect tcp socket: %s", strerror(errno));

    evpl_socket_init(evpl, s, s->fd, 0);

    rc = setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    evpl_socket_abort_if(rc, "Failed to set TCP_QUICKACK on socket");

    evpl_add_event(evpl, &s->event, s->fd,
                   evpl_socket_tcp_read,
                   evpl_socket_tcp_write,
                   evpl_socket_tcp_error);

    evpl_event_read_interest(evpl, &s->event);
    evpl_event_write_interest(evpl, &s->event);

} /* evpl_socket_tcp_connect */

void
evpl_socket_tcp_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    struct evpl_socket          *s               = evpl_bind_private(bind);
    struct evpl_accepted_socket *accepted_socket = accepted;
    struct evpl_notify           notify;
    int                          fd = accepted_socket->fd;
    int                          rc, yes = 1;

    evpl_free(accepted_socket);

    evpl_socket_init(evpl, s, fd, 1);

    rc = setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

    evpl_socket_abort_if(rc, "Failed to set TCP_QUICKACK on socket");

    evpl_add_event(evpl, &s->event, fd,
                   evpl_socket_tcp_read,
                   evpl_socket_tcp_write,
                   evpl_socket_tcp_error);

    evpl_event_read_interest(evpl, &s->event);

    notify.notify_type   = EVPL_NOTIFY_CONNECTED;
    notify.notify_status = 0;
    bind->notify_callback(evpl, bind, &notify, bind->private_data);

} /* evpl_attach_tcp */

void
evpl_accept_tcp(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_socket          *ls          = evpl_event_socket(event);
    struct evpl_bind            *listen_bind = evpl_private2bind(ls);
    struct evpl_address         *remote_addr;
    struct evpl_accepted_socket *accepted_socket;
    int                          fd;

    while (1) {

        remote_addr = evpl_address_alloc();

        remote_addr->addrlen = sizeof(remote_addr->sa);

        fd = accept(ls->fd, remote_addr->addr, &remote_addr->addrlen);

        if (fd < 0) {
            evpl_event_mark_unreadable(evpl, event);
            evpl_free(remote_addr);
            return;
        }

        accepted_socket = evpl_zalloc(sizeof(*accepted_socket));

        accepted_socket->fd = fd;

        listen_bind->accept_callback(evpl, listen_bind, remote_addr, accepted_socket, listen_bind->private_data);
    }

} /* evpl_accept_tcp */

void
evpl_socket_tcp_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind)
{
    struct evpl_socket *s = evpl_bind_private(listen_bind);
    int                 rc;
    const int           yes = 1;

    s->fd = socket(listen_bind->local->addr->sa_family, SOCK_STREAM, 0);

    evpl_socket_abort_if(s->fd < 0, "Failed to create tcp listen socket: %s",
                         strerror(errno));

    rc = setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    evpl_socket_abort_if(rc < 0, "Failed to set socket options: %s", strerror(
                             errno));

    rc = bind(s->fd, listen_bind->local->addr, listen_bind->local->addrlen);

    evpl_socket_abort_if(rc < 0, "Failed to bind listen socket: %s", strerror(
                             errno));

    rc = fcntl(s->fd, F_SETFL, fcntl(s->fd, F_GETFL, 0) | O_NONBLOCK);

    evpl_socket_abort_if(rc < 0, "Failed to set socket flags: %s", strerror(
                             errno));

    rc = listen(s->fd, evpl_shared->config->max_pending);

    evpl_socket_fatal_if(rc, "Failed to listen on listener fd");

    evpl_add_event(evpl, &s->event, s->fd,
                   evpl_accept_tcp, NULL, NULL);

    evpl_event_read_interest(evpl, &s->event);

} /* evpl_socket_tcp_listen */

struct evpl_protocol evpl_socket_tcp = {
    .id            = EVPL_STREAM_SOCKET_TCP,
    .connected     = 1,
    .stream        = 1,
    .name          = "STREAM_SOCKET_TCP",
    .connect       = evpl_socket_tcp_connect,
    .pending_close = evpl_socket_pending_close,
    .close         = evpl_socket_close,
    .listen        = evpl_socket_tcp_listen,
    .attach        = evpl_socket_tcp_attach,
    .flush         = evpl_socket_flush,
};
