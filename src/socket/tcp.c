/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

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

#include "core/evpl.h"
#include "core/internal.h"
#include "core/event.h"
#include "core/buffer.h"
#include "core/endpoint.h"
#include "core/bind.h"
#include "core/protocol.h"

#include "socket/common.h"
#include "socket/tcp.h"

static inline void
evpl_check_conn(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_socket *s)
{
    struct evpl_notify notify;
    socklen_t          len;
    int                rc, err;

    if (!s->connected) {
        len = sizeof(err);
        rc  = getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &len);
        evpl_socket_fatal_if(rc, "Failed to get SO_ERROR from socket");

        if (err) {
            evpl_defer(evpl, &bind->close_deferral);
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
    struct evpl_bvec   *bvec;
    struct evpl_notify  notify;
    struct iovec        iov[2];
    struct msghdr       msghdr;
    ssize_t             res, total, remain;
    int                 length, nbvec;

    evpl_check_conn(evpl, bind, s);

    if (s->recv1.length == 0) {
        if (s->recv2.length) {
            s->recv1        = s->recv2;
            s->recv2.length = 0;
        } else {
            evpl_bvec_alloc_whole(evpl, &s->recv1);
        }
    }

    if (s->recv2.length == 0) {
        evpl_bvec_alloc_whole(evpl, &s->recv2);
    }

    iov[0].iov_base = s->recv1.data;
    iov[0].iov_len  = s->recv1.length;
    iov[1].iov_base = s->recv2.data;
    iov[1].iov_len  = s->recv2.length;

    total = iov[0].iov_len + iov[1].iov_len;

    msghdr.msg_name       = NULL;
    msghdr.msg_namelen    = 0;
    msghdr.msg_iov        = iov;
    msghdr.msg_iovlen     = 2;
    msghdr.msg_control    = NULL;
    msghdr.msg_controllen = 0;
    msghdr.msg_flags      = 0;

    res = recvmsg(s->fd, &msghdr,  MSG_NOSIGNAL | MSG_DONTWAIT);

    if (res < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            evpl_defer(evpl, &bind->close_deferral);
        }
        goto out;
    } else if (res == 0) {
        evpl_defer(evpl, &bind->close_deferral);
        goto out;
    }

    if (s->recv1.length >= res) {
        evpl_bvec_ring_append(evpl, &bind->bvec_recv, &s->recv1, res);
    } else {
        remain = res - s->recv1.length;
        evpl_bvec_ring_append(evpl, &bind->bvec_recv, &s->recv1,
                              s->recv1.length);
        evpl_bvec_ring_append(evpl, &bind->bvec_recv, &s->recv2, remain);
    }

    if (bind->segment_callback) {

        bvec = alloca(sizeof(struct evpl_bvec) * s->config->max_num_bvec);

        do {
            length = bind->segment_callback(evpl, bind, bind->private_data);

            if (evpl_bvec_ring_bytes(&bind->bvec_recv) < length) {
                break;
            }

            if (unlikely(length < 0)) {
                evpl_defer(evpl, &bind->close_deferral);
                goto out;
            }

            if (length) {

                nbvec = evpl_bvec_ring_copyv(evpl, bvec, &bind->bvec_recv,
                                             length);

                notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
                notify.recv_msg.bvec   = bvec;
                notify.recv_msg.nbvec  = nbvec;
                notify.recv_msg.length = length;
                notify.recv_msg.addr   = bind->remote;

                bind->notify_callback(evpl, bind, &notify, bind->private_data);
            }

        } while (length);

    } else {
        notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
        notify.notify_status = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

 out:
    if (res < total) {
        evpl_event_mark_unreadable(event);
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
    int                 maxiov = s->config->max_num_bvec;
    int                 niov;
    struct msghdr       msghdr;
    ssize_t             res, total;

    iov = alloca(sizeof(struct iovec) * maxiov);

    evpl_check_conn(evpl, bind, s);

    niov = evpl_bvec_ring_iov(&total, iov, maxiov, &bind->bvec_send);

    msghdr.msg_name       = NULL;
    msghdr.msg_namelen    = 0;
    msghdr.msg_iov        = iov;
    msghdr.msg_iovlen     = niov;
    msghdr.msg_control    = NULL;
    msghdr.msg_controllen = 0;
    msghdr.msg_flags      = 0;

    res = sendmsg(s->fd, &msghdr,  MSG_NOSIGNAL | MSG_DONTWAIT);

    if (res < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            evpl_defer(evpl, &bind->close_deferral);
        }
        goto out;
    } else if (res == 0) {
        evpl_defer(evpl, &bind->close_deferral);
        goto out;
    }

    evpl_bvec_ring_consume(evpl, &bind->bvec_send, res);

    if (res != total) {
        evpl_event_mark_unwritable(event);
    }

    if (res && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

    if (evpl_bvec_ring_is_empty(&bind->bvec_send)) {
        evpl_event_write_disinterest(event);

        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_defer(evpl, &bind->close_deferral);
        }
    }

 out:

    if (res != total) {
        evpl_event_mark_unwritable(event);
    }

} /* evpl_write_tcp */

void
evpl_socket_tcp_error(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_socket_debug("tcp socket error");
} /* evpl_error_tcp */

void
evpl_socket_tcp_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket *s = evpl_bind_private(bind);
    int                 rc, flags;

    s->fd = socket(bind->remote->addr->sa_family, SOCK_STREAM, 0);

    evpl_socket_abort_if(s->fd < 0, "Failed to create tcp socket: %s", strerror(
                             errno));

    flags = fcntl(s->fd, F_GETFL, 0);

    evpl_socket_abort_if(flags < 0, "Failed to get socket flags: %s", strerror(
                             errno));

    rc = fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);

    evpl_socket_abort_if(rc < 0, "Failed to set socket flags: %s", strerror(
                             errno));


    rc = connect(s->fd, bind->remote->addr, bind->remote->addrlen);

    evpl_socket_abort_if(rc < 0 && errno != EINPROGRESS,
                         "Failed to connect tcp socket: %s", strerror(errno));

    evpl_socket_init(evpl, s, s->fd, 0);

    s->event.fd             = s->fd;
    s->event.read_callback  = evpl_socket_tcp_read;
    s->event.write_callback = evpl_socket_tcp_write;
    s->event.error_callback = evpl_socket_tcp_error;

    evpl_add_event(evpl, &s->event);
    evpl_event_read_interest(evpl, &s->event);
    evpl_event_write_interest(evpl, &s->event);

} /* evpl_socket_tcp_connect */

void
evpl_accept_tcp(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_socket  *ls          = evpl_event_socket(event);
    struct evpl_bind    *listen_bind = evpl_private2bind(ls);
    struct evpl_socket  *s;
    struct evpl_bind    *new_bind;
    struct evpl_address *remote_addr;
    struct evpl_notify   notify;
    int                  fd;

    while (1) {

        remote_addr = evpl_address_alloc(evpl);

        fd = accept(ls->fd, remote_addr->addr, &remote_addr->addrlen);

        if (fd < 0) {
            evpl_event_mark_unreadable(event);
            evpl_free(remote_addr);
            return;
        }

        new_bind = evpl_bind_alloc(evpl,
                                   listen_bind->protocol,
                                   listen_bind->local, remote_addr);

        --remote_addr->refcnt;
        s = evpl_bind_private(new_bind);

        evpl_socket_init(evpl, s, fd, 1);

        s->event.fd             = fd;
        s->event.read_callback  = evpl_socket_tcp_read;
        s->event.write_callback = evpl_socket_tcp_write;
        s->event.error_callback = evpl_socket_tcp_error;

        evpl_add_event(evpl, &s->event);
        evpl_event_read_interest(evpl, &s->event);

        listen_bind->accept_callback(
            listen_bind,
            &new_bind->notify_callback,
            &new_bind->segment_callback,
            &new_bind->private_data,
            listen_bind->private_data);

        notify.notify_type   = EVPL_NOTIFY_CONNECTED;
        notify.notify_status = 0;

        new_bind->notify_callback(evpl, new_bind, &notify,
                                  new_bind->private_data);

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

    rc = listen(s->fd, evpl_config(evpl)->max_pending);

    evpl_socket_fatal_if(rc, "Failed to listen on listener fd");

    s->event.fd            = s->fd;
    s->event.read_callback = evpl_accept_tcp;

    evpl_add_event(evpl, &s->event);
    evpl_event_read_interest(evpl, &s->event);

} /* evpl_socket_tcp_listen */

struct evpl_protocol evpl_socket_tcp = {
    .id        = EVPL_STREAM_SOCKET_TCP,
    .connected = 1,
    .stream    = 1,
    .name      = "STREAM_SOCKET_TCP",
    .connect   = evpl_socket_tcp_connect,
    .close     = evpl_socket_close,
    .listen    = evpl_socket_tcp_listen,
    .flush     = evpl_socket_flush,
};
