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
            bind->callback(evpl, bind, &notify, bind->private_data);
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
    struct evpl_notify  notify;
    struct iovec        iov[8];
    struct msghdr       msghdr;
    ssize_t             res, total, remain;
    int                 cb = 0;

    evpl_check_conn(evpl, bind, s);

    while (1) {

        if (s->recv1.length == 0) {
            if (s->recv2.length) {
                s->recv1        = s->recv2;
                s->recv2.length = 0;
            } else {
                evpl_bvec_alloc(evpl, s->config->buffer_size, 0, 1, &s->recv1);
            }
        }

        if (s->recv2.length == 0) {
            evpl_bvec_alloc(evpl, s->config->buffer_size, 0, 1, &s->recv2);
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
            evpl_event_mark_unreadable(event);
            evpl_defer(evpl, &bind->close_deferral);
            break;
        } else if (res == 0) {
            evpl_event_mark_unreadable(event);
            evpl_defer(evpl, &bind->close_deferral);
            break;
        }

        cb = 1;

        if (s->recv1.length >= res) {
            evpl_bvec_ring_append(evpl, &bind->bvec_recv, &s->recv1,
                                  res, 0);
        } else {
            remain = res - s->recv1.length;
            evpl_bvec_ring_append(evpl, &bind->bvec_recv, &s->recv1,
                                  s->recv1.length, 0);
            evpl_bvec_ring_append(evpl, &bind->bvec_recv, &s->recv2,
                                  remain, 0);
        }

        if (res < total) {
            evpl_event_mark_unreadable(event);
            break;
        }
    }

    if (cb) {
        notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
        notify.notify_status = 0;
        bind->callback(evpl, bind, &notify, bind->private_data);
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
    struct iovec        iov[8];
    int                 niov;
    struct msghdr       msghdr;
    ssize_t             res, total;

    evpl_check_conn(evpl, bind, s);


    niov = evpl_bvec_ring_iov(&total, iov, 8, 0, &bind->bvec_send);

    msghdr.msg_name       = NULL;
    msghdr.msg_namelen    = 0;
    msghdr.msg_iov        = iov;
    msghdr.msg_iovlen     = niov;
    msghdr.msg_control    = NULL;
    msghdr.msg_controllen = 0;
    msghdr.msg_flags      = 0;

    res = sendmsg(s->fd, &msghdr,  MSG_NOSIGNAL | MSG_DONTWAIT);

    if (res < 0) {
        evpl_event_mark_unwritable(event);
        evpl_defer(evpl, &bind->close_deferral);
        return;
    }

    evpl_bvec_ring_consume(evpl, &bind->bvec_send, res);

    if (res != total) {
        evpl_event_mark_unwritable(event);
    }

    if (res) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        bind->callback(evpl, bind, &notify, bind->private_data);
    }

    if (evpl_bvec_ring_is_empty(&bind->bvec_send)) {
        evpl_event_write_disinterest(event);

        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_defer(evpl, &bind->close_deferral);
        }
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
    struct addrinfo    *p;
    int                 fd, flags;

    s->fd = -1;

    for (p = bind->endpoint->ai; p != NULL; p = p->ai_next) {

        fd = socket(p->ai_family, SOCK_STREAM, p->ai_protocol);

        if (fd == -1) {
            continue;
        }

        flags = fcntl(fd, F_GETFL, 0);

        if (flags == -1) {
            close(fd);
            continue;
        }
        if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
            close(fd);
            continue;
        }


        if (connect(fd, p->ai_addr, p->ai_addrlen) == -1) {
            if (errno != EINPROGRESS) {
                evpl_socket_debug("connect errno: %s", strerror(errno));
                continue;
            }
        }

        break;
    }

    if (p == NULL) {
        evpl_socket_debug("failed to connect to any address");
        return;
    }

    evpl_socket_init(evpl, s, fd, 0);

    s->event.fd             = fd;
    s->event.read_callback  = evpl_socket_tcp_read;
    s->event.write_callback = evpl_socket_tcp_write;
    s->event.error_callback = evpl_socket_tcp_error;

    evpl_add_event(evpl, &s->event);
    evpl_event_read_interest(evpl, &s->event);

} /* evpl_bindect_tcp */

void
evpl_accept_tcp(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_socket     *ls          = evpl_event_socket(event);
    struct evpl_bind       *listen_bind = evpl_private2bind(ls);
    struct evpl_endpoint   *endpoint;
    struct evpl_socket     *s;
    struct evpl_bind       *new_bind;
    struct sockaddr_storage client_addr;
    struct sockaddr        *client_addrp;
    socklen_t               client_len = sizeof(client_addr);
    char                    ip_str[INET6_ADDRSTRLEN];
    int                     fd, port;
    void                   *addr;

    client_addrp =  (struct sockaddr *) &client_addr;


    while (1) {

        fd = accept(ls->fd, client_addrp, &client_len);

        if (fd < 0) {
            evpl_event_mark_unreadable(event);
            return;
        }

        if (client_addrp->sa_family == AF_INET) {
            struct sockaddr_in *ipv4 = (struct sockaddr_in *) client_addrp;
            addr = &(ipv4->sin_addr);
            port = ntohs(ipv4->sin_port);
        } else {
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) client_addrp;
            addr = &(ipv6->sin6_addr);
            port = ntohs(ipv6->sin6_port);
        }

        inet_ntop(client_addrp->sa_family, addr, ip_str, sizeof(ip_str));

        endpoint = evpl_endpoint_create(evpl, ip_str, port);

        new_bind = evpl_bind_alloc(evpl, endpoint);

        new_bind->protocol = listen_bind->protocol;

        evpl_endpoint_close(evpl, endpoint); /* drop our reference */

        s = evpl_bind_private(new_bind);

        evpl_socket_init(evpl, s, fd, 1);

        s->event.fd             = fd;
        s->event.read_callback  = evpl_socket_tcp_read;
        s->event.write_callback = evpl_socket_tcp_write;
        s->event.error_callback = evpl_socket_tcp_error;

        evpl_add_event(evpl, &s->event);
        evpl_event_read_interest(evpl, &s->event);

        evpl_accept(evpl, listen_bind, new_bind);
    }

} /* evpl_accept_tcp */

void
evpl_socket_tcp_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind)
{
    struct evpl_socket *s = evpl_bind_private(listen_bind);
    struct addrinfo    *p;
    int                 rc, fd;
    const int           yes = 1;

    s->fd = -1;

    for (p = listen_bind->endpoint->ai; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (fd == -1) {
            continue;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            return;
        }


        if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            continue;
        }

        break;
    }

    if (p == NULL) {
        evpl_socket_debug("Failed to bind to any addr");
        return;
    }

    rc = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    rc = listen(fd, evpl_config(evpl)->max_pending);

    evpl_socket_fatal_if(rc, "Failed to listen on listener fd");

    s->fd = fd;

    s->event.fd            = fd;
    s->event.read_callback = evpl_accept_tcp;

    evpl_add_event(evpl, &s->event);
    evpl_event_read_interest(evpl, &s->event);

} /* evpl_socket_tcp_listen */

struct evpl_protocol evpl_socket_tcp = {
    .id        = EVPL_STREAM_SOCKET_TCP,
    .connected = 1,
    .name      = "STREAM_SOCKET_TCP",
    .connect   = evpl_socket_tcp_connect,
    .close     = evpl_socket_close,
    .listen    = evpl_socket_tcp_listen,
    .flush     = evpl_socket_flush,
};