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
#include "core/conn.h"
#include "core/protocol.h"

#include "socket/tcp.h"

struct evpl_socket {
    struct evpl_event   event;
    int                 fd;
    int                 connected;
    int                 recv_size;
    struct evpl_bvec    recv1;
    struct evpl_bvec    recv2;
};

#define evpl_event_socket(eventp) container_of((eventp), struct evpl_socket, event)

void
evpl_socket_init(
    struct evpl        *evpl,
    struct evpl_socket *s,
    int                 fd,
    int                 connected)
{
    struct evpl_config *config = evpl_config(evpl);

    s->fd        = fd;
    s->connected = connected;
    s->recv_size = config->buffer_size;
} /* evpl_socket_init */

static inline void
evpl_check_conn(
    struct evpl       *evpl,
    struct evpl_conn  *conn,
    struct evpl_socket *s)
{
    socklen_t           len;
    int                 rc, err;

    if (!s->connected) {
        len = sizeof(err);
        rc  = getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &len);
        evpl_fatal_if(rc, "Failed to get SO_ERROR from socket");

        if (err) {
            evpl_defer(evpl, &conn->close_deferral);
        } else {
            conn->callback(evpl, conn, EVPL_EVENT_CONNECTED, 0,
                           conn->private_data);
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
    struct evpl_conn   *conn = evpl_private2conn(s);
    struct iovec        iov[8];
    struct msghdr       msghdr;
    ssize_t             res, total, remain;
    int                 cb = 0;


    evpl_debug("tcp socket %d readable", s->fd);

    evpl_check_conn(evpl, conn, s);

    while (1) {

        if (s->recv1.length == 0) {
            if (s->recv2.length) {
                s->recv1        = s->recv2;
                s->recv2.length = 0;
            } else {
                evpl_bvec_alloc(evpl, s->recv_size, 0, 1, &s->recv1);
            }
        }

        if (s->recv2.length == 0) {
            evpl_bvec_alloc(evpl, s->recv_size, 0, 1, &s->recv2);
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
            evpl_error("socket read returned %ld", res);
            evpl_event_mark_unreadable(event);
            evpl_defer(evpl, &conn->close_deferral);
            break;
        } else if (res == 0) {
            evpl_error("socket peer discon fd %d", s->fd);
            evpl_event_mark_unreadable(event);
            evpl_defer(evpl, &conn->close_deferral);
            break;
        }

        evpl_debug("fd %d read %ld bytes of %ld total", s->fd, res, total);
        cb = 1;

        if (s->recv1.length >= res) {
            evpl_bvec_ring_append(evpl, &conn->recv_ring, &s->recv1,
                                  res);
        } else {
            remain = res - s->recv1.length;
            evpl_bvec_ring_append(evpl, &conn->recv_ring, &s->recv1,
                                  s->recv1.length);
            evpl_bvec_ring_append(evpl, &conn->recv_ring, &s->recv2,
                                  remain);
        }

        if (res < total) {
            evpl_event_mark_unreadable(event);
            break;
        }
    }

    if (cb) {
        conn->callback(evpl, conn, EVPL_EVENT_RECEIVED, 0,
                       conn->private_data);
    }
} /* evpl_read_tcp */

void
evpl_socket_tcp_write(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_socket *s    = evpl_event_socket(event);
    struct evpl_conn   *conn = evpl_private2conn(s);
    struct iovec        iov[8];
    int                 niov;
    struct msghdr       msghdr;
    ssize_t             res, total;

    evpl_debug("tcp socket writable fd %d", s->fd);

    evpl_check_conn(evpl, conn, s);

    while (!evpl_bvec_ring_is_empty(&conn->send_ring)) {

        niov = evpl_bvec_ring_iov(&total, iov, 8, &conn->send_ring);

        msghdr.msg_name       = NULL;
        msghdr.msg_namelen    = 0;
        msghdr.msg_iov        = iov;
        msghdr.msg_iovlen     = niov;
        msghdr.msg_control    = NULL;
        msghdr.msg_controllen = 0;
        msghdr.msg_flags      = 0;

        evpl_debug("attempting to write %d iov", niov);

        res = sendmsg(s->fd, &msghdr,  MSG_NOSIGNAL | MSG_DONTWAIT);

        if (res < 0) {
            evpl_error("socket write returned %ld: %s", res, strerror(errno));
            evpl_event_mark_unwritable(event);
            evpl_defer(evpl, &conn->close_deferral);
            break;
        }

        evpl_debug("fd %d wrote %ld bytes", s->fd, res);

        evpl_bvec_ring_consume(evpl, &conn->send_ring, res);

        if (res != total) {
            evpl_event_mark_unwritable(event);
            break;
        }
    }

    if (evpl_bvec_ring_is_empty(&conn->send_ring)) {
        evpl_event_write_disinterest(event);

        if (conn->flags & EVPL_CONN_FINISH) {
            evpl_debug("arming close deferral");
            evpl_defer(evpl, &conn->close_deferral);
        }
    }

} /* evpl_write_tcp */

void
evpl_socket_tcp_error(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_debug("tcp socket error");
} /* evpl_error_tcp */

void
evpl_socket_tcp_connect(
    struct evpl        *evpl,
    struct evpl_conn   *conn)
{
    struct evpl_socket *s = evpl_conn_private(conn);
    struct addrinfo *p;
    int             fd, flags;

    evpl_debug("evpl_socket_tcp_connect: entry");

    s->fd = -1;

    for (p = conn->endpoint->ai; p != NULL; p = p->ai_next) {

        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

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
                evpl_debug("connect errno: %s", strerror(errno));
                continue;
            }
        }

        break;
    }

    if (p == NULL) {
        evpl_debug("failed to connect to any address");
        return;
    }

    evpl_socket_init(evpl, s, fd, 0);

    s->event.fd             = fd;
    s->event.read_callback  = evpl_socket_tcp_read;
    s->event.write_callback = evpl_socket_tcp_write;
    s->event.error_callback = evpl_socket_tcp_error;

    evpl_debug("connect fd %d", fd);
    evpl_add_event(evpl, &s->event);
    evpl_event_read_interest(evpl, &s->event);

} /* evpl_connect_tcp */

void
evpl_socket_tcp_flush(
    struct evpl        *evpl,
    struct evpl_conn   *conn)
{
    struct evpl_socket *s = evpl_conn_private(conn);

    evpl_event_write_interest(evpl, &s->event);
}

void
evpl_socket_tcp_close_conn(
    struct evpl        *evpl,
    struct evpl_conn   *conn)
{
    struct evpl_socket *s = evpl_conn_private(conn);

    if (s->fd >= 0) {
        evpl_debug("closing tcp socket fd %d", s->fd);
        close(s->fd);
    }

    if (s->recv1.length) {
        evpl_bvec_release(evpl, &s->recv1);
        s->recv1.length = 0;
    }

    if (s->recv2.length) {
        evpl_bvec_release(evpl, &s->recv2);
        s->recv2.length = 0;
    }

} /* evpl_tcp_close_conn */

void
evpl_socket_tcp_close_listener(
    struct evpl        *evpl,
    struct evpl_listener *listener)
{
    struct evpl_socket *s = evpl_listener_private(listener);

    if (s->fd >= 0) {
        evpl_debug("closing tcp socket fd %d", s->fd);
        close(s->fd);
    }

} /* evpl_tcp_close_listener */

void
evpl_accept_tcp(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_socket     *ls       = evpl_event_socket(event);
    struct evpl_listener   *listener = evpl_private2listener(ls);
    struct evpl_endpoint   *endpoint;
    struct evpl_socket     *s;
    struct evpl_conn       *conn;
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

        endpoint = evpl_endpoint_create(evpl, EVPL_SOCKET_TCP, ip_str, port);

        conn = evpl_alloc_conn(evpl, endpoint);

        evpl_endpoint_close(evpl, endpoint); /* drop our reference */

        s = evpl_conn_private(conn);

        evpl_info("new conn is fd %d", fd);

        evpl_socket_init(evpl, s, fd, 1);

        s->event.fd             = fd;
        s->event.read_callback  = evpl_socket_tcp_read;
        s->event.write_callback = evpl_socket_tcp_write;
        s->event.error_callback = evpl_socket_tcp_error;

        evpl_debug("accept fd %d", fd);
        evpl_add_event(evpl, &s->event);
        evpl_event_read_interest(evpl, &s->event);

        evpl_accept(evpl, listener, conn);
    }

} /* evpl_accept_tcp */

void
evpl_socket_tcp_listen(
    struct evpl        *evpl,
    struct evpl_listener *listener)
{
    struct evpl_socket *s = evpl_listener_private(listener);
    struct addrinfo *p;
    int             rc, fd;
    const int       yes = 1;

    s->fd = -1;

    for (p = listener->endpoint->ai; p != NULL; p = p->ai_next) {
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
        evpl_debug("Failed to bind to any addr");
        return;
    }

    rc = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    rc = listen(fd, evpl_config(evpl)->max_pending);

    evpl_fatal_if(rc, "Failed to listen on listener fd");

    s->fd = fd;

    s->event.fd            = fd;
    s->event.read_callback = evpl_accept_tcp;

    evpl_debug("tcp_listen fd %d", fd);
    evpl_add_event(evpl, &s->event);
    evpl_event_read_interest(evpl, &s->event);

} /* evpl_socket_tcp_listen */

struct evpl_protocol evpl_socket_tcp = {
    .id = EVPL_SOCKET_TCP,
    .name = "SOCKET_TCP",
    .connect = evpl_socket_tcp_connect,
    .close_conn = evpl_socket_tcp_close_conn,
    .listen = evpl_socket_tcp_listen,
    .close_listen = evpl_socket_tcp_close_listener,
    .flush = evpl_socket_tcp_flush,
};
