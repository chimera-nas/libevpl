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

#include "core/eventpoll.h"
#include "core/internal.h"
#include "core/event.h"
#include "core/tcp.h"
#include "core/buffer.h"
#include "core/conn.h"

void
eventpoll_socket_init(
    struct eventpoll        *eventpoll,
    struct eventpoll_socket *s,
    int                      fd,
    int                      connected)
{
    struct eventpoll_config *config = eventpoll_config(eventpoll);

    s->fd        = fd;
    s->connected = connected;
    s->recv_size = config->buffer_size;
} /* eventpoll_socket_init */

static inline void
eventpoll_check_conn(
    struct eventpoll       *eventpoll,
    struct eventpoll_event *event)
{
    struct eventpoll_socket *s    = eventpoll_event_backend(event);
    struct eventpoll_conn   *conn = eventpoll_event_conn(event);

    socklen_t                len;
    int                      rc, err;

    if (!s->connected) {
        len = sizeof(err);
        rc  = getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &err, &len);
        eventpoll_fatal_if(rc, "Failed to get SO_ERROR from socket");

        if (err) {
            eventpoll_event_mark_close(eventpoll, event);
        } else {
            conn->callback(eventpoll, conn, EVENTPOLL_EVENT_CONNECTED, 0,
                           conn->private_data);
        }

        s->connected = 1;
    }

} /* eventpoll_check_conn */

void
eventpoll_read_tcp(
    struct eventpoll       *eventpoll,
    struct eventpoll_event *event)
{
    struct eventpoll_socket *s    = eventpoll_event_backend(event);
    struct eventpoll_conn   *conn = eventpoll_event_conn(event);
    struct iovec             iov[8];
    struct msghdr            msghdr;
    ssize_t                  res, total, remain;
    int                      cb = 0;


    eventpoll_debug("tcp socket %d readable", s->fd);

    eventpoll_check_conn(eventpoll, event);

    while (1) {

        if (s->recv1.length == 0) {
            if (s->recv2.length) {
                s->recv1        = s->recv2;
                s->recv2.length = 0;
            } else {
                eventpoll_bvec_alloc(eventpoll, s->recv_size, 0, &s->recv1);
            }
        }

        if (s->recv2.length == 0) {
            eventpoll_bvec_alloc(eventpoll, s->recv_size, 0, &s->recv2);
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
            eventpoll_error("socket read returned %ld", res);
            eventpoll_event_mark_unreadable(event);
            eventpoll_event_mark_close(eventpoll, event);
            break;
        } else if (res == 0) {
            eventpoll_event_mark_unreadable(event);
            eventpoll_event_mark_close(eventpoll, event);
            break;
        }

        eventpoll_debug("read %ld bytes of %ld total", res, total);
        cb = 1;

        if (s->recv1.length >= res) {
            eventpoll_bvec_ring_append(eventpoll, &conn->recv_ring, &s->recv1,
                                       res);
        } else {
            remain = res - s->recv1.length;
            eventpoll_bvec_ring_append(eventpoll, &conn->recv_ring, &s->recv1,
                                       s->recv1.length);
            eventpoll_bvec_ring_append(eventpoll, &conn->recv_ring, &s->recv2,
                                       remain);
        }

        if (res < total) {
            eventpoll_event_mark_unreadable(event);
            break;
        }
    }

    if (cb) {
        conn->callback(eventpoll, conn, EVENTPOLL_EVENT_RECEIVED, 0,
                       conn->private_data);
    }
} /* eventpoll_read_tcp */

void
eventpoll_write_tcp(
    struct eventpoll       *eventpoll,
    struct eventpoll_event *event)
{
    struct eventpoll_socket *s    = eventpoll_event_backend(event);
    struct eventpoll_conn   *conn = eventpoll_event_conn(event);
    struct iovec             iov[8];
    int                      niov;
    struct msghdr            msghdr;
    ssize_t                  res, total;

    eventpoll_debug("tcp socket writable");

    eventpoll_check_conn(eventpoll, event);

    while (!eventpoll_bvec_ring_is_empty(&conn->send_ring)) {

        niov = eventpoll_bvec_ring_iov(&total, iov, 8, &conn->send_ring);

        msghdr.msg_name       = NULL;
        msghdr.msg_namelen    = 0;
        msghdr.msg_iov        = iov;
        msghdr.msg_iovlen     = niov;
        msghdr.msg_control    = NULL;
        msghdr.msg_controllen = 0;
        msghdr.msg_flags      = 0;

        res = sendmsg(s->fd, &msghdr,  MSG_NOSIGNAL | MSG_DONTWAIT);

        if (res < 0) {
            eventpoll_error("socket write returned %ld", res);
            eventpoll_event_mark_unwritable(event);
            eventpoll_event_mark_close(eventpoll, event);
            break;
        }

        eventpoll_debug("wrote %ld bytes", res);

        eventpoll_bvec_ring_consume(eventpoll, &conn->send_ring, res);

        if (res != total) {
            eventpoll_event_mark_unwritable(event);
            break;
        }
    }

    if (eventpoll_bvec_ring_is_empty(&conn->send_ring)) {
        eventpoll_event_write_disinterest(event);
    }

} /* eventpoll_write_tcp */

void
eventpoll_error_tcp(
    struct eventpoll       *eventpoll,
    struct eventpoll_event *event)
{
    eventpoll_debug("tcp socket error");
} /* eventpoll_error_tcp */

int
eventpoll_connect_tcp(
    struct eventpoll        *eventpoll,
    struct eventpoll_socket *s,
    struct eventpoll_event  *event,
    const char              *address,
    int                      port)
{
    char            port_str[8];
    struct addrinfo hints, *res, *p;
    int             rc, fd, flags;

    s->fd = -1;

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(address, port_str, &hints, &res);

    if (rc) {
        eventpoll_debug("failed to resolve address for connect");
        return 1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
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
                eventpoll_debug("connect errno: %s", strerror(errno));
                continue;
            }
        }

        break;
    }

    freeaddrinfo(res);

    if (p == NULL) {
        eventpoll_debug("failed to connect to any address");
        return 1;
    }

    eventpoll_socket_init(eventpoll, s, fd, 0);

    event->fd             = fd;
    event->read_callback  = eventpoll_read_tcp;
    event->write_callback = eventpoll_write_tcp;
    event->error_callback = eventpoll_error_tcp;

    return 0;
} /* eventpoll_connect_tcp */

void
eventpoll_close_tcp(
    struct eventpoll        *eventpoll,
    struct eventpoll_socket *s)
{
    if (s->fd >= 0) {
        eventpoll_debug("closing tcp socket fd %d", s->fd);
        close(s->fd);
    }

    if (s->recv1.length) {
        eventpoll_bvec_release(eventpoll, &s->recv1);
        s->recv1.length = 0;
    }

    if (s->recv2.length) {
        eventpoll_bvec_release(eventpoll, &s->recv2);
        s->recv2.length = 0;
    }

} /* eventpoll_close_tcp */

void
eventpoll_accept_tcp(
    struct eventpoll       *eventpoll,
    struct eventpoll_event *event)
{
    struct eventpoll_socket   *ls       = eventpoll_event_backend(event);
    struct eventpoll_listener *listener = eventpoll_event_listener(event);
    struct eventpoll_socket   *s;
    struct eventpoll_conn     *conn;
    struct sockaddr_storage    client_addr;
    struct sockaddr           *client_addrp;
    socklen_t                  client_len = sizeof(client_addr);
    char                       ip_str[INET6_ADDRSTRLEN];
    int                        fd, port;
    void                      *addr;

    client_addrp =  (struct sockaddr *) &client_addr;


    while (1) {

        fd = accept(ls->fd, client_addrp, &client_len);

        if (fd < 0) {
            eventpoll_event_mark_unreadable(event);
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

        conn = eventpoll_alloc_conn(eventpoll, EVENTPOLL_PROTO_TCP, ip_str,
                                    port);

        s = eventpoll_conn_backend(conn);

        eventpoll_info("new conn is fd %d", fd);

        eventpoll_socket_init(eventpoll, s, fd, 1);

        conn->event.fd             = fd;
        conn->event.read_callback  = eventpoll_read_tcp;
        conn->event.write_callback = eventpoll_write_tcp;
        conn->event.error_callback = eventpoll_error_tcp;

        eventpoll_accept(eventpoll, listener, conn);
    }

} /* eventpoll_accept_tcp */

int
eventpoll_listen_tcp(
    struct eventpoll        *eventpoll,
    struct eventpoll_socket *s,
    struct eventpoll_event  *event,
    const char              *address,
    int                      port)
{
    char            port_str[8];
    struct addrinfo hints, *res, *p;
    int             rc, fd;
    const int       yes = 1;

    s->fd = -1;

    snprintf(port_str, sizeof(port_str), "%d", port);

    memset(&hints, 0, sizeof hints);
    hints.ai_family   = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_flags    = AI_PASSIVE;

    rc = getaddrinfo(address, port_str, &hints, &res);

    if (rc) {
        eventpoll_debug("getaddrinfo returned %d", rc);
        return 1;
    }

    for (p = res; p != NULL; p = p->ai_next) {
        fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);

        if (fd == -1) {
            continue;
        }

        if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
            return errno;
        }


        if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
            close(fd);
            continue;
        }

        break;
    }

    freeaddrinfo(res);

    if (p == NULL) {
        eventpoll_debug("Failed to bind to any addr");
        return 1;
    }

    rc = fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);

    rc = listen(fd, eventpoll_config(eventpoll)->max_pending);

    eventpoll_fatal_if(rc, "Failed to listen on listener fd");

    s->fd = fd;

    event->fd            = fd;
    event->read_callback = eventpoll_accept_tcp;

    return 0;

} /* eventpoll_listen_tcp */
