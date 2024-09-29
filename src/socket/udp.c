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
#include "socket/udp.h"

void
evpl_socket_udp_read(
    struct evpl       *evpl,
    struct evpl_event *event)
{
#if 0
    struct evpl_socket *s    = evpl_event_socket(event);
    struct evpl_conn   *conn = evpl_private2conn(s);
    struct iovec        iov[8];
    struct msghdr       msghdr;
    ssize_t             res, total, remain;
    int                 cb = 0;

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
            evpl_event_mark_unreadable(event);
            evpl_defer(evpl, &conn->close_deferral);
            break;
        } else if (res == 0) {
            evpl_event_mark_unreadable(event);
            evpl_defer(evpl, &conn->close_deferral);
            break;
        }

        cb = 1;

        if (s->recv1.length >= res) {
            evpl_bvec_ring_append(evpl, &conn->recv_ring, &s->recv1,
                                  res, 0);
        } else {
            remain = res - s->recv1.length;
            evpl_bvec_ring_append(evpl, &conn->recv_ring, &s->recv1,
                                  s->recv1.length, 0);
            evpl_bvec_ring_append(evpl, &conn->recv_ring, &s->recv2,
                                  remain, 0);
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
#endif /* if 0 */
} /* evpl_socket_udp_read */

void
evpl_socket_udp_write(
    struct evpl       *evpl,
    struct evpl_event *event)
{
#if 0
    struct evpl_socket *s    = evpl_event_socket(event);
    struct evpl_bind   *bind = evpl_private2bind(s);
    struct iovec        iov[8];
    int                 niov, nmsg = 0;
    struct msghdr      *msghdr;
    struct msghdr       msgvec[8];
    ssize_t             res, total;

    while (!evpl_bvec_ring_is_empty(&ring->send_ring)) {

        msghdr = &msgvec[nmsg].msg_hdr;

        niov = evpl_bvec_ring_iov(&total, iov, 8, 1, &bind->send_ring);

        msghdr-<msg_name       = NULL;
        msghdr->msg_namelen    = 0;
        msghdr->msg_iov        = iov;
        msghdr->msg_iovlen     = niov;
        msghdr->msg_control    = NULL;
        msghdr->msg_controllen = 0;
        msghdr->msg_flags      = 0;

        nmsg++;
    }


    res = sendmmsg(s->fd, msgvec, nmsg, MSG_NOSIGNAL | MSG_DONTWAIT);

        if (res < 0) {
            evpl_event_mark_unwritable(event);
            evpl_defer(evpl, &conn->close_deferral);
            break;
        }

        evpl_bvec_ring_consume(evpl, &conn->send_ring, res);

        if (res != total) {
            evpl_event_mark_unwritable(event);
            break;
        }
    }

    if (evpl_bvec_ring_is_empty(&conn->send_ring)) {
        evpl_event_write_disinterest(event);

        if (conn->flags & EVPL_CONN_FINISH) {
            evpl_defer(evpl, &conn->close_deferral);
        }
    }

#endif /* if 0 */
} /* evpl_socket_udp_write */

void
evpl_socket_udp_error(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_socket_debug("udp socket error");
} /* evpl_error_udp */

void
evpl_socket_udp_bind(
    struct evpl      *evpl,
    struct evpl_bind *evbind)
{
    struct evpl_socket *s = evpl_bind_private(evbind);
    struct addrinfo    *p;
    int                 fd, flags;

    s->fd = -1;

    for (p = evbind->endpoint->ai; p != NULL; p = p->ai_next) {

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


        if (bind(fd, p->ai_addr, p->ai_addrlen) == -1) {
            if (errno != EINPROGRESS) {
                evpl_socket_debug("bind errno: %s", strerror(errno));
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
    s->event.read_callback  = evpl_socket_udp_read;
    s->event.write_callback = evpl_socket_udp_write;
    s->event.error_callback = evpl_socket_udp_error;

    evpl_add_event(evpl, &s->event);
    evpl_event_read_interest(evpl, &s->event);
} /* evpl_socket_udp_bind */

struct evpl_protocol evpl_socket_udp = {
    .id     = EVPL_SOCKET_UDP,
    .connected = 0,
    .name   = "SOCKET_UDP",
    .bind   = evpl_socket_udp_bind,
    .close  = evpl_socket_close,
    .flush  = evpl_socket_flush,
};
