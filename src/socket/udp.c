/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#define _GNU_SOURCE


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

    struct evpl_socket      *s = evpl_event_socket(event);
    struct evpl_bind        *bind = evpl_private2bind(s);
    struct evpl_socket_msg **msgs, *msg;
    struct evpl_dgram       *dgram;
    struct msghdr           *msghdr;
    struct mmsghdr          *msgvecs, *msgvec;
    ssize_t                  res;
    int                      cb = 0, i, nmsg = s->config->max_msg_batch;

    evpl_socket_debug("udp readable");


    msgs    = alloca(sizeof(struct evpl_socket_msg *) * nmsg);
    msgvecs = alloca(sizeof(struct mmsghdr) * nmsg);

    for (i = 0; i < nmsg; ++i) {
        msgvec = &msgvecs[i];

        msghdr = &msgvec->msg_hdr;

        msg = evpl_socket_msg_alloc(evpl, s);

        msgs[i] = msg;

        msghdr->msg_name       = &msg->addr;
        msghdr->msg_namelen    = sizeof(msg->addr);
        msghdr->msg_iov        = &msg->iov;
        msghdr->msg_iovlen     = 1;
        msghdr->msg_control    = NULL;
        msghdr->msg_controllen = 0;
        msghdr->msg_flags      = 0;

        msg->iov.iov_base = msg->bvec.data;
        msg->iov.iov_len  = msg->bvec.length;
    }

    res = recvmmsg(s->fd, msgvecs, nmsg, MSG_NOSIGNAL | MSG_DONTWAIT, NULL);

    evpl_socket_debug("udp recv read %d msg", res);

    if (res < 0) {
        evpl_event_mark_unreadable(event);
        evpl_defer(evpl, &bind->close_deferral);
        return;
    } else if (res == 0) {
        evpl_event_mark_unreadable(event);
        evpl_defer(evpl, &bind->close_deferral);
        return;
    }

    cb = 1;

    for (i = 0; i < res; ++i) {

        msg    = msgs[i];
        msghdr = &msgvecs[i].msg_hdr;

        evpl_socket_debug("msg %d len %d", i, msgvecs[i].msg_len);

        dgram = evpl_dgram_ring_add(&bind->dgram_recv);

        memcpy(&dgram->addr, msghdr->msg_name, msghdr->msg_namelen);
        dgram->addrlen = msghdr->msg_namelen;

        evpl_socket_msg_reload(evpl, s, msg);

        dgram->bvec = evpl_bvec_ring_add(&bind->bvec_recv, &msg->bvec,
                                         1);
        dgram->bvec->length = msgvecs[i].msg_len;

    }

    for (i = 0; i < nmsg; ++i) {
        evpl_socket_msg_free(evpl, s, msgs[i]);
    }

    if (res < nmsg) {
        evpl_event_mark_unreadable(event);
    }

    if (cb) {
        evpl_socket_debug("udp making receive callback");
        bind->callback(evpl, bind, EVPL_NOTIFY_RECEIVED, 0,
                       bind->private_data);
    }
} /* evpl_socket_udp_read */

void
evpl_socket_udp_write(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_socket *s    = evpl_event_socket(event);
    struct evpl_bind   *bind = evpl_private2bind(s);
    struct evpl_dgram  *dgram;
    struct iovec        iov[8];
    int                 niov, nmsg = 0, nmsgleft;
    struct msghdr      *msghdr;
    struct mmsghdr      msgvec[8];
    ssize_t             res, total;

    evpl_socket_debug("udp writable");

    dgram = evpl_dgram_ring_tail(&bind->dgram_send);

    while (dgram && nmsg < 8) {

        msghdr = &msgvec[nmsg].msg_hdr;

        niov = evpl_bvec_ring_iov(&total, iov, dgram->nbvec, 1,
                                  &bind->bvec_send);

        msghdr->msg_name       = &dgram->addr;
        msghdr->msg_namelen    = dgram->addrlen;
        msghdr->msg_iov        = iov;
        msghdr->msg_iovlen     = niov;
        msghdr->msg_control    = NULL;
        msghdr->msg_controllen = 0;
        msghdr->msg_flags      = 0;

        dgram = evpl_dgram_ring_next(&bind->dgram_send, dgram);

        nmsg++;
    }


    res = sendmmsg(s->fd, msgvec, nmsg, MSG_NOSIGNAL | MSG_DONTWAIT);

    if (res < 0) {
        evpl_event_mark_unwritable(event);
        evpl_defer(evpl, &bind->close_deferral);
        return;
    }

    nmsgleft = nmsg;

    while (nmsgleft) {
        dgram = evpl_dgram_ring_tail(&bind->dgram_send);

        evpl_bvec_ring_consumev(evpl, &bind->bvec_send, dgram->nbvec);

        evpl_dgram_ring_remove(&bind->dgram_send);

        --nmsgleft;
    }

    if (res != total) {
        evpl_event_mark_unwritable(event);
    }


    if (evpl_dgram_ring_is_empty(&bind->dgram_send)) {
        evpl_event_write_disinterest(event);

        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_defer(evpl, &bind->close_deferral);
        }
    }

    if (res > 0) {
        bind->callback(evpl, bind, EVPL_NOTIFY_SENT, 0, bind->private_data);
    }


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

        fd = socket(p->ai_family, SOCK_DGRAM, p->ai_protocol);

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
    .id        = EVPL_SOCKET_UDP,
    .connected = 0,
    .name      = "SOCKET_UDP",
    .bind      = evpl_socket_udp_bind,
    .close     = evpl_socket_close,
    .flush     = evpl_socket_flush,
};
