// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

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
#include "evpl/evpl.h"
#include "core/allocator.h"
#include "core/endpoint.h"
#include "core/bind.h"
#include "core/protocol.h"
#include "core/event_fn.h"
#include "core/socket/common.h"
#include "core/socket/udp.h"

void
evpl_socket_udp_read(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_socket           *s    = evpl_event_socket(event);
    struct evpl_bind             *bind = evpl_private2bind(s);
    struct evpl_socket_datagram **datagrams, *datagram;
    struct evpl_notify            notify;
    struct msghdr                *msghdr;
    struct mmsghdr               *msgvecs, *msgvec;
    struct sockaddr_storage      *sockaddrs;
    struct evpl_address          *addr;
    struct iovec                 *iov;
    ssize_t                       res;
    int                           i, nmsg = evpl_shared->config->max_datagram_batch;

    if (unlikely(s->fd < 0)) {
        return;
    }

    datagrams = alloca(sizeof(struct evpl_socket_datagram * ) * nmsg);
    msgvecs   = alloca(sizeof(struct mmsghdr) * nmsg);
    sockaddrs = alloca(sizeof(struct sockaddr_storage) * nmsg);
    iov       = alloca(sizeof(struct iovec) * nmsg);

    for (i = 0; i < nmsg; ++i) {
        msgvec = &msgvecs[i];

        msghdr = &msgvec->msg_hdr;

        datagram = evpl_socket_datagram_alloc(evpl, s);

        datagrams[i] = datagram;

        msghdr->msg_name       = &sockaddrs[i];
        msghdr->msg_namelen    = sizeof(sockaddrs[i]);
        msghdr->msg_iov        = iov;
        msghdr->msg_iovlen     = 1;
        msghdr->msg_control    = NULL;
        msghdr->msg_controllen = 0;
        msghdr->msg_flags      = 0;

        iov->iov_base = datagram->iovec.data;
        iov->iov_len  = datagram->iovec.length;

        iov++;
    }

    res = recvmmsg(s->fd, msgvecs, nmsg, MSG_NOSIGNAL | MSG_DONTWAIT, NULL);

    if (res < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            evpl_close(evpl, bind);
        }
        goto out;
    } else if (res == 0) {
        evpl_close(evpl, bind);
        goto out;
    }

    evpl_core_assert(res <= nmsg);

    for (i = 0; i < res; ++i) {

        datagram = datagrams[i];
        msghdr   = &msgvecs[i].msg_hdr;

        addr = evpl_address_alloc();

        memcpy(addr->addr, msghdr->msg_name,  msghdr->msg_namelen);
        addr->addrlen = msghdr->msg_namelen;

        notify.notify_type   = EVPL_NOTIFY_RECV_MSG;
        notify.notify_status = 0;

        datagram->iovec.length =  msgvecs[i].msg_len;

        notify.recv_msg.iovec  = &datagram->iovec;
        notify.recv_msg.niov   = 1;
        notify.recv_msg.length = msgvecs[i].msg_len;
        notify.recv_msg.addr   = addr;

        bind->notify_callback(evpl, bind, &notify, bind->private_data);

        evpl_iovec_decref(&datagram->iovec);
        evpl_socket_datagram_reload(evpl, s, datagram);
        evpl_address_release(addr);

    }

 out:
    for (i = 0; i < nmsg; ++i) {
        evpl_socket_datagram_free(evpl, s, datagrams[i]);
    }

    if (res < nmsg) {
        evpl_event_mark_unreadable(evpl, event);
    }

} /* evpl_socket_udp_read */

void
evpl_socket_udp_write(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_socket *s    = evpl_event_socket(event);
    struct evpl_bind   *bind = evpl_private2bind(s);
    struct evpl_iovec  *iovec;
    struct evpl_dgram  *dgram;
    struct evpl_notify  notify;
    struct iovec       *iov;
    int                 nmsg = 0, nmsgleft, i;
    int                 maxmsg = evpl_shared->config->max_datagram_batch;
    int                 maxiov = evpl_shared->config->max_num_iovec;
    struct msghdr      *msghdr;
    struct mmsghdr     *msgvec;
    ssize_t             res, total;

    if (unlikely(s->fd < 0)) {
        return;
    }

    dgram = evpl_dgram_ring_tail(&bind->dgram_send);

    if (!dgram) {
        res = -1;
        goto out;
    }

    msgvec = alloca(sizeof(struct mmsghdr) * maxmsg);

    iov = alloca(sizeof(struct iovec) * maxmsg * maxiov);

    iovec = evpl_iovec_ring_tail(&bind->iovec_send);

    while (dgram && nmsg < maxmsg) {

        msghdr = &msgvec[nmsg].msg_hdr;

        msghdr->msg_name       = dgram->addr->addr;
        msghdr->msg_namelen    = dgram->addr->addrlen;
        msghdr->msg_iov        = iov;
        msghdr->msg_iovlen     = dgram->niov;
        msghdr->msg_control    = NULL;
        msghdr->msg_controllen = 0;
        msghdr->msg_flags      = 0;

        for (i = 0; i < dgram->niov; ++i) {
            iov->iov_base = iovec->data;
            iov->iov_len  = iovec->length;
            iov++;
            iovec = evpl_iovec_ring_next(&bind->iovec_send, iovec);
        }

        dgram = evpl_dgram_ring_next(&bind->dgram_send, dgram);

        nmsg++;
    }


    res = sendmmsg(s->fd, msgvec, nmsg, MSG_NOSIGNAL | MSG_DONTWAIT);

    if (res < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            evpl_close(evpl, bind);
        }
        goto out;
    }

    nmsgleft = res;

    while (nmsgleft) {
        dgram = evpl_dgram_ring_tail(&bind->dgram_send);

        evpl_address_release(dgram->addr);

        evpl_iovec_ring_consumev(evpl, &bind->iovec_send, dgram->niov);

        evpl_dgram_ring_remove(&bind->dgram_send);

        --nmsgleft;
    }

    if (evpl_dgram_ring_is_empty(&bind->dgram_send)) {
        evpl_event_write_disinterest(evpl, event);

        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_close(evpl, bind);
        }
    }

    if (res > 0 && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {

        total = 0;

        for (i = 0; i < res; ++i) {
            total += msgvec[i].msg_len;
        }

        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = total;
        notify.sent.msgs     = res;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

 out:

    if (res != nmsg) {
        evpl_event_mark_unwritable(evpl, event);
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
    struct evpl_socket     *s = evpl_bind_private(evbind);
    int                     flags, rc;

    if (unlikely(s->fd < 0)) {
        return;
    }

#if 0
    struct sockaddr_storage addr;
    socklen_t               addrlen = sizeof(addr);
#endif /* if 0 */


    s->fd = socket(evbind->local->addr->sa_family, SOCK_DGRAM, 0);

    evpl_socket_abort_if(s->fd < 0, "Failed to create socket: %s", strerror(
                             errno));

    flags = fcntl(s->fd, F_GETFL, 0);

    evpl_socket_abort_if(flags < 0, "Failed to get socket flags: %s", strerror(
                             errno));

    rc = fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);

    evpl_socket_abort_if(rc, "Failed to set socket flags: %s", strerror(errno));

    rc = bind(s->fd, evbind->local->addr, evbind->local->addrlen);

    evpl_socket_abort_if(rc, "Failed to bind socket: %s", strerror(errno));

#if 0
    rc = getsockname(s->fd, (struct sockaddr *) &addr, &addrlen);

    evpl_socket_abort_if(rc, "Failed to get socket name: %s", strerror(errno));

    if (addr.ss_family == AF_INET) {
        port = ntohs(((struct sockaddr_in *) &addr)->sin_port);
    } else if (addr.ss_family == AF_INET6) {
        port = ntohs(((struct sockaddr_in6 *) &addr)->sin6_port);
    }
#endif /* if 0 */

    evpl_socket_init(evpl, s, s->fd, 0);

    evpl_add_event(evpl, &s->event, s->fd,
                   evpl_socket_udp_read,
                   evpl_socket_udp_write,
                   evpl_socket_udp_error);

    evpl_event_read_interest(evpl, &s->event);
} /* evpl_socket_udp_bind */

struct evpl_protocol evpl_socket_udp = {
    .id            = EVPL_DATAGRAM_SOCKET_UDP,
    .connected     = 0,
    .stream        = 0,
    .name          = "DATAGRAM_SOCKET_UDP",
    .bind          = evpl_socket_udp_bind,
    .pending_close = evpl_socket_pending_close,
    .close         = evpl_socket_close,
    .flush         = evpl_socket_flush,
};
