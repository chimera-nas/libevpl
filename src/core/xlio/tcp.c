// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <linux/errqueue.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "core/internal.h"
#include "evpl/evpl.h"
#include "core/event.h"
#include "core/buffer.h"
#include "core/endpoint.h"
#include "core/bind.h"
#include "core/protocol.h"

#include "common.h"

static inline void
evpl_xlio_prepare_iov(
    struct evpl                  *evpl,
    struct evpl_xlio             *xlio,
    struct evpl_xlio_socket      *s,
    struct iovec                 *iov,
    struct xlio_socket_send_attr *send_attr,
    struct evpl_iovec_ring       *ring)
{
    struct evpl_buffer  *buffer;
    struct ibv_mr      **mrset;
    struct evpl_iovec   *iovec;
    struct evpl_xlio_zc *zc;
    int                  pos = ring->tail;

    iovec = &ring->iovec[pos];

    buffer = iovec->private;

    mrset = (struct ibv_mr **) evpl_buffer_framework_private(buffer,
                                                             EVPL_FRAMEWORK_XLIO);

    send_attr->mkey = mrset[s->pd_index]->lkey;

    iov->iov_base = iovec->data;
    iov->iov_len  = iovec->length;

    if (iovec->length <= 64) {
        send_attr->flags |= XLIO_SOCKET_SEND_FLAG_INLINE;
    } else {
        send_attr->flags = 0;

        zc = evpl_xlio_alloc_zc(xlio);

        zc->buffer = iovec->private;
        zc->length = iovec->length;
        atomic_fetch_add_explicit(&zc->buffer->refcnt, 1, memory_order_relaxed);

        s->zc_pending++;

        send_attr->userdata_op = (uintptr_t) zc;
    }

} /* evpl_xlio_prepare_iov */

void
evpl_xlio_tcp_read(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s)
{
    struct evpl_bind  *bind = evpl_private2bind(s);
    struct evpl_notify notify;
    struct evpl_iovec *iovec;
    int                i, length, niov;

    if (bind->segment_callback) {

        iovec = alloca(sizeof(struct evpl_iovec) * s->config->max_num_iovec);

        while (1) {

            length = bind->segment_callback(evpl, bind, bind->private_data);

            if (length == 0 ||
                evpl_iovec_ring_bytes(&bind->iovec_recv) < length) {
                break;
            }

            if (unlikely(length < 0)) {
                evpl_defer(evpl, &bind->close_deferral);
                return;
            }

            niov = evpl_iovec_ring_copyv(evpl, iovec, &bind->iovec_recv,
                                         length);

            notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
            notify.recv_msg.iovec  = iovec;
            notify.recv_msg.niov   = niov;
            notify.recv_msg.length = length;
            notify.recv_msg.addr   = bind->remote;

            bind->notify_callback(evpl, bind, &notify, bind->private_data);

            for (i = 0; i < niov; ++i) {
                evpl_iovec_release(&iovec[i]);
            }

        }

    } else {
        notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
        notify.notify_status = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }

} /* evpl_xlio_tcp_read */

int
evpl_xlio_tcp_write(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s)
{
    struct evpl_xlio            *xlio;
    struct evpl_bind            *bind = evpl_private2bind(s);
    struct iovec                 iov;
    struct xlio_socket_send_attr send_attr;
    ssize_t                      res;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    evpl_xlio_prepare_iov(evpl, xlio, s, &iov, &send_attr, &bind->iovec_send);

    res = xlio->extra->xlio_socket_sendv(s->socket, &iov, 1, &send_attr);

    if (res) {
        return res;
    }

    evpl_iovec_ring_consume(evpl, &bind->iovec_send, iov.iov_len);

    return 0;
} /* evpl_write_tcp */

void
evpl_xlio_tcp_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_xlio        *xlio;
    struct evpl_xlio_socket *s = evpl_bind_private(bind);
    struct xlio_socket_attr  sock_attr;
    int                      rc;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    memset(&sock_attr, 0, sizeof(sock_attr));

    sock_attr.domain      = bind->remote->addr->sa_family;
    sock_attr.group       = xlio->poll_group;
    sock_attr.userdata_sq = (uintptr_t) s;

    rc = xlio->extra->xlio_socket_create(&sock_attr, &s->socket);

    evpl_xlio_abort_if(rc, "Failed to create XLIO tcp socket: %s", strerror(
                           errno));

    rc = xlio->extra->xlio_socket_connect(s->socket, bind->remote->addr, bind->
                                          remote->addrlen);

    evpl_xlio_abort_if(rc < 0,
                       "Failed to connect tcp socket: %s", strerror(errno));

    evpl_xlio_socket_init(evpl, xlio, s, 0, 0,
                          evpl_xlio_tcp_read,
                          evpl_xlio_tcp_write);

} /* evpl_xlio_tcp_connect */

void
evpl_xlio_tcp_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind)
{
    struct evpl_xlio        *xlio;
    struct evpl_xlio_socket *s = evpl_bind_private(listen_bind);
    struct xlio_socket_attr  sock_attr;
    int                      rc, yes = 1;

    s->evpl = evpl;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    memset(&sock_attr, 0, sizeof(sock_attr));

    sock_attr.domain      = listen_bind->local->addr->sa_family;
    sock_attr.group       = xlio->poll_group;
    sock_attr.userdata_sq = (uintptr_t) s;

    rc = xlio->extra->xlio_socket_create(&sock_attr, &s->socket);

    evpl_xlio_abort_if(rc, "Failed to create tcp listen socket: %s",
                       strerror(errno));

    rc = xlio->extra->xlio_socket_setsockopt(
        s->socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes));

    evpl_xlio_abort_if(rc < 0, "Failed to set SO_REUSEADDR");

    rc = xlio->extra->xlio_socket_bind(
        s->socket, listen_bind->local->addr, listen_bind->local->addrlen);

    evpl_xlio_abort_if(rc < 0, "Failed to bind listen socket: %s", strerror(
                           errno));

    rc = xlio->extra->xlio_socket_listen(s->socket);

    evpl_xlio_fatal_if(rc < 0, "Failed to listen on listener fd");

    evpl_xlio_socket_init(evpl, xlio, s, 1, 0,
                          evpl_xlio_tcp_read,
                          evpl_xlio_tcp_write);

} /* evpl_xlio_tcp_listen */

extern struct evpl_framework evpl_framework_xlio;
struct evpl_protocol         evpl_xlio_tcp = {
    .id        = EVPL_STREAM_XLIO_TCP,
    .connected = 1,
    .stream    = 1,
    .name      = "STREAM_XLIO_TCP",
    .framework = &evpl_framework_xlio,
    .connect   = evpl_xlio_tcp_connect,
    .close     = evpl_xlio_close,
    .listen    = evpl_xlio_tcp_listen,
    .flush     = evpl_xlio_flush,
};
