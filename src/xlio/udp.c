#define _GNU_SOURCE /* See feature_test_macros(7) */

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

#include "core/internal.h"
#include "core/evpl.h"
#include "core/event.h"
#include "core/buffer.h"
#include "core/endpoint.h"
#include "core/bind.h"
#include "core/protocol.h"

#include "core/protocol.h"
#include "core/evpl.h"
#include "common.h"

int
evpl_xlio_udp_read(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s)
{
    struct evpl_xlio             *xlio;
    struct evpl_bind             *bind = evpl_private2bind(s);
    struct evpl_socket_datagram **datagrams, *datagram;
    struct evpl_notify            notify;
    struct msghdr                *msghdr;
    struct mmsghdr               *msgvecs, *msgvec;
    struct sockaddr_storage      *sockaddrs;
    struct evpl_address          *addr;
    struct iovec                 *iov;
    ssize_t                       res;
    int                           i, nmsg = s->config->max_datagram_batch;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    datagrams = alloca(sizeof(struct evpl_xlio_datagram * ) * nmsg);
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

        iov->iov_base = datagram->bvec.data;
        iov->iov_len  = datagram->bvec.length;

        iov++;
    }

    res = xlio->api->recvmmsg(s->fd, msgvecs, nmsg, MSG_NOSIGNAL | MSG_DONTWAIT,
                              NULL
                              );

    if (res <= 0) {
        goto out;
    }

    for (i = 0; i < res; ++i) {

        datagram = datagrams[i];
        msghdr   = &msgvecs[i].msg_hdr;

        addr = evpl_address_alloc(evpl);

        memcpy(addr->addr, msghdr->msg_name,  msghdr->msg_namelen);
        addr->addrlen = msghdr->msg_namelen;

        notify.notify_type   = EVPL_NOTIFY_RECV_MSG;
        notify.notify_status = 0;

        datagram->bvec.length =  msgvecs[i].msg_len;

        notify.recv_msg.bvec   = &datagram->bvec;
        notify.recv_msg.nbvec  = 1;
        notify.recv_msg.length = msgvecs[i].msg_len;
        notify.recv_msg.addr   = addr;

        bind->notify_callback(evpl, bind, &notify, bind->private_data);

        evpl_bvec_release(evpl, &datagram->bvec);
        evpl_socket_datagram_reload(evpl, s, datagram);
        evpl_address_release(evpl, addr);

    }

 out:

    for (i = 0; i < nmsg; ++i) {
        evpl_socket_datagram_free(evpl, s, datagrams[i]);
    }

    if (res > 0 && res < nmsg) {
        errno = EAGAIN;
    }

    return res;

} /* evpl_xlio_udp_read */

void
evpl_xlio_udp_read_packets(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s,
    struct sockaddr_in      *srcaddr,
    struct xlio_buff_t      *buffs,
    int                      nbufs,
    uint16_t                 total_length)
{
    struct evpl_xlio    *xlio;
    struct evpl_bind    *bind = evpl_private2bind(s);
    struct evpl_notify   notify;
    struct evpl_address *addr;
    struct evpl_bvec    *bvec;
    struct xlio_buff_t  *cur;
    int                  i;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    addr          = evpl_address_alloc(evpl);
    addr->addr    = (struct sockaddr *) srcaddr;
    addr->addrlen = sizeof(*srcaddr);

    bvec = alloca(sizeof(struct evpl_bvec) * nbufs);

    cur = buffs;

    for (i = 0; i < nbufs ; i++, cur = cur->next) {
        bvec[i].buffer = evpl_xlio_buffer_alloc(evpl, xlio, cur);
        bvec[i].data   = cur->payload;
        bvec[i].length = cur->len;
    }

    notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
    notify.notify_status   = 0;
    notify.recv_msg.bvec   = bvec;
    notify.recv_msg.nbvec  = nbufs;
    notify.recv_msg.length = total_length;
    notify.recv_msg.addr   = addr;

    bind->notify_callback(evpl, bind, &notify, bind->private_data);

} /* evpl_xlio_udp_read_packets */

int
evpl_xlio_udp_write(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s)
{
    struct evpl_xlio  *xlio;
    struct evpl_bind  *bind = evpl_private2bind(s);
    struct evpl_bvec  *bvec;
    struct evpl_dgram *dgram;
    struct evpl_notify notify;
    struct iovec      *iov;
    int                nmsg = 0, nmsgleft, i;
    int                maxmsg = s->config->max_datagram_batch;
    int                maxiov = s->config->max_num_bvec;
    struct msghdr     *msghdr;
    struct mmsghdr    *msgvec;
    ssize_t            res, total;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    dgram = evpl_dgram_ring_tail(&bind->dgram_send);

    if (!dgram) {
        res = 0;
        goto out;
    }

    msgvec = alloca(sizeof(struct mmsghdr) * maxmsg);

    iov = alloca(sizeof(struct iovec) * maxmsg * maxiov);

    bvec = evpl_bvec_ring_tail(&bind->bvec_send);

    while (dgram && nmsg < maxmsg) {

        msghdr = &msgvec[nmsg].msg_hdr;

        msghdr->msg_name       = dgram->addr->addr;
        msghdr->msg_namelen    = dgram->addr->addrlen;
        msghdr->msg_iov        = iov;
        msghdr->msg_iovlen     = dgram->nbvec;
        msghdr->msg_control    = NULL;
        msghdr->msg_controllen = 0;
        msghdr->msg_flags      = 0;

        for (i = 0; i < dgram->nbvec; ++i) {
            iov->iov_base = bvec->data;
            iov->iov_len  = bvec->length;
            iov++;
            bvec = evpl_bvec_ring_next(&bind->bvec_send, bvec);
        }

        dgram = evpl_dgram_ring_next(&bind->dgram_send, dgram);

        nmsg++;
    }


    res = xlio->api->sendmmsg(s->fd, msgvec, nmsg, MSG_NOSIGNAL | MSG_DONTWAIT);

    if (res < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            evpl_defer(evpl, &bind->close_deferral);
        }
        goto out;
    }

    nmsgleft = res;

    while (nmsgleft) {
        dgram = evpl_dgram_ring_tail(&bind->dgram_send);

        evpl_address_release(evpl, dgram->addr);

        evpl_bvec_ring_consumev(evpl, &bind->bvec_send, dgram->nbvec);

        evpl_dgram_ring_remove(&bind->dgram_send);

        --nmsgleft;
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

    if (nmsg && res != nmsg) {
        return -1;
    }

    return 0;

} /* evpl_xlio_udp_write */

void
evpl_xlio_udp_bind(
    struct evpl      *evpl,
    struct evpl_bind *evbind)
{
    struct evpl_xlio        *xlio;
    struct evpl_xlio_socket *s = evpl_bind_private(evbind);
    int                      flags, rc;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    s->fd = xlio->api->socket(evbind->local->addr->sa_family, SOCK_DGRAM, 0);

    evpl_xlio_abort_if(s->fd < 0, "Failed to create socket: %s", strerror(
                           errno));

    flags = xlio->api->fcntl(s->fd, F_GETFL, 0);

    evpl_xlio_abort_if(flags < 0, "Failed to get socket flags: %s", strerror(
                           errno));

    rc = xlio->api->fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);

    evpl_xlio_abort_if(rc, "Failed to set socket flags: %s", strerror(errno));

    rc = xlio->api->bind(s->fd, evbind->local->addr, evbind->local->addrlen);

    evpl_xlio_abort_if(rc, "Failed to bind socket: %s", strerror(errno));

    evpl_xlio_socket_init(evpl, xlio, s, s->fd, 0, 1,
                          NULL,
                          evpl_xlio_udp_read,
                          evpl_xlio_udp_read_packets,
                          evpl_xlio_udp_write);

} /* evpl_xlio_udp_bind */

struct evpl_protocol evpl_xlio_udp = {
    .id        = EVPL_DATAGRAM_XLIO_UDP,
    .connected = 0,
    .stream    = 0,
    .name      = "DATAGRAM_XLIO_UDP",
    .bind      = evpl_xlio_udp_bind,
    .close     = evpl_xlio_close,
    .flush     = evpl_xlio_flush,
};
