#pragma once

#define _GNU_SOURCE

#include <sys/epoll.h>
#include <sys/socket.h>
#include <mellanox/xlio_extra.h>

#include "core/internal.h"
#include "core/evpl.h"
#include "core/protocol.h"
#include "core/endpoint.h"
#include "core/event.h"
#include "core/bind.h"

#include "utlist.h"

#define evpl_xlio_debug(...) evpl_debug("xlio", __VA_ARGS__)
#define evpl_xlio_info(...)  evpl_info("xlio", __VA_ARGS__)
#define evpl_xlio_error(...) evpl_error("xlio", __VA_ARGS__)
#define evpl_xlio_fatal(...) evpl_fatal("xlio", __VA_ARGS__)
#define evpl_xlio_abort(...) evpl_abort("xlio", __VA_ARGS__)

#define evpl_xlio_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "xlio", __VA_ARGS__)

#define evpl_xlio_abort_if(cond, ...) \
        evpl_abort_if(cond, "xlio", __VA_ARGS__)

struct xlio_api_t;

typedef void (*xlio_exit_fptr_t)(
    void);

typedef int (*socket_fptr_t) (
    int __domain,
    int __type,
    int __protocol);

typedef int (*ioctl_fptr_t)(
    int __fd,
    int __request,
    ...);

typedef int (*fcntl_fptr_t)(
    int __fd,
    int __cmd,
    ...);

typedef int (*bind_fptr_t)(
    int                    __fd,
    const struct sockaddr *__addr,
    socklen_t              __addrlen);

typedef int (*close_fptr_t)(
    int __fd);

typedef ssize_t (*recvmmsg_fptr_t)(
    int                    __fd,
    struct mmsghdr        *__mmsghdr,
    unsigned int           __vlen,
    int                    __flags,
    const struct timespec *__timeout);

typedef ssize_t (*sendmmsg_fptr_t)(
    int             __fd,
    struct mmsghdr *__mmsghdr,
    unsigned int    __vlen,
    int             __flags);

typedef int (*getsockopt_fptr_t)(
    int        __fd,
    int        __level,
    int        __optname,
    void      *__optval,
    socklen_t *__optlen);
typedef int (*setsockopt_fptr_t)(
    int           __fd,
    int           __level,
    int           __optname,
    __const void *__optval,
    socklen_t     __optlen);
typedef ssize_t (*readv_fptr_t)(
    int                 __fd,
    const struct iovec *iov,
    int                 iovcnt);

typedef ssize_t (*writev_fptr_t)(
    int                 __fd,
    const struct iovec *iov,
    int                 iovcnt);

typedef int (*connect_fptr_t)(
    int                    __fd,
    const struct sockaddr *__to,
    socklen_t              __tolen);

typedef int (*listen_fptr_t)(
    int __fd,
    int __backlog);

typedef int (*accept_fptr_t)(
    int              __fd,
    struct sockaddr *__addr,
    socklen_t       *__addrlen);

typedef int (*epoll_create_fptr_t)(
    int __size);

typedef int (*epoll_ctl_fptr_t)(
    int                 __epfd,
    int                 __op,
    int                 __fd,
    struct epoll_event *__event);

typedef int (*epoll_wait_fptr_t)(
    int                 __epfd,
    struct epoll_event *__events,
    int                 __maxevents,
    int                 __timeout);

struct evpl_xlio_api {
    void               *hdl;

    xlio_exit_fptr_t    xlio_exit;
    socket_fptr_t       socket;
    ioctl_fptr_t        ioctl;
    fcntl_fptr_t        fcntl;
    bind_fptr_t         bind;
    close_fptr_t        close;
    recvmmsg_fptr_t     recvmmsg;
    sendmmsg_fptr_t     sendmmsg;
    readv_fptr_t        readv;
    writev_fptr_t       writev;
    listen_fptr_t       listen;
    accept_fptr_t       accept;
    connect_fptr_t      connect;
    getsockopt_fptr_t   getsockopt;
    setsockopt_fptr_t   setsockopt;

    epoll_create_fptr_t epoll_create;
    epoll_ctl_fptr_t    epoll_ctl;
    epoll_wait_fptr_t   epoll_wait;

    struct xlio_api_t  *extra;
};

struct evpl_xlio_ring_fd {
    int fd;
    int refcnt;
};

struct evpl_socket_datagram {
    struct evpl_bvec             bvec;
    struct evpl_socket_datagram *next;
};

struct evpl_xlio_socket;

typedef void (*evpl_xlio_read_packets_callback_t)(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s,
    struct sockaddr_in      *srcaddr,
    struct xlio_buff_t      *buffs,
    int                      nbufs,
    uint16_t                 total_length);

typedef int (*evpl_xlio_read_callback_t)(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s);


typedef int (*evpl_xlio_write_callback_t)(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s);

typedef struct evpl_xlio_socket * (*evpl_xlio_accept_callback_t)(
    struct evpl             *evpl,
    struct evpl_xlio_socket *ls,
    struct evpl_address     *src,
    int                      fd);

struct evpl_xlio_event {
    int writable;
    int write_interest;
    int active;
};

struct evpl_xlio_socket {
    union {
        struct evpl_event      event;
        struct evpl_xlio_event xlio_event;
    };

    evpl_xlio_accept_callback_t       accept_callback;
    evpl_xlio_read_callback_t         read_callback;
    evpl_xlio_read_packets_callback_t read_packets_callback;
    evpl_xlio_write_callback_t        write_callback;

    int                               fd;
    int                               listen;
    int                               connected;
    int                               offloaded;
    const struct evpl_config         *config;
    struct evpl_socket_datagram      *free_datagrams;
    struct evpl_bvec                  recv1;
    struct evpl_bvec                  recv2;
    struct evpl_xlio_socket          *prev;
    struct evpl_xlio_socket          *next;
};

struct evpl_xlio {
    struct evpl_xlio_api     *api;
    struct evpl_poll         *poll;
    struct evpl_xlio_ring_fd *ring_fds;
    struct evpl_xlio_socket **active_sockets;
    struct evpl_xlio_socket  *listen_sockets;
    int                       num_ring_fds;
    int                       max_ring_fds;
    int                       num_active_sockets;
    int                       max_active_sockets;
};


#define evpl_event_xlio_socket(eventp) container_of((eventp), struct \
                                                    evpl_xlio_socket, \
                                                    event)

static inline void
evpl_xlio_buffer_free(
    struct evpl        *evpl,
    struct evpl_buffer *buffer)
{
    struct evpl_xlio   *xlio;
    struct xlio_buff_t *buff;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    buff = (struct xlio_buff_t *) buffer->framework_private[EVPL_FRAMEWORK_XLIO]
    ;

    xlio->api->extra->socketxtreme_free_buff(buff);

    evpl_free(buffer);
} // evpl_xlio_buffer_free

static inline struct evpl_buffer *
evpl_xlio_buffer_alloc(
    struct evpl        *evpl,
    struct evpl_xlio   *xlio,
    struct xlio_buff_t *buff)
{
    struct evpl_buffer *buffer;

    buffer = evpl_zalloc(sizeof(*buffer));

    buffer->data                                   = buff->payload;
    buffer->size                                   = buff->len;
    buffer->used                                   = buff->len;
    buffer->external                               = 1;
    buffer->framework_private[EVPL_FRAMEWORK_XLIO] = buff;
    buffer->refcnt                                 = 1;
    buffer->release                                = evpl_xlio_buffer_free;

    xlio->api->extra->socketxtreme_ref_buff(buff);

    return buffer;
} // evpl_xlio_buffer_alloc
static inline struct evpl_socket_datagram *
evpl_socket_datagram_alloc(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s)
{
    struct evpl_socket_datagram *datagram;

    if (s->free_datagrams) {
        datagram = s->free_datagrams;
        LL_DELETE(s->free_datagrams, datagram);
    } else {
        datagram = evpl_zalloc(sizeof(*datagram));
        evpl_bvec_alloc_datagram(evpl, &datagram->bvec);
    }

    return datagram;
} // evpl_socket_datagram_alloc

static inline void
evpl_socket_datagram_free(
    struct evpl                 *evpl,
    struct evpl_xlio_socket     *s,
    struct evpl_socket_datagram *datagram)
{
    LL_PREPEND(s->free_datagrams, datagram);
} // evpl_socket_msg_free

static inline void
evpl_socket_datagram_reload(
    struct evpl                 *evpl,
    struct evpl_xlio_socket     *s,
    struct evpl_socket_datagram *datagram)
{
    evpl_bvec_alloc_datagram(evpl, &datagram->bvec);
} // evpl_socket_msg_reload

static inline void
evpl_xlio_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_xlio            *xlio;
    struct evpl_xlio_socket     *s = evpl_bind_private(bind);
    struct evpl_socket_datagram *datagram;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    if (s->listen) {
        DL_DELETE(xlio->listen_sockets, s);
    }

    if (s->fd >= 0) {
        xlio->api->close(s->fd);
    }

    if (s->recv1.length) {
        evpl_bvec_release(evpl, &s->recv1);
        s->recv1.length = 0;
    }

    if (s->recv2.length) {
        evpl_bvec_release(evpl, &s->recv2);
        s->recv2.length = 0;
    }


    while (s->free_datagrams) {
        datagram = s->free_datagrams;
        LL_DELETE(s->free_datagrams, datagram);
        evpl_bvec_release(evpl, &datagram->bvec);
        evpl_free(datagram);
    }


} /* evpl_tcp_close_conn */

static inline void
evpl_xlio_socket_check_active(
    struct evpl_xlio        *xlio,
    struct evpl_xlio_socket *s)
{

    if (s->xlio_event.write_interest &&
        s->xlio_event.writable &&
        !s->xlio_event.active) {

        xlio->active_sockets[xlio->num_active_sockets++] = s;

        s->xlio_event.active = 1;

    }

} // evpl_xlio_socket_check_active

static inline void
evpl_xlio_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_xlio        *xlio;
    struct evpl_xlio_socket *s = evpl_bind_private(bind);

    if (s->offloaded) {

        s->xlio_event.write_interest = 1;

        xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

        evpl_xlio_socket_check_active(xlio, s);

    } else {
        evpl_event_write_interest(evpl, &s->event);
    }
} /* evpl_xlio_udp_flush */

static inline void
evpl_xlio_poll(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_xlio                     *xlio = private_data;
    struct evpl_xlio_socket              *s, *ls;
    struct evpl_address                  *src;
    struct evpl_bind                     *bind;
    struct xlio_socketxtreme_completion_t comps[16], *comp;
    struct evpl_xlio_socket              *map[16];
    int                                   i, j, k, n, res;

    for (i = 0; i < xlio->num_ring_fds; ++i) {

        n = xlio->api->extra->socketxtreme_poll(xlio->ring_fds[i].fd, comps, 16,
                                                SOCKETXTREME_POLL_TX);

        for (j = 0; j < n; ++j) {

            comp = &comps[j];

            if (comp->events & XLIO_SOCKETXTREME_NEW_CONNECTION_ACCEPTED) {

                DL_FOREACH(xlio->listen_sockets, ls)
                {
                    if (ls->fd == comp->listen_fd) {
                        break;
                    }
                }

                evpl_xlio_abort_if(!ls, "Failed to find listen socket in list");

                src = evpl_address_alloc(evpl);

                memcpy(src->addr, &comp->src, sizeof(comp->src));
                src->addrlen = sizeof(comp->src);

                s = ls->accept_callback(evpl, ls, src, comp->user_data);

            } else {

                if (comp->user_data > 100000) {
                    s = (struct evpl_xlio_socket *) comp->user_data;
                } else {
                    for (k = 0; k < j; ++k) {
                        if (comp[k].user_data == comp->user_data) {
                            s = map[k];
                            break;
                        }
                    }
                }
            }

            map[j] = s;

            if (comp->events & XLIO_SOCKETXTREME_PACKET) {
                s->read_packets_callback(evpl, s, &comp->src,
                                         comp->packet.buff_lst,
                                         comp->packet.num_bufs,
                                         comp->packet.total_len);

                xlio->api->extra->socketxtreme_free_packets(&comp->packet, 1);

            }

            if (comp->events & EPOLLIN) {
                bind = evpl_private2bind(s);
                evpl_defer(evpl, &bind->close_deferral);

            }

            if (comp->events & EPOLLOUT) {
                s->xlio_event.writable = 1;
                evpl_xlio_socket_check_active(xlio, s);
            }

        }
    }

    for (i = 0; i < xlio->num_active_sockets; ++i) {

        s = xlio->active_sockets[i];

        bind = evpl_private2bind(s);

        res = s->write_callback(evpl, s);

        if (res <= 0) {
            evpl_defer(evpl, &bind->close_deferral);
        }

        if (evpl_dgram_ring_is_empty(&bind->dgram_send)) {
            s->xlio_event.write_interest = 0;

            if (bind->flags & EVPL_BIND_FINISH) {
                evpl_defer(evpl, &bind->close_deferral);
            }
        }

        if (res > 0 && errno == EAGAIN) {
            s->xlio_event.writable = 0;
        }

        if (!s->xlio_event.write_interest ||
            s->xlio_event.writable) {

            s->xlio_event.active = 0;

            if (i + 1 < xlio->num_active_sockets) {
                xlio->active_sockets[i] = xlio->active_sockets[xlio->
                                                               num_active_sockets
                                                               - 1];
                i--;
            }

            xlio->num_active_sockets--;
        }
    }

} // evpl_xlio_poll

static void
evpl_xlio_error_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_xlio_debug("xlio socket error");
} /* evpl_error_udp */

static void
evpl_xlio_accept_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_xlio        *xlio;
    struct evpl_xlio_socket *ls = evpl_event_xlio_socket(event);
    struct evpl_address     *src;
    int                      fd;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    while (1) {

        src = evpl_address_alloc(evpl);

        fd = xlio->api->accept(ls->fd, src->addr, &src->addrlen);

        if (fd < 0) {
            evpl_event_mark_unreadable(event);
            evpl_free(src);
            return;
        }

        ls->accept_callback(evpl, ls, src, fd);
    }

} /* evpl_xlio_accept_tcp */


static void
evpl_xlio_read_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_xlio_socket *s    = evpl_event_xlio_socket(event);
    struct evpl_bind        *bind = evpl_private2bind(s);
    int                      res;

    if (s->listen) {
        evpl_xlio_accept_event(evpl, event);
    } else {
        res = s->read_callback(evpl, s);

        if (res <= 0) {
            evpl_defer(evpl, &bind->close_deferral);
        }

        if (res >= 0 && errno == EAGAIN) {
            evpl_event_mark_unreadable(event);
        }
    }

} // evpl_xlio_read_event

static void
evpl_xlio_write_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_xlio_socket *s    = evpl_event_xlio_socket(event);
    struct evpl_bind        *bind = evpl_private2bind(s);
    int                      res;

    res = s->write_callback(evpl, s);

    if (res < 0) {
        evpl_defer(evpl, &bind->close_deferral);
    }

    if (res > 0) {
        evpl_event_mark_unwritable(event);
    }

    if (evpl_dgram_ring_is_empty(&bind->dgram_send)) {

        evpl_event_write_disinterest(event);

        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_defer(evpl, &bind->close_deferral);
        }
    }

} /* evpl_xlio_udp_write_event */


static inline void
evpl_xlio_socket_init(
    struct evpl                      *evpl,
    struct evpl_xlio                 *xlio,
    struct evpl_xlio_socket          *s,
    int                               fd,
    int                               listen,
    int                               connected,
    evpl_xlio_accept_callback_t       accept_callback,
    evpl_xlio_read_callback_t         read_callback,
    evpl_xlio_read_packets_callback_t read_packets_callback,
    evpl_xlio_write_callback_t        write_callback)
{
    struct evpl_xlio_ring_fd *rfd;
    int                       n, max_fd;
    int                       i, j, res;
    int                      *fds;

    s->fd        = fd;
    s->listen    = listen;
    s->connected = connected;
    s->config    = evpl_config(evpl);

    s->accept_callback       = accept_callback;
    s->read_callback         = read_callback;
    s->read_packets_callback = read_packets_callback;
    s->write_callback        = write_callback;

    max_fd = xlio->api->extra->get_socket_rings_num(fd);

    if (max_fd) {
        s->offloaded = 1;

        fds = alloca(sizeof(int) * max_fd);

        n = xlio->api->extra->get_socket_rings_fds(fd, fds, max_fd);

        evpl_xlio_abort_if(n < 0, "Failed to get XLIO ring fds");

        for (i = 0; i < n; ++i) {

            for (j = 0 ; j < xlio->num_ring_fds; ++j) {
                rfd = &xlio->ring_fds[j];
                if (rfd->fd == fds[i]) {
                    rfd->refcnt++;
                    break;
                }
            }

            if (j == xlio->num_ring_fds) {
                rfd         = &xlio->ring_fds[xlio->num_ring_fds];
                rfd->fd     = fds[i];
                rfd->refcnt = 1;
                xlio->num_ring_fds++;
            }
        }

        if (!xlio->poll) {
            xlio->poll = evpl_add_poll(evpl, evpl_xlio_poll, xlio);
        }

        s->xlio_event.writable       = connected;
        s->xlio_event.write_interest = 0;
        s->xlio_event.active         = 0;

        res = xlio->api->setsockopt(s->fd, SOL_SOCKET, SO_XLIO_USER_DATA, &s,
                                    sizeof(s));

        evpl_xlio_abort_if(res, "Failed to set SO_XLIO_USER_DATA for socket");

    } else {
        evpl_xlio_debug("EVPL XLIO socket fd %d not offloaded", fd);
        s->offloaded = 0;

        s->event.fd             = s->fd;
        s->event.read_callback  = evpl_xlio_read_event;
        s->event.write_callback = evpl_xlio_write_event;
        s->event.error_callback = evpl_xlio_error_event;

        evpl_add_event(evpl, &s->event);
        evpl_event_read_interest(evpl, &s->event);

    }

    if (listen) {
        DL_APPEND(xlio->listen_sockets, s);
    }

} /* evpl_socket_init */
