#pragma once

#include <netinet/tcp.h> // For TCP_NODELAY


#include "utlist.h"
#include "core/evpl.h"

#define evpl_socket_debug(...) evpl_debug("socket", __VA_ARGS__)
#define evpl_socket_info(...)  evpl_info("socket", __VA_ARGS__)
#define evpl_socket_error(...) evpl_error("socket", __VA_ARGS__)
#define evpl_socket_fatal(...) evpl_fatal("socket", __VA_ARGS__)
#define evpl_socket_abort(...) evpl_abort("socket", __VA_ARGS__)

#define evpl_socket_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "socket", __VA_ARGS__)

#define evpl_socket_abort_if(cond, ...) \
        evpl_abort_if(cond, "socket", __VA_ARGS__)

struct evpl_socket_datagram {
    struct evpl_bvec             bvec;
    struct evpl_socket_datagram *next;
};

struct evpl_socket {
    struct evpl_event            event;
    int                          fd;
    int                          connected;
    const struct evpl_config    *config;
    struct evpl_socket_datagram *free_datagrams;
    struct evpl_bvec             recv1;
    struct evpl_bvec             recv2;
};

#define evpl_event_socket(eventp) container_of((eventp), struct evpl_socket, \
                                               event)

static inline struct evpl_socket_datagram *
evpl_socket_datagram_alloc(
    struct evpl        *evpl,
    struct evpl_socket *s)
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
    struct evpl_socket          *s,
    struct evpl_socket_datagram *datagram)
{
    LL_PREPEND(s->free_datagrams, datagram);
} // evpl_socket_msg_free

static inline void
evpl_socket_datagram_reload(
    struct evpl                 *evpl,
    struct evpl_socket          *s,
    struct evpl_socket_datagram *datagram)
{
    evpl_bvec_alloc_datagram(evpl, &datagram->bvec);
} // evpl_socket_msg_reload

static inline void
evpl_socket_init(
    struct evpl        *evpl,
    struct evpl_socket *s,
    int                 fd,
    int                 connected)
{
    int flags, rc;
    int res, yes = 1;

    s->fd        = fd;
    s->connected = connected;
    s->config    = evpl_config(evpl);


    flags = fcntl(s->fd, F_GETFL, 0);

    evpl_socket_abort_if(flags < 0, "Failed to get socket flags: %s", strerror(
                             errno));

    rc = fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);

    evpl_socket_abort_if(rc < 0, "Failed to set socket flags: %s", strerror(
                             errno));


    res = setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, (char *) &yes, sizeof(yes)
                     );

    evpl_socket_abort_if(res, "Failed to set TCP_QUICKACK on socket");


} /* evpl_socket_init */


static inline void
evpl_socket_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket          *s = evpl_bind_private(bind);
    struct evpl_socket_datagram *datagram;

    evpl_remove_event(evpl, &s->event);

    if (s->fd >= 0) {
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

    while (s->free_datagrams) {
        datagram = s->free_datagrams;
        LL_DELETE(s->free_datagrams, datagram);
        evpl_bvec_release(evpl, &datagram->bvec);
        evpl_free(datagram);
    }

    evpl_bind_destroy(evpl, bind);
} /* evpl_tcp_close_conn */

static inline void
evpl_socket_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket *s = evpl_bind_private(bind);

    evpl_event_write_interest(evpl, &s->event);
} /* evpl_socket_udp_flush */
