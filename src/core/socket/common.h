// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#include <netinet/tcp.h> // For TCP_NODELAY


#include "uthash/utlist.h"
#include "evpl/evpl.h"
#include "core/evpl_shared.h"

extern struct evpl_shared *evpl_shared;
#define evpl_socket_debug(...) evpl_debug("socket", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_socket_info(...)  evpl_info("socket", __FILE__, __LINE__, \
                                         __VA_ARGS__)
#define evpl_socket_error(...) evpl_error("socket", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_socket_fatal(...) evpl_fatal("socket", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_socket_abort(...) evpl_abort("socket", __FILE__, __LINE__, \
                                          __VA_ARGS__)

#define evpl_socket_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "socket", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_socket_abort_if(cond, ...) \
        evpl_abort_if(cond, "socket", __FILE__, __LINE__, __VA_ARGS__)

struct evpl_socket_datagram {
    struct evpl_iovec            iovec;
    struct evpl_socket_datagram *next;
};

struct evpl_accepted_socket {
    int fd;
};

struct evpl_socket {
    struct evpl_event            event;
    int                          fd;
    int                          connected;
    struct evpl_socket_datagram *free_datagrams;
    struct evpl_iovec            recv1;
    struct evpl_iovec            recv2;
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
        evpl_iovec_alloc_datagram(evpl, &datagram->iovec, evpl_shared->config->max_datagram_size);
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
    evpl_iovec_alloc_datagram(evpl, &datagram->iovec,
                              evpl_shared->config->max_datagram_size);
} // evpl_socket_msg_reload

static inline void
evpl_socket_init(
    struct evpl        *evpl,
    struct evpl_socket *s,
    int                 fd,
    int                 connected)
{
    int flags, rc;

    s->fd        = fd;
    s->connected = connected;


    flags = fcntl(s->fd, F_GETFL, 0);

    evpl_socket_abort_if(flags < 0, "Failed to get socket flags: %s", strerror(
                             errno));

    rc = fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);

    evpl_socket_abort_if(rc < 0, "Failed to set socket flags: %s", strerror(
                             errno));

} /* evpl_socket_init */

static inline void
evpl_socket_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket *s = evpl_bind_private(bind);

    evpl_event_read_disinterest(evpl, &s->event);
    evpl_event_write_disinterest(evpl, &s->event);

    close(s->fd);

    s->fd = -1;
} /* evpl_socket_pending_close */

static inline void
evpl_socket_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket          *s = evpl_bind_private(bind);
    struct evpl_socket_datagram *datagram;

    if (s->recv1.length) {
        evpl_iovec_decref(&s->recv1);
        s->recv1.length = 0;
    }

    if (s->recv2.length) {
        evpl_iovec_decref(&s->recv2);
        s->recv2.length = 0;
    }

    if (bind->protocol->id == EVPL_DATAGRAM_SOCKET_UDP) {
        struct evpl_dgram *dgram;

        while ((dgram = evpl_dgram_ring_tail(&bind->dgram_send)) != NULL) {
            evpl_address_release(dgram->addr);
            evpl_dgram_ring_remove(&bind->dgram_send);
        }
    }

    while (s->free_datagrams) {
        datagram = s->free_datagrams;
        LL_DELETE(s->free_datagrams, datagram);
        evpl_iovec_decref(&datagram->iovec);
        evpl_free(datagram);
    }

} /* evpl_tcp_close_conn */

static inline void
evpl_socket_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket *s = evpl_bind_private(bind);

    evpl_event_write_interest(evpl, &s->event);
} /* evpl_socket_udp_flush */
