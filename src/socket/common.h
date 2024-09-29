#pragma once

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

struct evpl_socket_msg {
    struct evpl_endpoint_stub   eps;
    struct evpl_bvec            bvec;
    struct iovec                iov;
    struct evpl_socket_msg     *next;
};

struct evpl_socket {
    struct evpl_event         event;
    int                       fd;
    int                       connected;
    const struct evpl_config *config;
    struct evpl_socket_msg   *free_msgs;
    struct evpl_bvec          recv1;
    struct evpl_bvec          recv2;
};

#define evpl_event_socket(eventp) container_of((eventp), struct evpl_socket, \
                                               event)

static inline struct evpl_socket_msg *
evpl_socket_msg_alloc(
    struct evpl        *evpl,
    struct evpl_socket *s)
{
    struct evpl_socket_msg *msg;

    if (s->free_msgs) {
        msg = s->free_msgs;
        LL_DELETE(s->free_msgs, msg);
    } else {
        msg = evpl_zalloc(sizeof(*msg));
        evpl_bvec_alloc(evpl, s->config->max_msg_size, 0, 1, &msg->bvec);
    }

    return msg;
} // evpl_socket_msg_alloc

static inline void
evpl_socket_msg_free(
    struct evpl            *evpl,
    struct evpl_socket     *s,
    struct evpl_socket_msg *msg)
{
    LL_PREPEND(s->free_msgs, msg);
} // evpl_socket_msg_free

static inline void
evpl_socket_msg_reload(
    struct evpl            *evpl,
    struct evpl_socket     *s,
    struct evpl_socket_msg *msg)
{
    evpl_bvec_alloc(evpl, s->config->max_msg_size, 0, 1, &msg->bvec);
} // evpl_socket_msg_reload

static inline void
evpl_socket_init(
    struct evpl        *evpl,
    struct evpl_socket *s,
    int                 fd,
    int                 connected)
{
    s->fd        = fd;
    s->connected = connected;
    s->config    = evpl_config(evpl);
} /* evpl_socket_init */


static inline void
evpl_socket_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket     *s = evpl_bind_private(bind);
    struct evpl_socket_msg *msg;

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

    while (s->free_msgs) {
        msg = s->free_msgs;
        LL_DELETE(s->free_msgs, msg);
        evpl_bvec_release(evpl, &msg->bvec);
        evpl_free(msg);
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
