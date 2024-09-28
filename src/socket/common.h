#pragma once

#define evpl_socket_debug(...) evpl_debug("socket", __VA_ARGS__)
#define evpl_socket_info(...)  evpl_info("socket", __VA_ARGS__)
#define evpl_socket_error(...) evpl_error("socket", __VA_ARGS__)
#define evpl_socket_fatal(...) evpl_fatal("socket", __VA_ARGS__)
#define evpl_socket_abort(...) evpl_abort("socket", __VA_ARGS__)

#define evpl_socket_fatal_if(cond, ...) \
    evpl_fatal_if(cond, "socket", __VA_ARGS__)

#define evpl_socket_abort_if(cond, ...) \
    evpl_abort_if(cond, "socket", __VA_ARGS__)


struct evpl_socket {
    struct evpl_event event;
    int               fd;
    int               connected;
    int               recv_size;
    struct evpl_bvec  recv1;
    struct evpl_bvec  recv2;
};

#define evpl_event_socket(eventp) container_of((eventp), struct evpl_socket, \
                                               event)

static inline void
evpl_socket_init(
    struct evpl        *evpl,
    struct evpl_socket *s,
    int                 fd,
    int                 connected)
{
    struct evpl_config *config = evpl_config(evpl);

    s->fd        = fd;
    s->connected = connected;
    s->recv_size = config->buffer_size;
} /* evpl_socket_init */


static inline void
evpl_socket_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket *s = evpl_bind_private(bind);

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

} /* evpl_tcp_close_conn */

static inline void
evpl_socket_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_socket *s = evpl_bind_private(bind);

    evpl_event_write_interest(evpl, &s->event);
} /* evpl_socket_udp_flush */
