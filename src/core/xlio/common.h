// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#define _GNU_SOURCE

#include <sys/epoll.h>
#include <sys/socket.h>
#include <mellanox/xlio_extra.h>
#include <infiniband/verbs.h>
#include <utlist.h>

#include "core/evpl.h"
#include "evpl/evpl.h"
#include "core/protocol.h"
#include "core/endpoint.h"
#include "core/allocator.h"
#include "core/bind.h"

#define evpl_xlio_debug(...) evpl_debug("xlio", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_xlio_info(...)  evpl_info("xlio", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_xlio_error(...) evpl_error("xlio", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_xlio_fatal(...) evpl_fatal("xlio", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_xlio_abort(...) evpl_abort("xlio", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_xlio_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "xlio", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_xlio_abort_if(cond, ...) \
        evpl_abort_if(cond, "xlio", __FILE__, __LINE__, __VA_ARGS__)

#define EVPL_XLIO_MAX_PD 16

struct xlio_api_t;

struct evpl_xlio_buffer {
    struct evpl_iovec_ref    ref;
    struct evpl_xlio        *xlio;
    struct xlio_buf         *buf;
    struct evpl_xlio_buffer *next;
};

struct evpl_xlio_api {
    void              *hdl;
    struct xlio_api_t *extra;
    struct ibv_pd     *pd[EVPL_XLIO_MAX_PD];
    pthread_mutex_t    pd_lock;
};

struct evpl_xlio_ring_fd {
    int fd;
    int refcnt;
};

struct evpl_socket_datagram {
    struct evpl_iovec            iovec;
    struct evpl_socket_datagram *next;
};

struct evpl_xlio_socket;

typedef void (*evpl_xlio_read_callback_t)(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s);


typedef int (*evpl_xlio_write_callback_t)(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s);

typedef void (*evpl_xlio_error_callback_t)(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s);


struct evpl_xlio_zc {
    struct evpl_xlio_buffer *buffer;
    unsigned int             length;
    int                      complete;
    struct evpl_xlio_zc     *next;
};

struct evpl_xlio_socket {
    struct evpl               *evpl;

    evpl_xlio_read_callback_t  read_callback;
    evpl_xlio_write_callback_t write_callback;

    struct ibv_pd             *pd;
    int                        pd_index;

    int                        readable;
    int                        writable;
    int                        write_interest;
    int                        active;
    int                        closed;

    uint64_t                   zc_pending;

    xlio_socket_t              socket;

    int                        listen;
    int                        connected;
};

struct evpl_xlio {
    struct xlio_api_t        *extra;
    struct evpl_xlio_api     *api;
    struct evpl_poll         *poll;
    xlio_poll_group_t         poll_group;
    struct evpl_xlio_socket **active_sockets;
    struct evpl_xlio_buffer  *free_xlio_buffers;
    struct evpl_xlio_zc      *free_zc;
    int                       num_active_sockets;
    int                       max_active_sockets;
};

struct evpl_xlio_accepted_socket {
    xlio_socket_t socket;
};

static inline void
evpl_xlio_buffer_free(
    struct evpl           *evpl,
    struct evpl_iovec_ref *ref)
{
    struct evpl_xlio_buffer *buffer = container_of(ref, struct evpl_xlio_buffer, ref);
    struct evpl_xlio        *xlio = buffer->xlio;
    struct xlio_buf         *buf  = buffer->buf;

    xlio->extra->xlio_poll_group_buf_free(xlio->poll_group, buf);

    LL_PREPEND(xlio->free_xlio_buffers, buffer);
} // evpl_xlio_buffer_free

static inline struct evpl_xlio_zc *
evpl_xlio_alloc_zc(struct evpl_xlio *xlio)
{
    struct evpl_xlio_zc *zc;

    if (xlio->free_zc) {
        zc = xlio->free_zc;
        LL_DELETE(xlio->free_zc, zc);
    } else {
        zc = evpl_zalloc(sizeof(*zc));
    }
    return zc;
} // evpl_xlio_alloc_zc

static inline void
evpl_xlio_free_zc(
    struct evpl_xlio    *xlio,
    struct evpl_xlio_zc *zc)
{
    LL_PREPEND(xlio->free_zc, zc);
} // evpl_xlio_free_zc

static inline struct evpl_xlio_buffer *
evpl_xlio_buffer_alloc(
    struct evpl      *evpl,
    struct evpl_xlio *xlio,
    void             *data,
    int               len,
    struct xlio_buf  *buff)
{
    struct evpl_xlio_buffer *buffer;

    buffer = xlio->free_xlio_buffers;

    if (buffer) {
        LL_DELETE(xlio->free_xlio_buffers, buffer);
    } else {
        buffer = evpl_zalloc(sizeof(*buffer));

        buffer->ref.release = evpl_xlio_buffer_free;
        buffer->xlio        = xlio;
    }
    buffer->buf        = buff;
    buffer->ref.refcnt = 1;
    buffer->ref.slab   = NULL;

    return buffer;
} // evpl_xlio_buffer_alloc

static void
evpl_xlio_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_xlio        *xlio;
    struct evpl_xlio_socket *s = evpl_bind_private(bind);

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    if (s->socket) {

        /* XXX libxlio seems not to handle case where we tear down a socket
         * that has actie zero-copy sends
         */
        while (s->zc_pending) {
            xlio->extra->xlio_poll_group_poll(xlio->poll_group);
        }

        xlio->extra->xlio_socket_destroy(s->socket);

#if 0
        while (!s->closed) {
            evpl_xlio_debug("Waiting for socket to close");
            xlio->extra->xlio_poll_group_poll(xlio->poll_group);
        }
#endif // if 0

        s->socket = 0;
    }
} /* evpl_xlio_pending_close */

static void
evpl_xlio_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    /* nothing more to do */
} /* evpl_xlio_close */

static inline void
evpl_xlio_socket_check_active(
    struct evpl_xlio        *xlio,
    struct evpl_xlio_socket *s)
{

    if (s->active) {
        return;
    }

    if ((s->write_interest && s->writable) ||
        s->readable) {

        xlio->active_sockets[xlio->num_active_sockets++] = s;

        s->active = 1;

    }

} // evpl_xlio_socket_check_active

static inline void
evpl_xlio_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_xlio        *xlio;
    struct evpl_xlio_socket *s = evpl_bind_private(bind);

    s->write_interest = 1;

    xlio = evpl_framework_private(evpl, EVPL_FRAMEWORK_XLIO);

    evpl_xlio_socket_check_active(xlio, s);

} /* evpl_xlio_udp_flush */


static inline void
evpl_xlio_send_completion(
    struct evpl             *evpl,
    struct evpl_xlio_socket *s,
    int                      length)
{
    struct evpl_bind  *bind = evpl_private2bind(s);
    struct evpl_notify notify;
    int                msg_sent = 0;


    if (bind->segment_callback) {
        struct evpl_dgram *dgram = evpl_dgram_ring_tail(&bind->dgram_send);

        if (dgram) {
            --dgram->niov;

            if (dgram->niov == 0) {
                msg_sent++;
                evpl_dgram_ring_remove(&bind->dgram_send);
            }
        }
    }

    if (bind->flags & EVPL_BIND_SENT_NOTIFY) {

        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = length;
        notify.sent.msgs     = msg_sent;

        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }
} /* evpl_xlio_send_completion */

void
evpl_xlio_socket_init(
    struct evpl               *evpl,
    struct evpl_xlio          *xlio,
    struct evpl_xlio_socket   *s,
    int                        listen,
    int                        connected,
    evpl_xlio_read_callback_t  read_callback,
    evpl_xlio_write_callback_t write_callback);
