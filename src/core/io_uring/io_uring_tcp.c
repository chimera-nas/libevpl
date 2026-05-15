// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE

#include <alloca.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/tcp.h> // For TCP_NODELAY
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>

#include "core/bind.h"
#include "core/io_uring/io_uring.h"
#include "core/io_uring/io_uring_internal.h"

struct evpl_io_uring_socket {
    int                           fd;
    int                           direct_fd_idx; /* -1 if not registered */
    int                           zcrx_enabled;  /* recv via IORING_OP_RECV_ZC */
    uint32_t                      send_group_id;
    struct evpl_io_uring_request *recv_req;
    struct evpl_io_uring_request *accept_req;
    int                           reqs_inflight;
    int                           send_ring_mask;
    struct io_uring_buf_ring     *send_ring;
    uint64_t                      send_ring_empty;
    struct evpl_iovec             send_ring_iov[64];

};

struct evpl_io_uring_accepted_socket {
    int fd;
};

static inline int
evpl_io_uring_alloc_direct_fd(
    struct evpl_io_uring_context *ctx,
    int                           fd)
{
    int idx;
    int rc;

    if (!ctx->effective.fixed_file || ctx->direct_fd_free_top == 0) {
        return -1;
    }

#ifdef HAVE_IO_URING_REGISTER_FILES_UPDATE
    idx = ctx->direct_fd_free[--ctx->direct_fd_free_top];

    rc = io_uring_register_files_update(&ctx->ring, idx, &fd, 1);

    if (rc < 0) {
        evpl_io_uring_error(
            "io_uring_register_files_update(idx=%d, fd=%d) failed: %s",
            idx, fd, strerror(-rc));
        ctx->direct_fd_free[ctx->direct_fd_free_top++] = idx;
        return -1;
    }

    ctx->direct_fd_slot[idx] = fd;
    return idx;
#else  /* ifdef HAVE_IO_URING_REGISTER_FILES_UPDATE */
    (void) idx; (void) rc; (void) fd;
    return -1;
#endif /* ifdef HAVE_IO_URING_REGISTER_FILES_UPDATE */
} /* evpl_io_uring_alloc_direct_fd */

static inline void
evpl_io_uring_free_direct_fd(
    struct evpl_io_uring_context *ctx,
    int                           idx)
{
#ifdef HAVE_IO_URING_REGISTER_FILES_UPDATE
    int sentinel = -1;
    if (idx < 0 || (unsigned) idx >= ctx->direct_fd_count) {
        return;
    }
    io_uring_register_files_update(&ctx->ring, idx, &sentinel, 1);
    ctx->direct_fd_slot[idx]                       = -1;
    ctx->direct_fd_free[ctx->direct_fd_free_top++] = idx;
#else  /* ifdef HAVE_IO_URING_REGISTER_FILES_UPDATE */
    (void) ctx; (void) idx;
#endif /* ifdef HAVE_IO_URING_REGISTER_FILES_UPDATE */
} /* evpl_io_uring_free_direct_fd */

static inline void
evpl_io_uring_set_sqe_fd(
    struct evpl_io_uring_context *ctx,
    struct io_uring_sqe          *sqe,
    struct evpl_io_uring_socket  *s)
{
    if (s->direct_fd_idx >= 0) {
        sqe->fd     = s->direct_fd_idx;
        sqe->flags |= IOSQE_FIXED_FILE;
    } else {
        sqe->fd = s->fd;
    }
    (void) ctx;
} /* evpl_io_uring_set_sqe_fd */

#define evpl_event_io_uring_socket(eventp) container_of((eventp), struct evpl_io_uring_socket, \
                                                        event)


static void
evpl_io_uring_tcp_recv_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req);


static inline void
evpl_io_uring_pump(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx,
    struct evpl_io_uring_socket  *s);

static inline void
evpl_io_uring_post_multishot_recv(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx,
    struct evpl_io_uring_socket  *s)
{
    struct evpl_io_uring_request *req;
    struct io_uring_sqe          *sqe;

    while (s->fd >= 0 && !s->recv_req) {

        req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

        req->callback = evpl_io_uring_tcp_recv_callback;

        req->tcp.socket = s;
        sqe             = io_uring_get_sqe(&ctx->ring);

#ifdef HAVE_IO_URING_ZCRX
        if (s->zcrx_enabled && ctx->zcrx) {
            io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, s->fd, NULL, 0, 0);
            sqe->zcrx_ifq_idx = ctx->zcrx->zcrx_id;
            sqe->ioprio      |= IORING_RECV_MULTISHOT;
            evpl_io_uring_set_sqe_fd(ctx, sqe, s);
        } else
#endif /* ifdef HAVE_IO_URING_ZCRX */
        {
            io_uring_prep_recv_multishot(sqe, s->fd, NULL, 0, 0);

            sqe->buf_group = EVPL_IO_URING_BUFGROUP_ID;
            sqe->flags    |= IOSQE_BUFFER_SELECT;
#ifdef HAVE_IO_URING_RECVSEND_BUNDLE
            if (ctx->effective.recv_bundle) {
                sqe->ioprio |= IORING_RECVSEND_BUNDLE;
            }
#endif /* ifdef HAVE_IO_URING_RECVSEND_BUNDLE */
            evpl_io_uring_set_sqe_fd(ctx, sqe, s);
        }
        io_uring_sqe_set_data64(sqe, (uint64_t) req);

        s->recv_req = req;

        evpl_defer(evpl, &ctx->flush);
    }
} /* evpl_io_uring_post_multishot_recv */

#ifdef HAVE_IO_URING_ZCRX
static void
evpl_io_uring_zcrx_frag_release(
    struct evpl           *evpl,
    struct evpl_iovec_ref *ref)
{
    struct evpl_io_uring_zcrx_frag  *frag = (struct evpl_io_uring_zcrx_frag *) ref;
    struct evpl_io_uring_zcrx_state *z    = frag->zcrx;
    uint32_t                         tail;

    /* Post the rqe back so the kernel can reuse the buffer. */
    tail = atomic_load_explicit((_Atomic uint32_t *) z->rq_ktail,
                                memory_order_relaxed);
    z->rq_rqes[tail & z->rq_mask].off = frag->area_off;
    z->rq_rqes[tail & z->rq_mask].len = frag->length;
    atomic_store_explicit((_Atomic uint32_t *) z->rq_ktail, tail + 1,
                          memory_order_release);

    /* Return the frag to the freelist. */
    frag->next    = z->free_frags;
    z->free_frags = frag;
    (void) evpl;
} /* evpl_io_uring_zcrx_frag_release */

static inline struct evpl_io_uring_zcrx_frag *
evpl_io_uring_zcrx_frag_alloc(struct evpl_io_uring_zcrx_state *z)
{
    struct evpl_io_uring_zcrx_frag *frag;

    if (z->free_frags) {
        frag          = z->free_frags;
        z->free_frags = frag->next;
        memset(frag, 0, sizeof(*frag));
    } else {
        frag = evpl_zalloc(sizeof(*frag));
    }
    return frag;
} /* evpl_io_uring_zcrx_frag_alloc */
#endif /* HAVE_IO_URING_ZCRX */

static inline void
evpl_io_uring_recv_deliver(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_iovec *iov;
    struct evpl_notify notify;
    uint64_t           length;
    int                niov;

    if (bind->segment_callback) {
        iov = alloca(sizeof(struct evpl_iovec) *
                     evpl_shared->config->max_num_iovec);

        while (1) {
            length = bind->segment_callback(evpl, bind, bind->private_data);

            if (length == 0 ||
                evpl_iovec_ring_bytes(&bind->iovec_recv) < length) {
                break;
            }

            if (unlikely(length < 0)) {
                evpl_close(evpl, bind);
                return;
            }

            niov = evpl_iovec_ring_copyv(evpl, iov, &bind->iovec_recv, length);

            notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
            notify.recv_msg.iovec  = iov;
            notify.recv_msg.niov   = niov;
            notify.recv_msg.length = length;
            notify.recv_msg.addr   = bind->remote;

            bind->notify_callback(evpl, bind, &notify, bind->private_data);
        }
    } else {
        notify.notify_type   = EVPL_NOTIFY_RECV_DATA;
        notify.notify_status = 0;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }
} /* evpl_io_uring_recv_deliver */

static void
evpl_io_uring_tcp_recv_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl,
                                                               EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket  *s = req->tcp.socket;
    struct evpl_bind             *bind;
    int                           more   = !!(req->flags & IORING_CQE_F_MORE);
    int                           buffer = !!(req->flags & IORING_CQE_F_BUFFER);

    /* Socket was detached by evpl_io_uring_close — bind is gone. */
    if (!s) {
        return;
    }

    bind = evpl_private2bind(s);

    if (unlikely(!more)) {
        s->recv_req = NULL;
        evpl_io_uring_error("recv_req finished res %d", req->res);
    }

    if (req->res <= 0) {
        evpl_io_uring_error("recv_req status res %d", req->res);
        if (req->res == -105 || req->res == -125) {
            return;
        }
        evpl_close(evpl, bind);
        return;
    }

#ifdef HAVE_IO_URING_ZCRX
    if (s->zcrx_enabled && ctx->zcrx) {
        struct evpl_io_uring_zcrx_frag *frag;
        struct evpl_iovec               iov;
        uint64_t                        off_raw = req->cqe_extra[0];
        uint64_t                        area_off;

        area_off = off_raw & ~IORING_ZCRX_AREA_MASK; /* low bits = offset in area */

        frag              = evpl_io_uring_zcrx_frag_alloc(ctx->zcrx);
        frag->zcrx        = ctx->zcrx;
        frag->area_off    = area_off;
        frag->length      = (uint32_t) req->res;
        frag->ref.refcnt  = 1;
        frag->ref.flags   = 0;
        frag->ref.slab    = NULL;
        frag->ref.release = evpl_io_uring_zcrx_frag_release;

        iov.data   = (char *) ctx->zcrx->area + area_off;
        iov.length = req->res;
        iov.pad    = 0;
        iov.ref    = &frag->ref;

        evpl_iovec_ring_append(evpl, &bind->iovec_recv, &iov, req->res);

        evpl_io_uring_recv_deliver(evpl, bind);
        return;
    }
#endif /* ifdef HAVE_IO_URING_ZCRX */

    if (buffer) {
        int                starting_id;
        int                remaining;
        int                buf_size;
        struct evpl_iovec *iov;

        starting_id = req->flags >> IORING_CQE_BUFFER_SHIFT;
        remaining   = req->res;
        buf_size    = ctx->recv_buffer_size;

#ifdef HAVE_IO_URING_RECVSEND_BUNDLE
        if (ctx->effective.recv_bundle) {
            int id = starting_id;
            while (remaining > 0) {
                int chunk = remaining > buf_size ? buf_size : remaining;
                iov         = &ctx->recv_ring_iov[id];
                iov->length = chunk;
                evpl_iovec_ring_append(evpl, &bind->iovec_recv, iov, chunk);
                ctx->recv_ring_iov_empty[id >> 6] |= (1ULL << (id & 63));
                remaining                         -= chunk;
                id                                 = (id + 1) & ctx->recv_ring_mask;
            }
        } else
#endif /* ifdef HAVE_IO_URING_RECVSEND_BUNDLE */
        {
            iov         = &ctx->recv_ring_iov[starting_id];
            iov->length = remaining;
            evpl_iovec_ring_append(evpl, &bind->iovec_recv, iov, remaining);
            ctx->recv_ring_iov_empty[starting_id >> 6] |=
                (1ULL << (starting_id & 63));
        }

        evpl_io_uring_recv_deliver(evpl, bind);
    }

} /* evpl_io_uring_tcp_recv_callback */

static void
evpl_io_uring_tcp_send_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl,
                                                               EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket  *s = req->tcp.socket;
    struct evpl_bind             *bind;
    struct evpl_notify            notify;
    int                           is_notif = !!(req->flags & IORING_CQE_F_NOTIF);
    int                           bytes;

    if (!s) {
        /* socket detached during close */
        if (req->tcp.is_send_zc && !is_notif) {
            return; /* wait for F_NOTIF */
        }
        if (req->tcp.use_fixed_buf || req->tcp.is_send_zc) {
            evpl_iovec_release(evpl, &req->tcp.send_iov);
        }
        return;
    }

    bind = evpl_private2bind(s);

    /* SEND_ZC emits two CQEs: first with res=bytes (and F_MORE set if a
     * notification will follow), second with F_NOTIF when the kernel is
     * done with the buffer. Release the iovec / advance state only on the
     * F_NOTIF CQE for zero-copy; on the first CQE we just emit NOTIFY_SENT.
     */

    if (req->tcp.is_send_zc && !is_notif) {
        /* First CQE for SEND_ZC: send result. */
        if (req->res < 0) {
            evpl_io_uring_error("send_zc first CQE error res %d", req->res);
        }

        req->tcp.sent_bytes = (req->res > 0) ? (uint32_t) req->res : 0;

        if (req->res > 0 && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {
            notify.notify_type   = EVPL_NOTIFY_SENT;
            notify.notify_status = 0;
            notify.sent.bytes    = req->res;
            notify.sent.msgs     = req->tcp.msgs_sent;
            bind->notify_callback(evpl, bind, &notify, bind->private_data);
        }

        /* Do not release iovec yet; do not free req. */
        return;
    }

    /* Single-CQE (legacy send) OR F_NOTIF (SEND_ZC notif) — finalize. */

    if (req->tcp.is_send_zc) {
        bytes = req->tcp.sent_bytes;
        evpl_iovec_release(evpl, &req->tcp.send_iov);
    } else {
        if (req->res < 0) {
            evpl_io_uring_error("send_req status res %d", req->res);
        }

        if (req->tcp.use_fixed_buf) {
            /* FIXED_BUF non-ZC: iov stored on req */
            evpl_iovec_release(evpl, &req->tcp.send_iov);
        } else {
            /* Legacy provided-buffer send ring */
            unsigned int buffer_id = req->tcp.send_buffer_id;
            evpl_iovec_release(evpl, &s->send_ring_iov[buffer_id]);
            s->send_ring_empty |= (1ULL << buffer_id);
        }
        bytes = req->res;

        if (req->res > 0 && (bind->flags & EVPL_BIND_SENT_NOTIFY)) {
            notify.notify_type   = EVPL_NOTIFY_SENT;
            notify.notify_status = 0;
            notify.sent.bytes    = req->res;
            notify.sent.msgs     = req->tcp.msgs_sent;
            bind->notify_callback(evpl, bind, &notify, bind->private_data);
        }
    }

    s->reqs_inflight--;

    evpl_io_uring_pump(evpl, ctx, s);

    if (s->reqs_inflight == 0) {
        if (bind->flags & EVPL_BIND_FINISH) {
            evpl_close(evpl, bind);
        }
    }

    if (bytes <= 0) {
        evpl_close(evpl, bind);
        return;
    }

} /* evpl_io_uring_tcp_send_callback */

static inline void
evpl_io_uring_pump(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx,
    struct evpl_io_uring_socket  *s)
{
    struct evpl_bind             *bind = evpl_private2bind(s);
    struct io_uring_sqe          *sqe;
    struct evpl_io_uring_request *req;
    int                           offset = 0, i;
    struct evpl_iovec            *tail_iov;
    unsigned int                  buf_index;
    uint64_t                      buf_offset;
    int                           use_fixed_buf;
    int                           use_send_zc;

    /* Make sure any slabs that became globally registered since our last
     * sync are pushed into this ring's buffer table before we issue any
     * FIXED_BUF send.
     */
    if (ctx->effective.fixed_buf) {
        evpl_io_uring_sync_registered_buffers(ctx);
    }

    while (!evpl_iovec_ring_is_empty(&bind->iovec_send)) {

        tail_iov = evpl_iovec_ring_tail(&bind->iovec_send);

        use_fixed_buf = 0;
        use_send_zc   = 0;
        buf_index     = 0;
        buf_offset    = 0;

#ifdef HAVE_IO_URING_RECVSEND_FIXED_BUF
        if (ctx->effective.fixed_buf) {
            use_fixed_buf = evpl_io_uring_iov_to_fixed(tail_iov, &buf_index,
                                                       &buf_offset);
            /* Only eligible if the buf_index is below our high water — i.e.
             * we've already pushed this slab into the per-ring table.
             */
            if (use_fixed_buf && buf_index >= ctx->buf_high_water) {
                use_fixed_buf = 0;
            }
            if (use_fixed_buf && ctx->effective.send_zc) {
                use_send_zc = 1;
            }
        }
#endif /* ifdef HAVE_IO_URING_RECVSEND_FIXED_BUF */

        if (!use_fixed_buf) {
            /* Legacy provided-buffer-ring path needs a free slot. */
            i = __builtin_ffsll(s->send_ring_empty);

            if (i == 0) {
                evpl_io_uring_debug("send ring empty, cannot send");
                break;
            }

            i--;
        } else {
            i = -1;
        }

        req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

        req->callback           = evpl_io_uring_tcp_send_callback;
        req->tcp.socket         = s;
        req->tcp.msgs_sent      = 0;
        req->tcp.is_send_zc     = use_send_zc ? 1 : 0;
        req->tcp.use_fixed_buf  = use_fixed_buf ? 1 : 0;
        req->tcp.sent_bytes     = 0;
        req->tcp.send_buffer_id = (uint16_t) i;

        /* Snapshot data/length before evpl_iovec_move() which invalidates
         * tail_iov->data.
         */
        void        *send_data = tail_iov->data;
        unsigned int send_len  = tail_iov->length;

        if (use_fixed_buf) {
            evpl_iovec_move(&req->tcp.send_iov, tail_iov);
        } else {
            evpl_iovec_move(&s->send_ring_iov[i], tail_iov);
            s->send_ring_empty &= ~(1ULL << i);
        }

        if (bind->segment_callback) {
            struct evpl_dgram *dgram = evpl_dgram_ring_tail(&bind->dgram_send);

            if (dgram) {

                dgram->niov--;

                if (dgram->niov == 0) {
                    req->tcp.msgs_sent++;
                    evpl_dgram_ring_remove(&bind->dgram_send);
                }
            }
        }

        sqe = io_uring_get_sqe(&ctx->ring);

        evpl_io_uring_abort_if(!sqe, "io_uring_get_sqe returned NULL");

#ifdef HAVE_IO_URING_RECVSEND_FIXED_BUF
        if (use_send_zc) {
#ifdef HAVE_IO_URING_PREP_SEND_ZC
            io_uring_prep_send_zc(sqe, 0, send_data, send_len,
                                  MSG_WAITALL, 0);
            evpl_io_uring_set_sqe_fd(ctx, sqe, s);
            sqe->ioprio   |= IORING_RECVSEND_FIXED_BUF;
            sqe->buf_index = buf_index;
#endif /* ifdef HAVE_IO_URING_PREP_SEND_ZC */
        } else if (use_fixed_buf) {
            io_uring_prep_send(sqe, 0, send_data, send_len, MSG_WAITALL);
            evpl_io_uring_set_sqe_fd(ctx, sqe, s);
            sqe->ioprio   |= IORING_RECVSEND_FIXED_BUF;
            sqe->buf_index = buf_index;
        } else
#endif /* ifdef HAVE_IO_URING_RECVSEND_FIXED_BUF */
        {
            io_uring_buf_ring_add(
                s->send_ring,
                evpl_iovec_data(&s->send_ring_iov[i]),
                evpl_iovec_length(&s->send_ring_iov[i]),
                i,
                s->send_ring_mask,
                offset);

            offset++;

            io_uring_prep_send(sqe, 0, NULL, 0, MSG_WAITALL);
            evpl_io_uring_set_sqe_fd(ctx, sqe, s);

            sqe->flags    |= IOSQE_BUFFER_SELECT;
            sqe->buf_group = s->send_group_id;
            (void) send_data; (void) send_len;
        }

        io_uring_sqe_set_data64(sqe, (uint64_t) req);
        (void) buf_offset;

        evpl_iovec_ring_remove(&bind->iovec_send);

        s->reqs_inflight++;
    }

    if (!ctx->effective.fixed_buf && offset > 0) {
        io_uring_buf_ring_advance(s->send_ring, offset);
    }

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_pump */

static inline void
evpl_io_uring_setup_socket(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx,
    struct evpl_io_uring_socket  *s,
    int                           listen)
{
    int flags, rc, yes = 1, n;

    n = evpl_io_uring_fill_recv_ring(evpl, ctx);

    if (n) {
        io_uring_buf_ring_advance(ctx->recv_ring, n);
    }

    s->send_group_id = ctx->next_send_group_id++;

    s->direct_fd_idx = -1;
    s->zcrx_enabled  = 0;
    s->recv_req      = NULL;
    s->accept_req    = NULL;
    s->reqs_inflight = 0;

    s->send_ring_empty = UINT64_MAX;

    flags = fcntl(s->fd, F_GETFL, 0);

    evpl_io_uring_abort_if(flags < 0, "Failed to get socket flags: %s",
                           strerror(errno));

    rc = fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);

    evpl_io_uring_abort_if(rc < 0, "Failed to set socket flags: %s",
                           strerror(errno));

    if (ctx->effective.fixed_file) {
        s->direct_fd_idx = evpl_io_uring_alloc_direct_fd(ctx, s->fd);
    }

    if (!listen) {
        rc = setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

        evpl_io_uring_abort_if(rc, "Failed to set TCP_NODELAY on socket");

#ifdef HAVE_IO_URING_ZCRX
        if (ctx->effective.zcrx && ctx->zcrx) {
            int       napi_id;
            socklen_t napi_len = sizeof(napi_id);
            if (getsockopt(s->fd, SOL_SOCKET, SO_INCOMING_NAPI_ID, &napi_id,
                           &napi_len) == 0 && napi_id != 0) {
                if (ctx->zcrx->napi_id == 0) {
                    ctx->zcrx->napi_id = (uint32_t) napi_id;
                }
                if ((uint32_t) napi_id == ctx->zcrx->napi_id) {
                    s->zcrx_enabled = 1;
                } else {
                    evpl_io_uring_info(
                        "socket NAPI id %d does not match zcrx ifq (%u); "
                        "this socket will use non-ZC recv",
                        napi_id, ctx->zcrx->napi_id);
                }
            }
        }
#endif /* ifdef HAVE_IO_URING_ZCRX */

        evpl_io_uring_post_multishot_recv(evpl, ctx, s);
    }

    /* Always set up the per-socket send_ring; it is the fallback path when
     * an iov is not eligible for FIXED_BUF (e.g. when its slab has not yet
     * been pushed into our ring's registered-buffer table).
     */
    s->send_ring = io_uring_setup_buf_ring(&ctx->ring, 64,
                                           s->send_group_id, 0, &rc);
    s->send_ring_mask = io_uring_buf_ring_mask(64);
    evpl_io_uring_abort_if(rc, "Failed to setup send ring");

} /* evpl_io_uring_setup_socket */

static void
evpl_io_uring_tcp_connect_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_io_uring_context *ctx  = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket  *s    = req->tcp.socket;
    struct evpl_bind             *bind = evpl_private2bind(s);
    struct evpl_notify            notify;

    if (req->res < 0) {
        evpl_close(evpl, bind);
        return;
    }

    notify.notify_type   = EVPL_NOTIFY_CONNECTED;
    notify.notify_status = 0;
    bind->notify_callback(evpl, bind, &notify, bind->private_data);

    evpl_io_uring_pump(evpl, ctx, s);
} /* evpl_io_uring_tcp_connect_callback */

static void
evpl_io_uring_tcp_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct io_uring_sqe          *sqe = io_uring_get_sqe(&ctx->ring);
    struct evpl_io_uring_socket  *s   = evpl_bind_private(bind);
    struct evpl_io_uring_request *req;

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

    req->tcp.socket = s;
    req->callback   = evpl_io_uring_tcp_connect_callback;

    s->fd = socket(bind->remote->addr->sa_family, SOCK_STREAM, 0);

    evpl_io_uring_abort_if(s->fd < 0, "Failed to create tcp socket: %s", strerror(
                               errno));

    evpl_io_uring_setup_socket(evpl, ctx, s, 0);

    io_uring_prep_connect(sqe, s->fd, (struct sockaddr *) bind->remote->addr, bind->remote->addrlen);

    io_uring_sqe_set_data(sqe, req);

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_tcp_connect */

static void
evpl_io_uring_tcp_close_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
} /* evpl_io_uring_tcp_close_callback */

static void
evpl_io_uring_tcp_cancel_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_io_uring_socket  *s   = req->tcp.socket;
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *close_req;
    struct io_uring_sqe          *sqe;

    close_req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

    sqe = io_uring_get_sqe(&ctx->ring);

    close_req->tcp.socket = s;
    close_req->callback   = evpl_io_uring_tcp_close_callback;

    io_uring_prep_close(sqe, s->fd);

    io_uring_sqe_set_data(sqe, close_req);

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_tcp_close */


static void
evpl_io_uring_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_io_uring_socket  *s   = evpl_bind_private(bind);
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *req;
    struct io_uring_sqe          *sqe;

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

    sqe = io_uring_get_sqe(&ctx->ring);

    req->tcp.socket = s;
    req->callback   = evpl_io_uring_tcp_cancel_callback;

    io_uring_prep_cancel_fd(sqe, s->fd, IORING_ASYNC_CANCEL_ALL);

    io_uring_sqe_set_data(sqe, req);

    evpl_defer(evpl, &ctx->flush);
} /* evpl_io_uring_tcp_close */

static void
evpl_io_uring_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket  *s   = evpl_bind_private(bind);

    /* Detach in-flight multishot recv/accept requests from this socket so
     * that any final CQE that arrives after the bind is destroyed sees a
     * NULL socket pointer and bails out cleanly. The request will be
     * reclaimed by the destroy-time drain or by its own final CQE.
     */
    if (s->recv_req) {
        s->recv_req->tcp.socket = NULL;
        s->recv_req             = NULL;
    }

    if (s->accept_req) {
        s->accept_req->tcp.socket = NULL;
        s->accept_req             = NULL;
    }

    if (s->direct_fd_idx >= 0) {
        evpl_io_uring_free_direct_fd(ctx, s->direct_fd_idx);
        s->direct_fd_idx = -1;
    }
} /* evpl_io_uring_tcp_close */


static void
evpl_io_uring_tcp_accept_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_io_uring_socket          *ls = req->tcp.socket;
    struct evpl_bind                     *listen_bind;
    struct evpl_address                  *remote_addr;
    struct evpl_io_uring_accepted_socket *accepted_socket;
    int                                   more = !!(req->flags & IORING_CQE_F_MORE);

    /* Socket was detached by evpl_io_uring_close — listen bind is gone. */
    if (!ls) {
        return;
    }

    listen_bind = evpl_private2bind(ls);

    if (unlikely(!more)) {
        ls->accept_req = NULL;
    }

    if (req->res < 0) {
        return;
    }

    remote_addr = evpl_address_alloc();

    remote_addr->addrlen = sizeof(remote_addr->sa);

    accepted_socket = evpl_zalloc(sizeof(*accepted_socket));

    accepted_socket->fd = req->res;

    listen_bind->accept_callback(evpl, listen_bind, remote_addr, accepted_socket, listen_bind->private_data);

} /* evpl_accept_tcp */

static void
evpl_io_uring_tcp_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind)
{
    struct evpl_io_uring_socket  *s   = evpl_bind_private(listen_bind);
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *req;
    struct io_uring_sqe          *sqe;
    int                           rc;
    const int                     yes = 1;

    s->fd = socket(listen_bind->local->addr->sa_family, SOCK_STREAM, 0);

    evpl_io_uring_abort_if(s->fd < 0, "Failed to create tcp listen socket: %s",
                           strerror(errno));

    rc = setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    evpl_io_uring_abort_if(rc < 0, "Failed to set socket options: %s", strerror(
                               errno));

    rc = bind(s->fd, listen_bind->local->addr, listen_bind->local->addrlen);

    evpl_io_uring_abort_if(rc < 0, "Failed to bind listen socket: %s", strerror(
                               errno));

    evpl_io_uring_setup_socket(evpl, ctx, s, 1);

    rc = listen(s->fd, evpl_shared->config->max_pending);

    evpl_io_uring_fatal_if(rc, "Failed to listen on listener fd");

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

    req->callback   = evpl_io_uring_tcp_accept_callback;
    req->tcp.socket = s;
    sqe             = io_uring_get_sqe(&ctx->ring);

    io_uring_prep_multishot_accept(sqe, s->fd, NULL, 0, 0);

    io_uring_sqe_set_data64(sqe, (uint64_t) req);

    s->accept_req = req;

    evpl_defer(evpl, &ctx->flush);

} /* evpl_io_uring_tcp_listen */

static void
evpl_io_uring_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    struct evpl_io_uring_context         *ctx             = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket          *s               = evpl_bind_private(bind);
    struct evpl_io_uring_accepted_socket *accepted_socket = accepted;
    struct evpl_notify                    notify;
    struct sockaddr_storage               ss;
    socklen_t                             sslen = sizeof(ss);
    int                                   rc;

    s->fd = accepted_socket->fd;

    evpl_free(accepted_socket);

    rc = getsockname(s->fd, (struct sockaddr *) &ss, &sslen);

    evpl_io_uring_abort_if(rc < 0, "getsockname failed: %s", strerror(errno));

    bind->local          = evpl_address_alloc();
    bind->local->addrlen = sslen;
    memcpy(bind->local->addr, &ss, sslen);

    evpl_io_uring_setup_socket(evpl, ctx, s, 0);

    notify.notify_type   = EVPL_NOTIFY_CONNECTED;
    notify.notify_status = 0;
    bind->notify_callback(evpl, bind, &notify, bind->private_data);

    evpl_io_uring_pump(evpl, ctx, s);
} /* evpl_io_uring_tcp_attach */

static void
evpl_io_uring_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket  *s   = evpl_bind_private(bind);

    evpl_io_uring_pump(evpl, ctx, s);
} /* evpl_io_uring_tcp_flush */

struct evpl_protocol evpl_io_uring_tcp = {
    .id            = EVPL_STREAM_IO_URING_TCP,
    .connected     = 1,
    .stream        = 1,
    .name          = "STREAM_IO_URING_TCP",
    .framework     = &evpl_framework_io_uring,
    .connect       = evpl_io_uring_tcp_connect,
    .pending_close = evpl_io_uring_pending_close,
    .close         = evpl_io_uring_close,
    .listen        = evpl_io_uring_tcp_listen,
    .attach        = evpl_io_uring_attach,
    .flush         = evpl_io_uring_flush,
};
