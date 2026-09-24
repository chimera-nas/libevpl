#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif /* ifndef _GNU_SOURCE */
#include "core/os.h"
// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only




#include <sys/types.h>



#include <errno.h>
#include <fcntl.h>


#include "core/bind.h"
#include "core/io_uring/io_uring.h"
#include "core/io_uring/io_uring_internal.h"

struct evpl_io_uring_socket {
    int                              fd;
    struct evpl_io_uring_request    *recv_req;
    struct evpl_io_uring_request    *accept_req;
    int                              reqs_inflight;
    int                              direct_fd_idx; /* -1 if not registered */
    int                              zcrx_enabled;
    #ifdef HAVE_IO_URING_ZCRX
    struct evpl_io_uring_zcrx_state *zcrx; /* the ifq this socket receives on */
    #endif /* ifdef HAVE_IO_URING_ZCRX */  /* recv via IORING_OP_RECV_ZC */

    /* Scratch for a coalesced send.  Only one send is in flight per socket
     * (reqs_inflight gates it), so one array per socket suffices, and it has to
     * outlive the submission because the kernel reads it on completion. */
    struct iovec                    *send_iov;
    struct msghdr                    send_msg;
};

struct evpl_io_uring_accepted_socket {
    int fd;
};

#define evpl_event_io_uring_socket(eventp) container_of((eventp), struct evpl_io_uring_socket, \
                                                        event)

/*
 * Registered (direct) descriptors.  Handing the kernel a table index instead of
 * a file descriptor saves the per-operation fget/fput on the ring's fast path.
 * The socket keeps its ordinary fd open as well, so any path that has not been
 * converted keeps working unchanged.
 */
static inline int
evpl_io_uring_alloc_direct_fd(
    struct evpl_io_uring_context *ctx,
    int                           fd)
{
#ifdef HAVE_IO_URING_REGISTER_FILES_UPDATE
    int idx;
    int rc;

    if (!ctx->effective.fixed_file || ctx->direct_fd_free_top == 0) {
        return -1;
    }

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
    (void) ctx; (void) fd;
    return -1;
#endif /* ifdef HAVE_IO_URING_REGISTER_FILES_UPDATE */
} /* evpl_io_uring_alloc_direct_fd */

static inline void
evpl_io_uring_free_direct_fd(
    struct evpl_io_uring_context *ctx,
    int                           idx)
{
#ifdef HAVE_IO_URING_REGISTER_FILES_UPDATE
    int fd = -1;

    io_uring_register_files_update(&ctx->ring, idx, &fd, 1);

    ctx->direct_fd_slot[idx]                       = -1;
    ctx->direct_fd_free[ctx->direct_fd_free_top++] = idx;
#else  /* ifdef HAVE_IO_URING_REGISTER_FILES_UPDATE */
    (void) ctx; (void) idx;
#endif /* ifdef HAVE_IO_URING_REGISTER_FILES_UPDATE */
} /* evpl_io_uring_free_direct_fd */

static inline void
evpl_io_uring_set_sqe_fd(
    struct io_uring_sqe         *sqe,
    struct evpl_io_uring_socket *s)
{
    if (s->direct_fd_idx >= 0) {
        sqe->fd     = s->direct_fd_idx;
        sqe->flags |= IOSQE_FIXED_FILE;
    } else {
        sqe->fd = s->fd;
    }
} /* evpl_io_uring_set_sqe_fd */


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

    while (s->fd >= 0 && !(evpl_private2bind(s)->flags & EVPL_BIND_PENDING_CLOSED) && !s->recv_req) {

        req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

        req->callback = evpl_io_uring_tcp_recv_callback;

        req->tcp.socket = s;
        req->owner      = evpl_private2bind(s);
        evpl_bind_operation_begin(req->owner);
        sqe = io_uring_get_sqe(&ctx->ring);

#ifdef HAVE_IO_URING_ZCRX
        if (s->zcrx_enabled && s->zcrx) {
            /* The queue's page-pool provider belongs to our ifq, so RECV_ZC is
             * the only way to consume data that lands on it. */
            io_uring_prep_rw(IORING_OP_RECV_ZC, sqe, s->fd, NULL, 0, 0);
            sqe->zcrx_ifq_idx = s->zcrx->zcrx_id;
            sqe->ioprio      |= IORING_RECV_MULTISHOT;
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
        }

        evpl_io_uring_set_sqe_fd(sqe, s);
        io_uring_sqe_set_data64(sqe, (uint64_t) req);

        s->recv_req = req;

        evpl_defer(evpl, &ctx->flush);
    }
} /* evpl_io_uring_post_multishot_recv */

#ifdef HAVE_IO_URING_ZCRX

/*
 * A ZCRX fragment is a reference to a range of the registered area that the
 * kernel filled directly.  Releasing it hands the range back to the kernel by
 * writing an rqe at the locally cached tail; the tail itself is published once
 * per poll iteration (see evpl_io_uring_zcrx_publish_tail), so a stream of
 * released fragments costs plain stores rather than one fence apiece.
 */
static void
evpl_io_uring_zcrx_frag_release(
    struct evpl           *evpl,
    struct evpl_iovec_ref *ref)
{
    struct evpl_io_uring_zcrx_frag  *frag = (struct evpl_io_uring_zcrx_frag *) ref;
    struct evpl_io_uring_zcrx_state *z    = frag->zcrx;
    uint32_t                         pos  = z->tail_cached;

    (void) evpl;

    z->rq_rqes[pos & z->rq_mask].off = frag->area_off;
    z->rq_rqes[pos & z->rq_mask].len = frag->length;
    z->tail_cached                   = pos + 1;

    frag->next    = z->free_frags;
    z->free_frags = frag;
} /* evpl_io_uring_zcrx_frag_release */

static inline struct evpl_io_uring_zcrx_frag *
evpl_io_uring_zcrx_frag_alloc(struct evpl_io_uring_zcrx_state *z)
{
    struct evpl_io_uring_zcrx_frag *frag;

    if (z->free_frags) {
        frag          = z->free_frags;
        z->free_frags = frag->next;
    } else {
        frag = evpl_zalloc(sizeof(*frag));
    }

    return frag;
} /* evpl_io_uring_zcrx_frag_alloc */

#endif /* ifdef HAVE_IO_URING_ZCRX */

static inline void
evpl_io_uring_recv_deliver(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_iovec *iov;
    struct evpl_notify notify;
    int                length, niov;

    if (bind->segment_callback) {

        iov = alloca(sizeof(struct evpl_iovec) * evpl_shared->config->max_num_iovec);

        while (!(bind->flags & EVPL_BIND_PENDING_CLOSED)) {

            length = bind->segment_callback(evpl, bind, bind->private_data);

            /* A negative length is the segment callback's request to drop
             * the connection (an unparseable or oversized frame).  This test
             * must precede the ring-bytes comparison: that comparison
             * promotes the signed length to the unsigned type of
             * evpl_iovec_ring_bytes, so a negative value compares as huge and
             * would break out of the loop before ever reaching this check. */
            if (unlikely(length < 0)) {
                evpl_close(evpl, bind);
                return;
            }

            if (length == 0 ||
                evpl_iovec_ring_bytes(&bind->iovec_recv) < (uint64_t) length) {
                break;
            }

            niov = evpl_iovec_ring_copyv_bounded(evpl, iov,
                                                 evpl_shared->config->max_num_iovec, &bind->iovec_recv, length);
            if (niov < 0) {
                evpl_close(evpl, bind);
                return;
            }

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
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_socket  *s   = req->tcp.socket;
    int                           buffer_id;
    struct evpl_iovec            *iov;
    struct evpl_bind             *bind   = evpl_private2bind(req->tcp.socket);
    int                           more   = !!(req->flags & IORING_CQE_F_MORE);
    int                           buffer = !!(req->flags & IORING_CQE_F_BUFFER);

    if (unlikely(!more)) {
        s->recv_req = NULL;
        evpl_io_uring_error("recv_req finished res %d", req->res);
    }

    if (req->res <= 0) {
        evpl_io_uring_error("recv_req status res %d", req->res);
        if (req->res == -ENOBUFS) {
            int n = evpl_io_uring_fill_recv_ring(evpl, ctx);
            io_uring_buf_ring_advance(ctx->recv_ring, n);
            evpl_io_uring_post_multishot_recv(evpl, ctx, s);
            return;
        }
        if (req->res == -ECANCELED) {
            return;
        }
        evpl_close(evpl, bind);
        return;
    }

#ifdef HAVE_IO_URING_ZCRX
    if (s->zcrx_enabled && s->zcrx) {
        struct evpl_io_uring_zcrx_frag *frag;
        struct evpl_iovec               zc_iov;
        uint64_t                        area_off;

        /* CQE32's second half carries the offset of the filled range within the
         * registered area. The iovec references that range in place; releasing
         * it hands the range back to the kernel via an rqe. */
        area_off = req->cqe_extra[0] & ~IORING_ZCRX_AREA_MASK;

        frag              = evpl_io_uring_zcrx_frag_alloc(s->zcrx);
        frag->zcrx        = s->zcrx;
        frag->area_off    = area_off;
        frag->length      = (uint32_t) req->res;
        frag->ref.refcnt  = 1;
        frag->ref.flags   = 0;
        frag->ref.slab    = NULL;
        frag->ref.release = evpl_io_uring_zcrx_frag_release;

        zc_iov.data   = (char *) s->zcrx->area + area_off;
        zc_iov.length = req->res;
        zc_iov.pad    = 0;
        zc_iov.ref    = &frag->ref;

        s->zcrx->stat_frags++;
        s->zcrx->stat_bytes += (uint64_t) req->res;

        evpl_iovec_ring_append(evpl, &bind->iovec_recv, &zc_iov, req->res);

        evpl_io_uring_recv_deliver(evpl, bind);
    } else
#endif /* ifdef HAVE_IO_URING_ZCRX */

    if (buffer) {

        buffer_id = req->flags >> IORING_CQE_BUFFER_SHIFT;

#ifdef HAVE_IO_URING_RECVSEND_BUNDLE
        if (ctx->effective.recv_bundle) {
            int remaining = req->res;
            int id        = buffer_id;

            /* A bundled completion consumes as many consecutive provided
             * buffers as it needed, and req->res is the total across all of
             * them.  Each buffer holds at most recv_buffer_size bytes, so the
             * total has to be split back across the individual slots -- giving
             * one slot the whole length would hand the application an iovec
             * running well past the end of its buffer. */
            while (remaining > 0) {
                int chunk = remaining > ctx->recv_buffer_size ?
                    ctx->recv_buffer_size : remaining;

                iov         = &ctx->recv_ring_iov[id];
                iov->length = chunk;

                evpl_iovec_ring_append(evpl, &bind->iovec_recv, iov, chunk);

                ctx->recv_ring_iov_empty[id >> 6] |= (1ULL << (id & 63));

                remaining -= chunk;
                id         = (id + 1) & ctx->recv_ring_mask;
            }
        } else
#endif /* ifdef HAVE_IO_URING_RECVSEND_BUNDLE */
        {
            iov         = &ctx->recv_ring_iov[buffer_id];
            iov->length = req->res;

            evpl_iovec_ring_append(evpl, &bind->iovec_recv, iov, req->res);

            ctx->recv_ring_iov_empty[buffer_id >> 6] |= (1ULL << (buffer_id & 63));
        }

        evpl_io_uring_recv_deliver(evpl, bind);
    }

    if (!more) {
        evpl_io_uring_post_multishot_recv(evpl, ctx, s);
    }

} /* evpl_io_uring_tcp_recv_callback */

static inline void
evpl_io_uring_send_zc_release(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    int i;

    for (i = 0; i < req->tcp.zc_niov; i++) {
        evpl_iovec_release(evpl, &req->tcp.zc_iov[i]);
    }

    if (req->tcp.zc_iov) {
        evpl_free(req->tcp.zc_iov);
        req->tcp.zc_iov = NULL;
    }

    req->tcp.zc_niov = 0;
} /* evpl_io_uring_send_zc_release */

static void
evpl_io_uring_tcp_send_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_io_uring_context *ctx  = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_bind             *bind = evpl_private2bind(req->tcp.socket);
    struct evpl_io_uring_socket  *s    = req->tcp.socket;
    struct evpl_notify            notify;
    int                           consumed, msgs = 0;
    int                           res;

    /* A zero-copy send completes twice: first with the byte count, then with
     * IORING_CQE_F_NOTIF once the kernel has finished with the payload.  The
     * buffers cannot be recycled until that notification, so everything is
     * deferred to it -- including dropping reqs_inflight, which is what keeps
     * the pump from resubmitting data the kernel is still reading.  A failed
     * zero-copy send reports no F_MORE and never notifies, so it falls through
     * here and is handled like any other error. */
    if (req->tcp.is_send_zc) {
        if (req->flags & IORING_CQE_F_NOTIF) {
#ifdef IORING_NOTIF_USAGE_ZC_COPIED
            ctx->stat_zc_notifs++;
            if (req->res & (int) IORING_NOTIF_USAGE_ZC_COPIED) {
                ctx->stat_zc_copied++;
            }
#endif /* ifdef IORING_NOTIF_USAGE_ZC_COPIED */
            /* The kernel has stopped reading the payload; drop the references
             * this request held.  The queue advanced when the send itself
             * completed, so there is nothing else left to do. */
            evpl_io_uring_send_zc_release(evpl, req);
            return;
        }

        res = req->res;

        /* A failed zero-copy send reports no F_MORE and never notifies, so the
         * references have to go back here instead. */
        if (!(req->flags & IORING_CQE_F_MORE)) {
            evpl_io_uring_send_zc_release(evpl, req);
        }
    } else {
        res = req->res;
    }

#if defined(HAVE_IO_URING_PREP_SEND_ZC) && defined(HAVE_IO_URING_PREP_SENDMSG_ZC_FIXED)
    if (req->tcp.is_send_zc && res > 0) {
        ctx->stat_zc_bytes += (uint64_t) res;
    }
#endif /* HAVE_IO_URING_PREP_SEND_ZC && HAVE_IO_URING_PREP_SENDMSG_ZC_FIXED */

    s->reqs_inflight--;
    if (res <= 0) {
        evpl_close(evpl, bind);
        return;
    }

    /* The queue owns the buffer until completion. A short send consumes only
     * the completed prefix; its suffix stays first in line for the next SQE.
     * In particular, an error CQE has no buffer-selection index to release. */
    consumed = evpl_iovec_ring_consume(evpl, &bind->iovec_send, res);
    if (bind->segment_callback) {
        /* One completion can retire several buffers, and a message may span
         * more than one, so walk the queue rather than assuming one apiece. */
        while (consumed) {
            struct evpl_dgram *dgram = evpl_dgram_ring_tail(&bind->dgram_send);

            if (!dgram) {
                break;
            }

            if (dgram->niov > consumed) {
                dgram->niov -= consumed;
                break;
            }

            consumed -= dgram->niov;
            msgs++;
            evpl_dgram_ring_remove(&bind->dgram_send);
        }
    }
    if (bind->flags & EVPL_BIND_SENT_NOTIFY) {
        notify.notify_type   = EVPL_NOTIFY_SENT;
        notify.notify_status = 0;
        notify.sent.bytes    = res;
        notify.sent.msgs     = msgs;
        bind->notify_callback(evpl, bind, &notify, bind->private_data);
    }
    evpl_io_uring_pump(evpl, ctx, s);
    if (!s->reqs_inflight && evpl_iovec_ring_is_empty(&bind->iovec_send) &&
        (bind->flags & EVPL_BIND_FINISH)) {
        evpl_close(evpl, bind);
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
    struct evpl_iovec            *iov;
    ssize_t                       total;
    int                           niov;

    /* Serialize sends on each stream: independent SQEs need not complete in
     * submission order. Ordinary send works on the same kernels as multishot
     * receive, without the newer provided-buffer send extension. */
    if ((bind->flags & EVPL_BIND_PENDING_CLOSED) || s->reqs_inflight ||
        evpl_iovec_ring_is_empty(&bind->iovec_send)) {
        return;
    }
    iov = evpl_iovec_ring_tail(&bind->iovec_send);
    (void) iov; /* only the zero-copy path below walks the queue by iovec */

    /* Submit everything queued as one operation.  One iovec per SQE would
     * serialize the stream into a submit/complete round trip per buffer, since
     * only one send may be outstanding at a time; coalescing keeps the same
     * ordering guarantee at a fraction of the syscalls. */
    niov = evpl_iovec_ring_iov(&total, s->send_iov,
                               evpl_shared->config->max_num_iovec,
                               &bind->iovec_send);

    if (!niov) {
        return;
    }

#if defined(HAVE_IO_URING_PREP_SEND_ZC) && defined(HAVE_IO_URING_PREP_SENDMSG_ZC_FIXED)
    /* Zero-copy send.
     *
     * The payload goes to the kernel by reference, so the copy disappears --
     * and with it the page allocation and zeroing the copy forced.  It is sent
     * from this ring's registered buffer table, so the pages are pinned and
     * IOMMU-mapped once when the slab is registered rather than on every send;
     * without that, the pinning costs about what the copy did.
     *
     * A registered send addresses one slab, so a batch runs only as far as the
     * first buffer from a different slab; the rest stays queued for the next
     * round.  A short send is fine and deliberately not avoided with
     * MSG_WAITALL: asking for all of it parks the operation on POLLOUT until
     * the whole batch fits in the socket, where letting it report what it took
     * lets the queue advance by that much and resubmit the rest immediately.
     * Nothing can overtake the remainder, because only one send is ever in
     * flight.
     *
     * Such a send completes twice, and the two completions mean different
     * things.  The first says the socket has taken the data, which is what
     * fixes its place in the stream; the notification only says the kernel has
     * stopped reading our buffers.  So the queue advances and the next send
     * goes out on the first completion, and the buffers are held by this
     * request until the notification, which is free to lag behind.  Waiting on
     * the notification instead would idle the sender for a DMA round trip per
     * batch. */
    if (ctx->effective.send_zc) {
        struct evpl_iovec *first  = iov;
        int                maxiov = evpl_shared->config->max_num_iovec;
        unsigned int       group;
        uint64_t           offset;
        int                i;

        if (evpl_io_uring_iov_to_fixed(iov, &group, &offset) &&
            evpl_io_uring_ensure_buf_registered(ctx, group)) {

            niov = 0;

            while (iov && niov < maxiov) {
                unsigned int idx;

                if (!evpl_io_uring_iov_to_fixed(iov, &idx, &offset) ||
                    idx != group) {
                    break;
                }

                s->send_iov[niov].iov_base = iov->data;
                s->send_iov[niov].iov_len  = iov->length;
                niov++;

                iov = evpl_iovec_ring_next(&bind->iovec_send, iov);
            }

            req                 = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);
            req->callback       = evpl_io_uring_tcp_send_callback;
            req->tcp.socket     = s;
            req->owner          = bind;
            req->tcp.is_send_zc = 1;
            req->tcp.zc_niov    = niov;
            req->tcp.zc_iov     = evpl_zalloc(niov * sizeof(struct evpl_iovec));

            /* Hold our own reference on each buffer, so the send queue can be
             * advanced on the first completion without freeing memory the
             * kernel is still reading. */
            iov = first;
            for (i = 0; i < niov; i++) {
                evpl_iovec_clone(&req->tcp.zc_iov[i], iov);
                iov = evpl_iovec_ring_next(&bind->iovec_send, iov);
            }

            evpl_bind_operation_begin(bind);

            sqe = io_uring_get_sqe(&ctx->ring);
            evpl_io_uring_abort_if(!sqe, "io_uring_get_sqe returned NULL");

            memset(&s->send_msg, 0, sizeof(s->send_msg));
            s->send_msg.msg_iov    = s->send_iov;
            s->send_msg.msg_iovlen = niov;

            io_uring_prep_sendmsg_zc_fixed(sqe, s->fd, &s->send_msg,
                                           MSG_NOSIGNAL, group);
#ifdef IORING_SEND_ZC_REPORT_USAGE
            /* Have the notification tell us whether the kernel really sent
             * from our pages or quietly fell back to copying them. */
            sqe->ioprio |= IORING_SEND_ZC_REPORT_USAGE;
#endif /* ifdef IORING_SEND_ZC_REPORT_USAGE */
            evpl_io_uring_set_sqe_fd(sqe, s);
            io_uring_sqe_set_data(sqe, req);

            ctx->stat_zc_sends++;
            ctx->stat_zc_iovs += (uint64_t) niov;

            s->reqs_inflight++;
            evpl_defer(evpl, &ctx->flush);
            return;
        }
    }
#endif /* HAVE_IO_URING_PREP_SEND_ZC && HAVE_IO_URING_PREP_SENDMSG_ZC_FIXED */

    req             = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);
    req->callback   = evpl_io_uring_tcp_send_callback;
    req->tcp.socket = s;
    req->owner      = bind;
    evpl_bind_operation_begin(bind);
    sqe = io_uring_get_sqe(&ctx->ring);
    evpl_io_uring_abort_if(!sqe, "io_uring_get_sqe returned NULL");

    if (niov == 1) {
        io_uring_prep_send(sqe, s->fd, s->send_iov[0].iov_base,
                           s->send_iov[0].iov_len, MSG_NOSIGNAL);
    } else {
        memset(&s->send_msg, 0, sizeof(s->send_msg));
        s->send_msg.msg_iov    = s->send_iov;
        s->send_msg.msg_iovlen = niov;
        io_uring_prep_sendmsg(sqe, s->fd, &s->send_msg, MSG_NOSIGNAL);
    }

    evpl_io_uring_set_sqe_fd(sqe, s);
    io_uring_sqe_set_data(sqe, req);
    s->reqs_inflight++;
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

    s->recv_req      = NULL;
    s->accept_req    = NULL;
    s->reqs_inflight = 0;
    s->direct_fd_idx = -1;
    s->zcrx_enabled  = 0;

    if (!s->send_iov) {
        s->send_iov = evpl_zalloc(sizeof(struct iovec) *
                                  evpl_shared->config->max_num_iovec);
    }


    flags = fcntl(s->fd, F_GETFL, 0);

    evpl_io_uring_abort_if(flags < 0, "Failed to get socket flags: %s", strerror(errno));

    rc = fcntl(s->fd, F_SETFL, flags | O_NONBLOCK);

    evpl_io_uring_abort_if(rc < 0, "Failed to set socket flags: %s", strerror(
                               errno));


    if (ctx->effective.fixed_file) {
        s->direct_fd_idx = evpl_io_uring_alloc_direct_fd(ctx, s->fd);
    }

    if (!listen) {
#ifdef HAVE_IO_URING_ZCRX
        /* When this ring owns the queue's ifq, every accepted socket on it
         * receives via RECV_ZC. Steering only ZCRX-bound traffic to this
         * queue is the caller's job (typically an ethtool ntuple rule). */
        if (ctx->effective.zcrx && ctx->num_zcrx) {
            s->zcrx_enabled = 1;
            s->zcrx         = ctx->zcrx[0];

            /* With several ifqs, receive on the one bound to the queue this
             * connection actually arrives on; the kernel names that queue's
             * NAPI instance, and each ifq learned its own at registration.
             * A socket on some other queue still works through the first
             * ifq, but by copy rather than placement, so count it. */
            if (ctx->num_zcrx > 1) {
                unsigned int napi_id = 0;
                socklen_t    len     = sizeof(napi_id);
                int          zi, found = 0;

                if (getsockopt(s->fd, SOL_SOCKET, SO_INCOMING_NAPI_ID,
                               &napi_id, &len) == 0 && napi_id) {
                    for (zi = 0; zi < ctx->num_zcrx; zi++) {
                        if (ctx->zcrx[zi]->napi_id == napi_id) {
                            s->zcrx = ctx->zcrx[zi];
                            found   = 1;
                            break;
                        }
                    }
                }

                if (!found) {
                    ctx->stat_zcrx_unmatched++;
                }
            }
        }
#endif /* ifdef HAVE_IO_URING_ZCRX */

        /* ZCRX delivers out of the registered area, so the provided-buffer
         * recv ring would only tie up allocator buffers it never fills. */
        if (!s->zcrx_enabled) {
            evpl_io_uring_init_recv_ring(ctx);
            n = evpl_io_uring_fill_recv_ring(evpl, ctx);
            if (n) {
                io_uring_buf_ring_advance(ctx->recv_ring, n);
            }
        }

        rc = setsockopt(s->fd, IPPROTO_TCP, TCP_NODELAY, &yes, sizeof(yes));

        evpl_io_uring_abort_if(rc, "Failed to set TCP_NODELAY on socket");


        evpl_io_uring_post_multishot_recv(evpl, ctx, s);
    }


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
    req->owner      = evpl_private2bind(s);
    evpl_bind_operation_begin(req->owner);
    req->callback = evpl_io_uring_tcp_connect_callback;

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
    close_req->owner      = evpl_private2bind(s);
    evpl_bind_operation_begin(close_req->owner);
    close_req->callback = evpl_io_uring_tcp_close_callback;

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
    req->owner      = evpl_private2bind(s);
    evpl_bind_operation_begin(req->owner);
    req->callback = evpl_io_uring_tcp_cancel_callback;

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

    (void) ctx;
    (void) s;
    evpl_core_assert(!s->recv_req && !s->accept_req && !bind->outstanding);

    if (s->direct_fd_idx >= 0) {
        evpl_io_uring_free_direct_fd(ctx, s->direct_fd_idx);
        s->direct_fd_idx = -1;
    }

    if (s->send_iov) {
        evpl_free(s->send_iov);
        s->send_iov = NULL;
    }
} /* evpl_io_uring_tcp_close */


static void
evpl_io_uring_tcp_accept_callback(
    struct evpl                  *evpl,
    struct evpl_io_uring_request *req)
{
    struct evpl_io_uring_socket          *ls          = req->tcp.socket;
    struct evpl_bind                     *listen_bind = evpl_private2bind(ls);
    struct evpl_address                  *remote_addr;
    struct evpl_io_uring_accepted_socket *accepted_socket;
    int                                   more = !!(req->flags & IORING_CQE_F_MORE);

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

static int
evpl_io_uring_tcp_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind)
{
    struct evpl_io_uring_socket  *s   = evpl_bind_private(listen_bind);
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    struct evpl_io_uring_request *req;
    struct io_uring_sqe          *sqe;
    char                          addr_str[80];
    int                           rc;
    const int                     yes = 1;

    s->fd = socket(listen_bind->local->addr->sa_family, SOCK_STREAM, 0);

    if (s->fd < 0) {
        evpl_io_uring_error("Failed to create tcp listen socket: %s",
                            strerror(errno));
        return -1;
    }

    rc = setsockopt(s->fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int));

    if (rc < 0) {
        evpl_io_uring_error("Failed to set socket options: %s",
                            strerror(errno));
        goto fail;
    }

    rc = bind(s->fd, listen_bind->local->addr, listen_bind->local->addrlen);

    if (rc < 0) {
        evpl_address_get_address(listen_bind->local, addr_str, sizeof(addr_str));
        evpl_io_uring_error("Failed to bind listen socket to %s: %s",
                            addr_str, strerror(errno));
        goto fail;
    }

    /* Ordered ahead of setup_socket so that every failure above is a plain
     * close of our own fd.  setup_socket consumes a send group id and tops up
     * the shared recv ring, which is not worth unwinding. */
    rc = listen(s->fd, evpl_shared->config->max_pending);

    if (rc < 0) {
        evpl_io_uring_error("Failed to listen on listener fd: %s",
                            strerror(errno));
        goto fail;
    }

    evpl_io_uring_setup_socket(evpl, ctx, s, 1);

    req = evpl_io_uring_request_alloc(ctx, EVPL_IO_URING_REQ_TCP);

    req->callback   = evpl_io_uring_tcp_accept_callback;
    req->tcp.socket = s;
    req->owner      = evpl_private2bind(s);
    evpl_bind_operation_begin(req->owner);
    sqe = io_uring_get_sqe(&ctx->ring);

    io_uring_prep_multishot_accept(sqe, s->fd, NULL, 0, 0);

    io_uring_sqe_set_data64(sqe, (uint64_t) req);

    s->accept_req = req;

    evpl_defer(evpl, &ctx->flush);

    return 0;

 fail:

    close(s->fd);

    s->fd = -1;

    return -1;
} /* evpl_io_uring_tcp_listen */

static void
evpl_io_uring_attach_discard(
    struct evpl *evpl,
    void        *accepted)
{
    struct evpl_io_uring_accepted_socket *a = accepted;

    (void) evpl;
    close(a->fd);
    evpl_free(a);
} /* evpl_io_uring_attach_discard */

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

/* Distributed listen for io_uring_tcp + ZCRX.
 *
 * When ZCRX is in effect the kernel binds one memory-provider ifq per rxq, and
 * only the ring that owns the ifq can RECV_ZC from packets that land there. To
 * get real zero-copy on every accepted connection the listen has to happen on
 * the same ring that will do the recv, which means each worker opens its own
 * listen socket + ring + ifq for its assigned rxq rather than sharing one
 * centralized listener.
 *
 * Initial constraint (intentional, can be relaxed later): rxq_count must be
 * <= the number of attached workers, so a bad thread/queue plan is reported
 * rather than silently under-subscribed.
 */
static int
evpl_io_uring_tcp_listen_distributed(
    struct evpl_listener *listener,
    unsigned int          protocol_id,
    struct evpl_address  *address)
{
    struct evpl_global_config              *cfg = evpl_shared->config;
    struct evpl_listen_distributed_request *reqs;
    unsigned int                            num_queues;
    unsigned int                            i;

    /* Only take the distributed path when ZCRX is explicitly requested; a
    * non-zero return leaves the centralized single-bind path in place. */
    if (cfg->io_uring_zerocopy_rx != EVPL_IO_URING_ON ||
        !cfg->io_uring_zcrx_interface) {
        return -1;
    }

    num_queues = cfg->io_uring_zcrx_rxq_count;
    if (num_queues == 0) {
        num_queues = 1;
    }

    evpl_io_uring_abort_if(
        num_queues > (unsigned int) listener->num_attached,
        "io_uring_tcp listen_distributed: ZCRX rxq_count=%u but only %d "
        "worker(s) attached to the listener. Attach at least %u workers "
        "via evpl_listener_attach before evpl_listen, or reduce rxq_count.",
        num_queues, listener->num_attached, num_queues);

    reqs = evpl_zalloc(num_queues * sizeof(*reqs));

    for (i = 0; i < num_queues; i++) {
        struct evpl_listener_binding *binding = listener->attached[i];

        evpl_address_incref(address);
        reqs[i].protocol_id      = protocol_id;
        reqs[i].address          = address;
        reqs[i].rxq              = cfg->io_uring_zcrx_rxq + i;
        reqs[i].listener_binding = binding;
        reqs[i].complete         = 0;
        reqs[i].status           = 0;

        evpl_mutex_init(&reqs[i].lock, NULL);
        evpl_cond_init(&reqs[i].cond, NULL);

        evpl_mutex_lock(&binding->evpl->lock);
        DL_APPEND(binding->evpl->listen_distributed_requests, &reqs[i]);
        evpl_mutex_unlock(&binding->evpl->lock);

        evpl_ring_doorbell(&binding->evpl->run_doorbell);
    }

    for (i = 0; i < num_queues; i++) {
        evpl_mutex_lock(&reqs[i].lock);
        while (!reqs[i].complete) {
            evpl_cond_wait(&reqs[i].cond, &reqs[i].lock);
        }
        evpl_mutex_unlock(&reqs[i].lock);

        evpl_io_uring_abort_if(
            reqs[i].status != 0,
            "listen_distributed: worker %u reported status %d",
            i, reqs[i].status);

        evpl_mutex_destroy(&reqs[i].lock);
        evpl_cond_destroy(&reqs[i].cond);
    }

    evpl_free(reqs);

    return 0;
} /* evpl_io_uring_tcp_listen_distributed */

struct evpl_protocol evpl_io_uring_tcp = {
    .id                 = EVPL_STREAM_IO_URING_TCP,
    .connected          = 1,
    .stream             = 1,
    .name               = "STREAM_IO_URING_TCP",
    .framework          = &evpl_framework_io_uring,
    .connect            = evpl_io_uring_tcp_connect,
    .pending_close      = evpl_io_uring_pending_close,
    .close              = evpl_io_uring_close,
    .listen             = evpl_io_uring_tcp_listen,
    .listen_distributed = evpl_io_uring_tcp_listen_distributed,
    .discard_accepted   = evpl_io_uring_attach_discard,
    .attach             = evpl_io_uring_attach,
    .flush              = evpl_io_uring_flush,
};
