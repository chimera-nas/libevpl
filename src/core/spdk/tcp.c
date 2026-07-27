// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * STREAM_SPDK_TCP: TCP stream protocol over spdk_sock (pluggable posix/uring
 * implementations, selected with evpl_global_config_set_spdk_sock_impl).
 *
 * Requires EVPL_CORE_MECH_SPDK: each evpl thread keeps an spdk_sock_group in
 * its SPDK framework state (created lazily on first socket use) and pumps it
 * with a shared sweep -- spdk_sock_group_poll (which fires per-sock recv and
 * accept callbacks, flushes queued write requests, and advances asynchronous
 * connects) followed by an XLIO-style active-socket write pass.  The sweep
 * runs from three places:
 *
 *   - an evpl_add_poll callback, every loop pass while in poll mode.  When
 *     interrupt mode is not enabled process-wide, force_poll_mode pins the
 *     loop so the group is always pumped (XLIO precedent);
 *   - the group's interrupt registration when interrupt mode is enabled, so
 *     sock-only threads can sleep.  This runs OUTSIDE evpl_continue, so it
 *     ends with evpl_kick() whenever work was done or deferrals/closes are
 *     pending, waking the mechanism's pump before the reactor sleeps;
 *   - a 1ms progress timer, armed in interrupt mode only while connects are
 *     in flight or write requests are outstanding: the group epoll reports
 *     only EPOLLIN, and SPDK expects the caller to retry partially-flushed
 *     writes ("caller in interrupt mode should retry"), so both need a
 *     time-based nudge while the reactor sleeps.
 *
 * Sends are zero-copy spdk_sock_writev_async requests using the rdmacm waist
 * model: iovecs stay in bind->iovec_send holding their reference for the
 * whole flight; submit advances the ring's waist, and the completion (FIFO
 * for the non-zcopy posix path -- zcopy is deliberately disabled) releases
 * from the tail.  Cancelled requests (-ECANCELED from group removal or sock
 * close) leave the ring alone; evpl_bind_destroy's ring clear reclaims them.
 *
 * Interrupt-mode wiring is code-complete but not covered by the mini-reactor
 * test harness (which never enables interrupt mode); it shares this sweep
 * with the tested poll path.
 */

#include <stdio.h>
#include <stdlib.h>
#include <alloca.h>
#include <string.h>
#include <errno.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "core/evpl.h"
#include "evpl/evpl.h"
#include "core/macros.h"
#include "core/protocol.h"
#include "core/evpl_shared.h"
#include "core/bind.h"
#include "core/address.h"
#include "core/iovec.h"
#include "core/spdk/evpl_spdk.h"
#include "core/spdk/spdk_sock_common.h"

extern struct evpl_shared *evpl_shared;

#define evpl_spdk_sock_debug(...) evpl_debug("spdk_sock", __FILE__, \
                                             __LINE__, __VA_ARGS__)
#define evpl_spdk_sock_info(...)  evpl_info("spdk_sock", __FILE__, \
                                            __LINE__, __VA_ARGS__)
#define evpl_spdk_sock_error(...) evpl_error("spdk_sock", __FILE__, \
                                             __LINE__, __VA_ARGS__)
#define evpl_spdk_sock_abort_if(cond, ...) \
        evpl_abort_if(cond, "spdk_sock", __FILE__, __LINE__, __VA_ARGS__)

_Static_assert(offsetof(struct evpl_spdk_sock_request, iov) ==
               sizeof(struct spdk_sock_request),
               "iov[] must directly follow spdk_sock_request "
               "(SPDK_SOCK_REQUEST_IOV contract)");

struct evpl_spdk_accepted_sock {
    struct spdk_sock *sock;
};

static void evpl_spdk_sock_progress_timer_cb(
    struct evpl       *evpl,
    struct evpl_timer *timer);

static int evpl_spdk_sock_sweep(
    struct evpl             *evpl,
    struct evpl_spdk_thread *ctx);

static int evpl_spdk_sock_submit(
    struct evpl             *evpl,
    struct evpl_spdk_thread *ctx,
    struct evpl_spdk_sock   *s,
    struct evpl_bind        *bind);

static int evpl_spdk_sock_intr_fn(
    void *arg);

static void
evpl_spdk_sock_poll_cb(
    struct evpl *evpl,
    void        *arg)
{
    evpl_spdk_sock_sweep(evpl, arg);
} /* evpl_spdk_sock_poll_cb */

/* Interrupt-mode progress accounting: (connecting socks + socks with
 * outstanding write requests); the 1ms timer runs while nonzero. */
static void
evpl_spdk_sock_progress_inc(struct evpl_spdk_thread *ctx)
{
    if (ctx->progress++ == 0 && ctx->intr_registered &&
        !ctx->progress_timer_armed) {
        evpl_add_timer(ctx->evpl, &ctx->progress_timer,
                       evpl_spdk_sock_progress_timer_cb,
                       EVPL_SPDK_SOCK_PROGRESS_US);
        ctx->progress_timer_armed = 1;
    }
} /* evpl_spdk_sock_progress_inc */

static void
evpl_spdk_sock_progress_dec(struct evpl_spdk_thread *ctx)
{
    if (--ctx->progress == 0 && ctx->progress_timer_armed) {
        evpl_remove_timer(ctx->evpl, &ctx->progress_timer);
        ctx->progress_timer_armed = 0;
    }
} /* evpl_spdk_sock_progress_dec */

static void
evpl_spdk_sock_check_active(
    struct evpl_spdk_thread *ctx,
    struct evpl_spdk_sock   *s)
{
    if (s->active) {
        return;
    }

    if (ctx->num_active >= ctx->max_active) {
        ctx->max_active *= 2;
        ctx->active      = evpl_realloc(ctx->active,
                                        ctx->max_active *
                                        sizeof(*ctx->active));
    }

    ctx->active[ctx->num_active++] = s;

    s->active = 1;
} /* evpl_spdk_sock_check_active */

/* Extract ip string + port from an evpl address. */
static void
evpl_spdk_sock_endpoint_parts(
    struct evpl_address *address,
    char                *ip,
    size_t               iplen,
    uint16_t            *port)
{
    if (address->addr->sa_family == AF_INET) {
        struct sockaddr_in *sin = (struct sockaddr_in *) address->addr;
        inet_ntop(AF_INET, &sin->sin_addr, ip, iplen);
        *port = ntohs(sin->sin_port);
    } else {
        struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) address->addr;
        inet_ntop(AF_INET6, &sin6->sin6_addr, ip, iplen);
        *port = ntohs(sin6->sin6_port);
    }
} /* evpl_spdk_sock_endpoint_parts */

/* Fill an evpl address from an ip string + port. */
static void
evpl_spdk_sock_address_fill(
    struct evpl_address *address,
    const char          *ip,
    uint16_t             port)
{
    struct sockaddr_in  *sin  = (struct sockaddr_in *) address->addr;
    struct sockaddr_in6 *sin6 = (struct sockaddr_in6 *) address->addr;

    if (inet_pton(AF_INET, ip, &sin->sin_addr) == 1) {
        sin->sin_family  = AF_INET;
        sin->sin_port    = htons(port);
        address->addrlen = sizeof(*sin);
    } else if (inet_pton(AF_INET6, ip, &sin6->sin6_addr) == 1) {
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port   = htons(port);
        address->addrlen  = sizeof(*sin6);
    } else {
        address->addrlen = 0;
    }
} /* evpl_spdk_sock_address_fill */

/*
 * Lazy per-thread group bring-up on first socket use.  The framework's
 * per-thread ctx (struct evpl_spdk_thread) was created by bind_prepare's
 * evpl_attach_framework before any protocol op runs.
 */
static struct evpl_spdk_thread *
evpl_spdk_sock_thread(struct evpl *evpl)
{
    struct evpl_spdk_thread *ctx;
    int                      rc;

    ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_SPDK);

    if (ctx->group) {
        return ctx;
    }

    ctx->group = spdk_sock_group_create(NULL);

    evpl_spdk_sock_abort_if(!ctx->group, "spdk_sock_group_create failed");

    ctx->poll = evpl_add_poll(evpl, NULL, NULL, evpl_spdk_sock_poll_cb, ctx);

    if (spdk_interrupt_mode_is_enabled()) {
        rc = spdk_sock_group_register_interrupt(ctx->group,
                                                SPDK_INTERRUPT_EVENT_IN,
                                                evpl_spdk_sock_intr_fn,
                                                ctx, "evpl_sock");

        evpl_spdk_sock_abort_if(rc,
                                "spdk_sock_group_register_interrupt failed: %d (sock impl without interrupt support?)",
                                rc);

        ctx->intr_registered = 1;
    } else {
        /* No interrupt path: the loop must stay in poll mode so the group
         * is pumped every pass (requires config poll_mode, the default). */
        evpl->force_poll_mode = 1;
    }

    return ctx;
} /* evpl_spdk_sock_thread */

static void
evpl_spdk_sock_write_complete(
    void *cb_arg,
    int   err)
{
    struct evpl_spdk_sock_request *request = cb_arg;
    struct evpl_spdk_sock         *s       = request->sock;
    struct evpl                   *evpl    = s->evpl;
    struct evpl_bind              *bind    = evpl_private2bind(s);
    struct evpl_spdk_thread       *ctx;
    struct evpl_notify             notify;
    struct evpl_iovec             *iovec;
    int                            i, niov_sent, msg_sent = 0;

    ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_SPDK);

    if (--s->outstanding == 0) {
        evpl_spdk_sock_progress_dec(ctx);
    }

    if (err == 0) {

        /* FIFO completion: this request's iovecs are exactly at the ring
         * tail.  Release their flight references and retire them. */
        for (i = 0; i < request->niov; i++) {
            iovec = evpl_iovec_ring_tail(&bind->iovec_send);
            evpl_iovec_release_internal(evpl, iovec);
            evpl_iovec_ring_remove(&bind->iovec_send);
        }

        niov_sent = request->niov;

        if (bind->segment_callback) {
            while (niov_sent) {
                struct evpl_dgram *dgram =
                    evpl_dgram_ring_tail(&bind->dgram_send);

                if (!dgram) {
                    break;
                }

                if (dgram->niov > niov_sent) {
                    dgram->niov -= niov_sent;
                    break;
                }

                niov_sent -= dgram->niov;
                msg_sent++;
                evpl_dgram_ring_remove(&bind->dgram_send);
            }
        }

        if (bind->flags & EVPL_BIND_SENT_NOTIFY) {
            notify.notify_type   = EVPL_NOTIFY_SENT;
            notify.notify_status = 0;
            notify.sent.bytes    = request->total;
            notify.sent.msgs     = msg_sent;
            bind->notify_callback(evpl, bind, &notify, bind->private_data);
        }

        if (evpl_iovec_ring_is_empty(&bind->iovec_send) &&
            (bind->flags & EVPL_BIND_FINISH)) {
            evpl_close(evpl, bind);
        }

    } else {
        /* -ECANCELED (group removal / sock close) or a transport error.  Do
         * NOT touch the send ring: releases beyond the completed prefix are
         * evpl_bind_destroy's job via its ring clear.  Once one request
         * errors the sock is dying, so no success completion can follow. */
        if (err != -ECANCELED && !s->closed) {
            evpl_spdk_sock_debug("spdk_sock write failed: %d", err);
        }

        s->closed = 1;

        evpl_close(evpl, bind);
    }

    request->next      = ctx->free_requests;
    ctx->free_requests = request;
} /* evpl_spdk_sock_write_complete */

/*
 * Waist-based zero-copy submission from the send ring.  Reentrancy note:
 * spdk_sock_writev_async and spdk_sock_flush may invoke the completion
 * callback synchronously (immediate kernel send, or -EBADF on a dead sock);
 * the callback touches only tail/outstanding while this loop reads
 * waist/head, so the interleaving is safe.
 */
static int
evpl_spdk_sock_submit(
    struct evpl             *evpl,
    struct evpl_spdk_thread *ctx,
    struct evpl_spdk_sock   *s,
    struct evpl_bind        *bind)
{
    struct evpl_iovec_ring        *ring = &bind->iovec_send;
    struct evpl_spdk_sock_request *request;
    struct evpl_iovec             *cur;
    int                            work = 0;

    while (ring->waist != ring->head && !s->closed &&
           s->outstanding < EVPL_SPDK_SOCK_MAX_INFLIGHT) {

        request = ctx->free_requests;

        if (request) {
            ctx->free_requests = request->next;
        } else {
            request = evpl_zalloc(sizeof(*request));
        }

        memset(&request->base, 0, sizeof(request->base));

        request->sock  = s;
        request->niov  = 0;
        request->total = 0;

        while (ring->waist != ring->head &&
               request->niov < EVPL_SPDK_SOCK_REQ_MAX_IOV) {
            cur = &ring->iovec[ring->waist];

            request->iov[request->niov].iov_base = cur->data;
            request->iov[request->niov].iov_len  = cur->length;

            request->total += cur->length;
            request->niov++;

            ring->waist = (ring->waist + 1) & ring->mask;
        }

        request->base.iovcnt = request->niov;
        request->base.cb_fn  = evpl_spdk_sock_write_complete;
        request->base.cb_arg = request;

        if (s->outstanding++ == 0) {
            evpl_spdk_sock_progress_inc(ctx);
        }

        spdk_sock_writev_async(s->sock, &request->base);

        work++;
    }

    /* Prod the impl to hit the kernel now rather than on the next group
     * poll; a partial flush (EAGAIN) is retried by the sweep. */
    if (work && s->sock && !s->closed) {
        if (spdk_sock_flush(s->sock) < 0 &&
            errno != EAGAIN && errno != EWOULDBLOCK && errno != EBADF) {
            evpl_close(evpl, bind);
        }
    }

    s->write_interest = (ring->waist != ring->head);

    if (s->write_interest && !s->closed) {
        evpl_spdk_sock_check_active(ctx, s);
    }

    return work;
} /* evpl_spdk_sock_submit */

/* Per-sock group callback: data available to read (socket/tcp.c model). */
static void
evpl_spdk_sock_recv_cb(
    void                   *arg,
    struct spdk_sock_group *group,
    struct spdk_sock       *sock)
{
    struct evpl_spdk_sock *s    = arg;
    struct evpl           *evpl = s->evpl;
    struct evpl_bind      *bind = evpl_private2bind(s);
    struct evpl_iovec     *iovec;
    struct evpl_notify     notify;
    struct iovec           iov[2];
    ssize_t                res, total, remain;
    int                    length, niov, iter;
    uint64_t               got = 0;

    if (s->closed || !s->sock) {
        return;
    }

    for (iter = 0; iter < 8; iter++) {

        if (s->recv1.length == 0) {
            if (s->recv2.length) {
                evpl_iovec_move(&s->recv1, &s->recv2);
                s->recv2.length = 0;
            } else {
                evpl_iovec_alloc_whole(evpl, &s->recv1);
            }
        }

        if (s->recv2.length == 0) {
            evpl_iovec_alloc_whole(evpl, &s->recv2);
        }

        iov[0].iov_base = s->recv1.data;
        iov[0].iov_len  = s->recv1.length;
        iov[1].iov_base = s->recv2.data;
        iov[1].iov_len  = s->recv2.length;

        total = iov[0].iov_len + iov[1].iov_len;

        res = spdk_sock_readv(s->sock, iov, 2);

        if (res < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                evpl_close(evpl, bind);
            }
            break;
        } else if (res == 0) {
            evpl_close(evpl, bind);
            break;
        }

        if (s->recv1.length >= res) {
            evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv1, res);
        } else {
            remain = res - s->recv1.length;
            evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv1,
                                   s->recv1.length);
            evpl_iovec_ring_append(evpl, &bind->iovec_recv, &s->recv2, remain);
        }

        got += res;

        if (res < total) {
            break;
        }
    }

    if (!got) {
        return;
    }

    if (bind->segment_callback) {

        iovec = alloca(sizeof(struct evpl_iovec) *
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

            niov = evpl_iovec_ring_copyv(evpl, iovec, &bind->iovec_recv,
                                         length);

            notify.notify_type     = EVPL_NOTIFY_RECV_MSG;
            notify.recv_msg.iovec  = iovec;
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
} /* evpl_spdk_sock_recv_cb */

/*
 * The shared pump: group poll (recv/accept dispatch, queued-write flushing,
 * async-connect progress) plus the active-socket write sweep.
 */
static int
evpl_spdk_sock_sweep(
    struct evpl             *evpl,
    struct evpl_spdk_thread *ctx)
{
    struct evpl_spdk_sock *s;
    struct evpl_bind      *bind;
    int                    i, n, work = 0;

    if (!ctx->group) {
        return 0;
    }

    n = spdk_sock_group_poll(ctx->group);

    if (n > 0) {
        work += n;
    }

    for (i = 0; i < ctx->num_active;) {
        s    = ctx->active[i];
        bind = evpl_private2bind(s);

        if (!s->closed && s->connected && s->write_interest) {
            work += evpl_spdk_sock_submit(evpl, ctx, s, bind);
        }

        if (s->closed || !s->write_interest) {
            s->active      = 0;
            ctx->active[i] = ctx->active[--ctx->num_active];
        } else {
            i++;
        }
    }

    if (work) {
        evpl_activity(evpl);
    }

    return work;
} /* evpl_spdk_sock_sweep */

/*
 * fd_group handler for the sock group in interrupt mode.  Runs OUTSIDE
 * evpl_continue on the owning thread: anything the dispatched callbacks
 * deferred (sends from recv callbacks arm flush deferrals, closes arm close
 * deferrals) would otherwise sit unprocessed while the reactor sleeps, so
 * kick the mechanism's pump whenever there is any sign of follow-up work.
 */
static int
evpl_spdk_sock_intr_fn(void *arg)
{
    struct evpl_spdk_thread *ctx  = arg;
    struct evpl             *evpl = ctx->evpl;
    int                      work;

    work = evpl_spdk_sock_sweep(evpl, ctx);

    if (work || evpl->num_active_deferrals || evpl->pending_close_binds) {
        evpl_kick(evpl);
    }

    return work;
} /* evpl_spdk_sock_intr_fn */

static void
evpl_spdk_sock_progress_timer_cb(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    struct evpl_spdk_thread *ctx =
        container_of(timer, struct evpl_spdk_thread, progress_timer);

    evpl_spdk_sock_sweep(evpl, ctx);
} /* evpl_spdk_sock_progress_timer_cb */

/* Framework per-thread teardown; runs from evpl_destroy after every bind has
 * been closed, so the group is empty. */
void
evpl_spdk_sock_thread_destroy(
    struct evpl             *evpl,
    struct evpl_spdk_thread *ctx)
{
    struct evpl_spdk_sock_request *request;
    int                            rc;

    if (ctx->progress_timer_armed) {
        evpl_remove_timer(evpl, &ctx->progress_timer);
        ctx->progress_timer_armed = 0;
    }

    if (ctx->intr_registered) {
        spdk_sock_group_unregister_interrupt(ctx->group);
        ctx->intr_registered = 0;
    }

    if (ctx->poll) {
        evpl_remove_poll(evpl, ctx->poll);
        ctx->poll             = NULL;
        evpl->force_poll_mode = 0;
    }

    if (ctx->group) {
        rc = spdk_sock_group_close(&ctx->group);

        if (rc) {
            evpl_spdk_sock_error("spdk_sock_group_close failed: %s",
                                 strerror(errno));
        }
    }

    while ((request = ctx->free_requests)) {
        ctx->free_requests = request->next;
        evpl_free(request);
    }
} /* evpl_spdk_sock_thread_destroy */

static void
evpl_spdk_sock_connect_done(
    void *cb_arg,
    int   status)
{
    struct evpl_spdk_sock   *s    = cb_arg;
    struct evpl             *evpl = s->evpl;
    struct evpl_bind        *bind = evpl_private2bind(s);
    struct evpl_spdk_thread *ctx;
    struct evpl_notify       notify;
    char                     laddr[INET6_ADDRSTRLEN];
    char                     paddr[INET6_ADDRSTRLEN];
    uint16_t                 lport, pport;

    ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_SPDK);

    if (s->connecting) {
        s->connecting = 0;
        evpl_spdk_sock_progress_dec(ctx);
    }

    if (status != 0) {
        s->connect_failed = 1;

        if (!s->closed) {
            evpl_spdk_sock_debug("spdk_sock connect failed: %d", status);
            evpl_close(evpl, bind);
        }
        return;
    }

    s->connected = 1;
    s->writable  = 1;

    /* Resolve the actual local endpoint; kept only when the caller did not
     * bind an explicit local address. */
    if (!bind->local &&
        spdk_sock_getaddr(s->sock, laddr, sizeof(laddr), &lport,
                          paddr, sizeof(paddr), &pport) == 0) {
        bind->local = evpl_address_alloc();
        evpl_spdk_sock_address_fill(bind->local, laddr, lport);
    }

    notify.notify_type   = EVPL_NOTIFY_CONNECTED;
    notify.notify_status = 0;
    bind->notify_callback(evpl, bind, &notify, bind->private_data);

    /* Data staged before the connect completed. */
    if (!evpl_iovec_ring_is_empty(&bind->iovec_send)) {
        evpl_defer(evpl, &bind->flush_deferral);
    }
} /* evpl_spdk_sock_connect_done */

static void
evpl_spdk_tcp_connect(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_spdk_thread *ctx;
    struct evpl_spdk_sock   *s = evpl_bind_private(bind);
    struct spdk_sock_opts    opts;
    char                     ip[INET6_ADDRSTRLEN];
    uint16_t                 port;
    const char              *impl = evpl_shared->config->spdk_sock_impl;
    int                      rc;

    evpl_spdk_sock_abort_if(
        evpl_shared->config->core_mech != EVPL_CORE_MECH_SPDK,
        "STREAM_SPDK_TCP requires EVPL_CORE_MECH_SPDK");

    ctx = evpl_spdk_sock_thread(evpl);

    s->evpl = evpl;

    evpl_spdk_sock_endpoint_parts(bind->remote, ip, sizeof(ip), &port);

    memset(&opts, 0, sizeof(opts));
    opts.opts_size = sizeof(opts);
    spdk_sock_get_default_opts(&opts);

    /* zcopy off: write completions must be FIFO for the waist/tail release
     * model, which is only guaranteed for the non-zcopy path. */
    opts.zcopy = false;

    if (bind->local) {
        uint16_t lport;

        evpl_spdk_sock_endpoint_parts(bind->local, s->src_addr,
                                      sizeof(s->src_addr), &lport);
        opts.src_addr = s->src_addr;
        opts.src_port = lport;
    }

    s->connecting = 1;
    evpl_spdk_sock_progress_inc(ctx);

    s->sock = spdk_sock_connect_async(ip, port, impl, &opts,
                                      evpl_spdk_sock_connect_done, s);

    if (!s->sock) {
        /* Implementation without async connect, or an immediate failure
         * (posix fires the callback on failure even when returning NULL --
         * connect_failed guards double handling). */
        if (s->connecting) {
            s->connecting = 0;
            evpl_spdk_sock_progress_dec(ctx);
        }

        if (!s->connect_failed) {
            s->sock = spdk_sock_connect_ext(ip, port, impl, &opts);
        }

        if (!s->sock) {
            evpl_spdk_sock_debug("spdk_sock connect to %s:%u failed: %s",
                                 ip, port, strerror(errno));
            evpl_close(evpl, bind);
            return;
        }
    }

    rc = spdk_sock_group_add_sock(ctx->group, s->sock,
                                  evpl_spdk_sock_recv_cb, s);

    evpl_spdk_sock_abort_if(rc, "spdk_sock_group_add_sock failed: %s",
                            strerror(errno));

    s->in_group = 1;
    ctx->num_socks++;

    if (!s->connecting && !s->connected) {
        /* Synchronous fallback connected inline. */
        evpl_spdk_sock_connect_done(s, 0);
    }
} /* evpl_spdk_tcp_connect */

/* Listen-socket group callback: connections ready to accept.  Runs on the
 * shared listener thread; accepted socks are in no group (verified), so the
 * wrapper hands bare spdk_sock ownership to the worker's attach. */
static void
evpl_spdk_sock_accept_cb(
    void                   *arg,
    struct spdk_sock_group *group,
    struct spdk_sock       *sock)
{
    struct evpl_spdk_sock          *ls          = arg;
    struct evpl                    *evpl        = ls->evpl;
    struct evpl_bind               *listen_bind = evpl_private2bind(ls);
    struct spdk_sock               *new_sock;
    struct evpl_spdk_accepted_sock *wrapper;
    struct evpl_address            *remote;
    char                            laddr[INET6_ADDRSTRLEN];
    char                            paddr[INET6_ADDRSTRLEN];
    uint16_t                        lport, pport;

    while ((new_sock = spdk_sock_accept(ls->sock)) != NULL) {

        remote = evpl_address_alloc();

        if (spdk_sock_getaddr(new_sock, laddr, sizeof(laddr), &lport,
                              paddr, sizeof(paddr), &pport) == 0) {
            evpl_spdk_sock_address_fill(remote, paddr, pport);
        }

        wrapper       = evpl_zalloc(sizeof(*wrapper));
        wrapper->sock = new_sock;

        listen_bind->accept_callback(evpl, listen_bind, remote, wrapper,
                                     listen_bind->private_data);
    }
} /* evpl_spdk_sock_accept_cb */

static void
evpl_spdk_tcp_listen(
    struct evpl      *evpl,
    struct evpl_bind *listen_bind)
{
    struct evpl_spdk_thread *ctx;
    struct evpl_spdk_sock   *s = evpl_bind_private(listen_bind);
    struct spdk_sock_opts    opts;
    char                     ip[INET6_ADDRSTRLEN];
    uint16_t                 port;
    int                      rc;

    evpl_spdk_sock_abort_if(
        evpl_shared->config->core_mech != EVPL_CORE_MECH_SPDK,
        "STREAM_SPDK_TCP requires EVPL_CORE_MECH_SPDK");

    ctx = evpl_spdk_sock_thread(evpl);

    s->evpl   = evpl;
    s->listen = 1;

    evpl_spdk_sock_endpoint_parts(listen_bind->local, ip, sizeof(ip), &port);

    memset(&opts, 0, sizeof(opts));
    opts.opts_size = sizeof(opts);
    spdk_sock_get_default_opts(&opts);
    opts.zcopy = false;

    s->sock = spdk_sock_listen_ext(ip, port,
                                   evpl_shared->config->spdk_sock_impl,
                                   &opts);

    evpl_spdk_sock_abort_if(!s->sock, "Failed to listen on %s:%u: %s",
                            ip, port, strerror(errno));

    rc = spdk_sock_group_add_sock(ctx->group, s->sock,
                                  evpl_spdk_sock_accept_cb, s);

    evpl_spdk_sock_abort_if(rc, "spdk_sock_group_add_sock failed: %s",
                            strerror(errno));

    s->in_group = 1;
    ctx->num_socks++;
} /* evpl_spdk_tcp_listen */

static void
evpl_spdk_tcp_attach(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *accepted)
{
    struct evpl_spdk_accepted_sock *wrapper = accepted;
    struct evpl_spdk_thread        *ctx;
    struct evpl_spdk_sock          *s = evpl_bind_private(bind);
    struct evpl_notify              notify;
    char                            laddr[INET6_ADDRSTRLEN];
    char                            paddr[INET6_ADDRSTRLEN];
    uint16_t                        lport, pport;
    int                             rc;

    ctx = evpl_spdk_sock_thread(evpl);

    s->evpl      = evpl;
    s->sock      = wrapper->sock;
    s->connected = 1;
    s->writable  = 1;

    rc = spdk_sock_group_add_sock(ctx->group, s->sock,
                                  evpl_spdk_sock_recv_cb, s);

    evpl_spdk_sock_abort_if(rc,
                            "failed to add accepted sock to group: %s",
                            strerror(errno));

    s->in_group = 1;
    ctx->num_socks++;

    /* The connect request's local_address is deliberately NULL: resolve the
     * actual local endpoint of the accepted connection here. */
    if (spdk_sock_getaddr(s->sock, laddr, sizeof(laddr), &lport,
                          paddr, sizeof(paddr), &pport) == 0) {
        bind->local = evpl_address_alloc();
        evpl_spdk_sock_address_fill(bind->local, laddr, lport);
    }

    notify.notify_type   = EVPL_NOTIFY_CONNECTED;
    notify.notify_status = 0;
    bind->notify_callback(evpl, bind, &notify, bind->private_data);

    evpl_free(wrapper);
} /* evpl_spdk_tcp_attach */

static void
evpl_spdk_tcp_flush(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_spdk_sock   *s = evpl_bind_private(bind);
    struct evpl_spdk_thread *ctx;

    if (!s->sock || s->closed) {
        return;
    }

    if (!s->connected) {
        /* connect_done re-defers the flush once established. */
        s->write_interest = 1;
        return;
    }

    ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_SPDK);

    evpl_spdk_sock_submit(evpl, ctx, s, bind);
} /* evpl_spdk_tcp_flush */

/*
 * Runs from the close deferral inside evpl_continue -- never from within
 * spdk_sock_group_poll, so mutating the group here is safe.  Removing the
 * sock from the group aborts outstanding write requests: their completions
 * fire synchronously here with -ECANCELED and leave the send ring alone.
 * Fully synchronous teardown; EVPL_BIND_CLOSE_DEFERRED is never needed.
 */
static void
evpl_spdk_tcp_pending_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_spdk_sock   *s = evpl_bind_private(bind);
    struct evpl_spdk_thread *ctx;

    ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_SPDK);

    if (s->connecting) {
        s->connecting = 0;
        evpl_spdk_sock_progress_dec(ctx);
    }

    s->closed = 1;

    if (s->sock) {
        if (s->in_group) {
            spdk_sock_group_remove_sock(ctx->group, s->sock);
            s->in_group = 0;
            ctx->num_socks--;
        }

        spdk_sock_close(&s->sock);
    }

    if (s->outstanding) {
        evpl_spdk_sock_error("sock closed with %u write requests still "
                             "outstanding", s->outstanding);
    }
} /* evpl_spdk_tcp_pending_close */

static void
evpl_spdk_tcp_close(
    struct evpl      *evpl,
    struct evpl_bind *bind)
{
    struct evpl_spdk_sock *s = evpl_bind_private(bind);

    if (s->recv1.length) {
        evpl_iovec_release_internal(evpl, &s->recv1);
        s->recv1.length = 0;
    }

    if (s->recv2.length) {
        evpl_iovec_release_internal(evpl, &s->recv2);
        s->recv2.length = 0;
    }
} /* evpl_spdk_tcp_close */

struct evpl_protocol evpl_spdk_tcp = {
    .id            = EVPL_STREAM_SPDK_TCP,
    .connected     = 1,
    .stream        = 1,
    .name          = "STREAM_SPDK_TCP",
    .framework     = &evpl_framework_spdk,
    .connect       = evpl_spdk_tcp_connect,
    .pending_close = evpl_spdk_tcp_pending_close,
    .close         = evpl_spdk_tcp_close,
    .listen        = evpl_spdk_tcp_listen,
    .attach        = evpl_spdk_tcp_attach,
    .flush         = evpl_spdk_tcp_flush,
};
