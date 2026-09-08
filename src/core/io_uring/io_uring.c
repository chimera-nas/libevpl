// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdatomic.h>
#include <unistd.h>
#include <errno.h>

#include "io_uring_internal.h"

#include "core/evpl_shared.h"
#include "core/io_uring/io_uring.h"
#include "core/poll.h"

static void
evpl_io_uring_flush_sqe(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;

    /*
     * Just submit.  There was a hand-rolled IORING_SQ_NEED_WAKEUP check here
     * that ran *before* this call, and waking the sqpoll thread at that point
     * is worse than not waking it at all: io_uring_get_sqe() advances only
     * liburing's private sqe_tail, so the poller wakes, finds the ring's
     * kernel-visible tail unchanged, has nothing to do, and goes back to
     * sleep -- clearing the very NEED_WAKEUP flag that io_uring_submit() is
     * about to consult.  liburing then concludes no enter is needed and
     * returns without a syscall, leaving the SQE sitting unconsumed until
     * something else happens to wake the poller.
     *
     * io_uring_submit() does the same check in the only order that is correct:
     * publish the tail first, then test NEED_WAKEUP and enter with
     * IORING_ENTER_SQ_WAKEUP if it is set.
     *
     * (For most of this file's life the hand-rolled check read io_uring::flags
     * rather than the SQ ring's, which tests IORING_SETUP_IOPOLL -- never set
     * here -- so the branch was dead and liburing quietly did the right thing.
     * Correcting the word woke the branch up, and with it this race.)
     */
    io_uring_submit(&ctx->ring);
} /* evpl_io_uring_flush */


/*
 * Ring setup shared by the availability probe and every per-thread ring, so
 * the probe tests exactly the configuration the threads will run with.
 *
 * SQPOLL is off unless configured (see the io_uring_sqpoll note in config.c):
 * a kernel thread per ring that spins for a second after each submission is
 * paid for only by a ring that stays busy, and the depth-one I/O it slows
 * down is the common case for an event loop that mostly waits.  Without it,
 * COOP_TASKRUN keeps completion task-work from interrupting this thread while
 * it runs, and TASKRUN_FLAG lets liburing skip the io_uring_enter() when
 * nothing is pending.  DEFER_TASKRUN is deliberately not used: it runs
 * completions only when the issuing thread enters the ring, and this loop
 * sleeps in the core poller on the ring's eventfd, so completions would never
 * be posted while it waits.
 */
static void
evpl_io_uring_params(struct io_uring_params *params)
{
    memset(params, 0, sizeof(*params));

    params->flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_SQE128 | IORING_SETUP_CQE32;

    if (evpl_shared->config->io_uring_sqpoll) {
        params->flags         |= IORING_SETUP_SQPOLL;
        params->sq_thread_idle = 1000;
    } else {
        params->flags |= IORING_SETUP_COOP_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
    }
} /* evpl_io_uring_params */

/*
 * Availability probe: a NULL return tells the shared attach that io_uring is
 * not usable here (old kernel, seccomp, SQPOLL refused without privilege) and
 * no thread will create a ring.  The probe ring used to live for the whole
 * process, an SQPOLL ring that nothing ever attached to and whose kernel
 * thread served no one; build it with the real parameters and tear it down.
 */
static void *
evpl_io_uring_init(void)
{
    struct io_uring        ring;
    struct io_uring_params params;
    int                    rc;

    evpl_io_uring_params(&params);

    /* Probe with a small ring: this asks whether the flags are accepted, not
     * whether the configured size fits.  A size the host cannot afford is
     * still reported where it happens, by the per-thread create below. */
    rc = io_uring_queue_init_params(256, &ring, &params);

    if (rc < 0) {
        evpl_io_uring_debug("io_uring unavailable: %s (%d)", strerror(-rc), rc);
        return NULL;
    }

    io_uring_queue_exit(&ring);

    /* Nothing is shared between rings; the framework pattern needs a non-NULL
     * token to record that the probe passed. */
    return (void *) 1;
} /* evpl_io_uring_init */

static void
evpl_io_uring_cleanup(void *private_data)
{
    (void) private_data;
} /* evpl_io_uring_cleanup */

static inline int
evpl_io_uring_complete(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx)
{
    uint64_t                      debounce_offset;
    struct evpl_io_uring_request *req;
    int                           buf_count = 0, cq_count = 0;
    struct io_uring_cqe          *cqes[64], *cqe;

    cq_count = io_uring_peek_batch_cqe(&ctx->ring, cqes, 64);

    for (int i = 0; i < cq_count; i++) {
        cqe =   cqes[i];

        req = (struct evpl_io_uring_request *) io_uring_cqe_get_data64(cqe);

        req->res   = cqe->res;
        req->flags = cqe->flags;

        if (req->res < 0) {
            evpl_io_uring_error("io_uring_complete res %d", req->res);
        }

        switch (req->req_type) {
            case EVPL_IO_URING_REQ_BLOCK:

                if (req->block.need_debounce) {
                    debounce_offset = 0;

                    for (int i = 0; i < req->block.niov; i++) {
                        memcpy(req->block.iov[i].iov_base, req->block.bounce + debounce_offset, req->block.iov[i].
                               iov_len);
                        debounce_offset += req->block.iov[i].iov_len;
                    }
                }

                req->callback(evpl, req);

                if (req->block.bounce) {
                    evpl_free(req->block.bounce);
                }
                break;
            case EVPL_IO_URING_REQ_TCP:
                req->callback(evpl, req);
                break;
        } /* switch */

        if (!(cqe->flags & IORING_CQE_F_MORE)) {
            evpl_io_uring_request_free(ctx, req);
        }
    }

    if (cq_count) {

        buf_count = evpl_io_uring_fill_recv_ring(evpl, ctx);

        //__io_uring_buf_ring_cq_advance(&ctx->ring, ctx->recv_ring, cq_count, buf_count);

        io_uring_buf_ring_advance(ctx->recv_ring, buf_count);
        io_uring_cq_advance(&ctx->ring, cq_count);

        evpl_activity(evpl);
    }

    return cq_count;
} /* evpl_io_uring_complete */

static void
evpl_io_uring_poll_enter(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;
    int                           rc;

    /* A failure here only leaves the eventfd armed while we poll, which costs a
     * spurious wakeup and nothing else -- unlike poll_exit below, where it is
     * the difference between waking and hanging. */
    rc = io_uring_unregister_eventfd(&ctx->ring);

    if (rc < 0) {
        evpl_io_uring_debug("io_uring_unregister_eventfd() failed: %s (%d)", strerror(-rc), rc);
    }

    evpl_io_uring_complete(evpl, ctx);
} /* evpl_io_uring_poll_enter */

static void
evpl_io_uring_poll_exit(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;
    int                           rc = 0, i;

    /*
     * Leaving poll mode makes this eventfd the only thing that can wake the
     * loop for a completion, so a silent failure here is a hang: the loop
     * blocks, the CQE arrives with nothing to signal, and if the caller is
     * waiting on that very request nothing else will ever wake it either.
     * The result was previously discarded.
     *
     * Retry the transient cases -- EINTR, and the EBUSY io_uring can return
     * while the ring is mid-operation.  A failure that survives those is
     * fatal: there is no correct way to continue, because the loop is about to
     * block on a signal that will never arrive, and an abort naming the cause
     * is strictly better than the silent hang that leaves.
     */
    for (i = 0; i < EVPL_IO_URING_ARM_RETRIES; i++) {
        rc = io_uring_register_eventfd(&ctx->ring, ctx->eventfd);

        if (rc == 0 || (rc != -EINTR && rc != -EBUSY && rc != -EAGAIN)) {
            break;
        }
    }

    evpl_io_uring_abort_if(rc < 0,
                           "io_uring_register_eventfd() failed: %s (%d); completions would "
                           "arrive with nothing to wake the event loop",
                           strerror(-rc), rc);

    evpl_io_uring_complete(evpl, ctx);
} /* evpl_io_uring_poll_exit */

static void
evpl_io_uring_poll(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;

    evpl_io_uring_complete(evpl, ctx);
} /* evpl_io_uring_poll */

static void
evpl_io_uring_complete_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_io_uring_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_IO_URING);
    uint64_t                      value;
    int                           rc, n;

    do {
        rc = read(ctx->eventfd, &value, sizeof(value));
    } while (rc < 0 && errno == EINTR);

    if (rc != sizeof(value)) {
        evpl_event_mark_unreadable(evpl, &ctx->event);
    }

    /* Drain regardless of what the eventfd said.  The counter and the
     * completion queue are separate pieces of state: a CQE posted while the
     * eventfd was unregistered (the whole of poll mode) never incremented it,
     * and returning early on an empty read would leave that CQE sitting in the
     * ring.  With one request outstanding and nothing else to wake this loop,
     * that is a hang rather than a delay -- the request the caller is blocked
     * on is the only thing that could have produced the next wakeup. */
    do {
        n = evpl_io_uring_complete(evpl, ctx);
    } while (n);
} /* evpl_io_uring_complete */

static void *
evpl_io_uring_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx;
    int                           ret;
    struct io_uring_params        params;

    (void) private_data;

    evpl_io_uring_params(&params);

    ctx = evpl_zalloc(sizeof(*ctx));

    ctx->next_send_group_id = EVPL_IO_URING_BUFGROUP_ID + 1;

    ret = io_uring_queue_init_params(evpl_shared->config->io_uring_entries, &ctx->ring, &params);

    evpl_io_uring_abort_if(ret < 0, "io_uring_queue_init_params() failed: %s (%d)", strerror(-ret), ret);

    ctx->eventfd = eventfd(0, EFD_NONBLOCK);

    evpl_io_uring_abort_if(ctx->eventfd < 0, "eventfd");

    ret = io_uring_register_eventfd(&ctx->ring, ctx->eventfd);

    evpl_io_uring_abort_if(ret < 0,
                           "io_uring_register_eventfd() failed: %s (%d); no completion "
                           "would ever wake this event loop",
                           strerror(-ret), ret);

    evpl_add_event(evpl, &ctx->event, ctx->eventfd,
                   evpl_io_uring_complete_event, NULL, NULL);

    evpl_event_read_interest(evpl, &ctx->event);

    evpl_deferral_init(&ctx->flush, evpl_io_uring_flush_sqe, ctx);

    ctx->recv_ring_size   = 8192;
    ctx->recv_buffer_size = 2 * 1024 * 1024;

    ctx->recv_ring = io_uring_setup_buf_ring(&ctx->ring, ctx->recv_ring_size,
                                             EVPL_IO_URING_BUFGROUP_ID,
                                             0, &ret);

    ctx->recv_ring_mask = io_uring_buf_ring_mask(ctx->recv_ring_size);

    ctx->recv_ring_iov_empty = evpl_zalloc((ctx->recv_ring_size / 64) * sizeof(uint64_t));
    memset(ctx->recv_ring_iov_empty, 0xff, (ctx->recv_ring_size / 64) * sizeof(uint64_t));

    ctx->recv_ring_iov = evpl_zalloc(ctx->recv_ring_size * sizeof(struct evpl_iovec));

    evpl_io_uring_abort_if(ret < 0, "io_uring_setup_buf_ring");

    ctx->poll = evpl_add_poll(evpl, evpl_io_uring_poll_enter, evpl_io_uring_poll_exit, evpl_io_uring_poll, ctx);

    return ctx;
} /* evpl_io_uring_create */

static void
evpl_io_uring_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;
    struct evpl_io_uring_request *req;
    int                           n;

    while (ctx->free_requests) {
        req = ctx->free_requests;
        LL_DELETE(ctx->free_requests, req);
        evpl_free(req);
    }

    n = evpl_io_uring_fill_recv_ring(evpl, ctx);

    if (n) {
        io_uring_buf_ring_advance(ctx->recv_ring, n);
    }

    io_uring_free_buf_ring(&ctx->ring, ctx->recv_ring, ctx->recv_ring_size, 0);

    io_uring_queue_exit(&ctx->ring);

    close(ctx->eventfd);

    evpl_iovecs_release_internal(evpl, ctx->recv_ring_iov, ctx->recv_ring_size);

    evpl_free(ctx->recv_ring_iov_empty);
    evpl_free(ctx->recv_ring_iov);

    evpl_free(ctx);
} /* evpl_io_uring_destroy */

struct evpl_framework evpl_framework_io_uring = {
    .id      = EVPL_FRAMEWORK_IO_URING,
    .name    = "IO_URING",
    .init    = evpl_io_uring_init,
    .cleanup = evpl_io_uring_cleanup,
    .create  = evpl_io_uring_create,
    .destroy = evpl_io_uring_destroy,
};
