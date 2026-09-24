// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#ifndef MAP_HUGE_SHIFT
#define MAP_HUGE_SHIFT 26
#endif /* ifndef MAP_HUGE_SHIFT */
#ifndef MAP_HUGE_2MB
#define MAP_HUGE_2MB   (21 << MAP_HUGE_SHIFT)
#endif /* ifndef MAP_HUGE_2MB */
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <stdatomic.h>

#include <errno.h>
#include <net/if.h>
#include <unistd.h>

#include "io_uring_internal.h"

#include "core/evpl_shared.h"
#include "core/io_uring/io_uring.h"
#include "core/poll.h"
#include "core/allocator.h"

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
 *
 * Zero-copy receive is the one exception to both rules: the kernel requires
 * DEFER_TASKRUN and refuses an SQPOLL ring, so such a ring takes DEFER_TASKRUN
 * and stays pinned in poll mode for as long as its ifq is registered.
 */
static inline int
evpl_io_uring_mode_wants(unsigned mode)
{
    return mode == EVPL_IO_URING_ON || mode == EVPL_IO_URING_AUTO;
} /* evpl_io_uring_mode_wants */

static inline int
evpl_io_uring_mode_required(unsigned mode)
{
    return mode == EVPL_IO_URING_ON;
} /* evpl_io_uring_mode_required */

/*
 * Whether any ring in this process is going to want a ZCRX ifq.  ZCRX and
 * SQPOLL are mutually exclusive, and both the availability probe and every
 * per-thread ring have to make that call identically, or the probe stops
 * testing the configuration the threads actually run with.
 */
static int
evpl_io_uring_wants_zcrx(void)
{
#ifdef HAVE_IO_URING_ZCRX
    const struct evpl_global_config *cfg = evpl_shared->config;

    return evpl_io_uring_mode_wants(cfg->io_uring_zerocopy_rx) &&
           cfg->io_uring_zcrx_interface != NULL;
#else  /* ifdef HAVE_IO_URING_ZCRX */
    return 0;
#endif /* ifdef HAVE_IO_URING_ZCRX */
} /* evpl_io_uring_wants_zcrx */

static void
evpl_io_uring_params(struct io_uring_params *params)
{
    memset(params, 0, sizeof(*params));

    params->flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_SQE128 | IORING_SETUP_CQE32;

    if (evpl_io_uring_wants_zcrx()) {
        /* io_register_zcrx_ifq() rejects a ring without DEFER_TASKRUN
         * outright, so a ring that will carry a ZCRX ifq has no choice.  That
         * is also why zcrx_setup() pins the thread into poll mode: with
         * DEFER_TASKRUN the kernel only runs completion task work when this
         * thread enters the ring, so a loop that went back to sleeping on the
         * completion eventfd would never be woken to do it.  TASKRUN_FLAG comes
         * along because the kernel only publishes IORING_SQ_TASKRUN when it is
         * set, and evpl_io_uring_complete() needs that flag to know whether
         * entering the ring is worth a syscall. */
        params->flags |= IORING_SETUP_DEFER_TASKRUN | IORING_SETUP_TASKRUN_FLAG;
    } else if (evpl_shared->config->io_uring_sqpoll) {
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
    struct evpl_io_uring_shared *shared;
    struct io_uring              ring;
    struct io_uring_params       params;
    struct rlimit                rlim;
    int                          rc;

    evpl_io_uring_params(&params);

    /* Try to bump RLIMIT_MEMLOCK to RLIM_INFINITY so that
     * io_uring_register_buffers can pin enough pages for our slabs.
     * Older kernels enforce MEMLOCK on registered buffers; newer ones
     * (6.2+) only enforce when the caller lacks CAP_IPC_LOCK. Either way,
     * raising the limit is safe -- if we lack the privilege the syscall
     * just fails and we fall back to a smaller pin budget.
     */
    if (getrlimit(RLIMIT_MEMLOCK, &rlim) == 0 &&
        rlim.rlim_cur < RLIM_INFINITY) {
        struct rlimit new_rlim;

        new_rlim.rlim_cur = RLIM_INFINITY;
        new_rlim.rlim_max = RLIM_INFINITY;
        if (setrlimit(RLIMIT_MEMLOCK, &new_rlim) != 0) {
            evpl_io_uring_info(
                "could not raise RLIMIT_MEMLOCK (current %lu KiB); "
                "io_uring registered buffers may be limited",
                (unsigned long) (rlim.rlim_cur / 1024));
        }
    }

    /* Probe with a small ring: this asks whether the flags are accepted, not
     * whether the configured size fits.  A size the host cannot afford is
     * still reported where it happens, by the per-thread create below. */
    rc = io_uring_queue_init_params(256, &ring, &params);

    if (rc < 0) {
        evpl_io_uring_debug("io_uring unavailable: %s (%d)", strerror(-rc), rc);
        return NULL;
    }

    io_uring_queue_exit(&ring);

    /* The rings share no io_uring state, but registered memory slabs are
     * process-wide: register_memory assigns each slab a stable index here and
     * every per-thread ring registers the slabs it actually touches into its
     * own FIXED_BUF table under that index. */
    shared = evpl_zalloc(sizeof(*shared));

    evpl_mutex_init(&shared->buf_lock, NULL);
    shared->buf_count = 0;

    return shared;
} /* evpl_io_uring_init */

static void *
evpl_io_uring_register_memory(
    void *buffer,
    int   size,
    void *buffer_private,
    void *thread_private)
{
    struct evpl_io_uring_shared *shared = thread_private;
    uintptr_t                    idx_plus_one;

    if (!shared) {
        return NULL;
    }

    /* If this slab was already registered (re-register path), reuse it. */
    idx_plus_one = (uintptr_t) buffer_private;
    if (idx_plus_one != 0) {
        return buffer_private;
    }

    evpl_mutex_lock(&shared->buf_lock);

    if (shared->buf_count >= EVPL_IO_URING_MAX_REGISTERED_BUFFERS) {
        evpl_mutex_unlock(&shared->buf_lock);
        evpl_io_uring_info(
            "registered buffer table full (%u entries), slab will not be fixed-buf eligible",
            shared->buf_count);
        return NULL;
    }

    shared->buf_slabs[shared->buf_count].addr = buffer;
    shared->buf_slabs[shared->buf_count].len  = size;
    idx_plus_one                              = (uintptr_t) (shared->buf_count + 1);
    shared->buf_count++;

    evpl_mutex_unlock(&shared->buf_lock);

    return (void *) idx_plus_one;
} /* evpl_io_uring_register_memory */

static void
evpl_io_uring_unregister_memory(
    void *buffer_private,
    void *thread_private)
{
    /* Registered buffer indices are stable for process lifetime. We don't
     * release them here — slabs are freed only at process shutdown, and the
     * per-ring buffer table is torn down with the ring.
     */
    (void) buffer_private;
    (void) thread_private;
} /* evpl_io_uring_unregister_memory */

static void
evpl_io_uring_cleanup(void *private_data)
{
    struct evpl_io_uring_shared *shared = private_data;

    evpl_mutex_destroy(&shared->buf_lock);

    evpl_free(shared);
} /* evpl_io_uring_cleanup */

static inline int
evpl_io_uring_complete(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx)
{
    uint64_t                      debounce_offset;
    struct evpl_io_uring_request *req;
    int                           buf_count = 0, cq_count = 0;

    /* On DEFER_TASKRUN rings, task work (and therefore CQE delivery) is
     * deferred until the ring is entered with IORING_ENTER_GETEVENTS.
     * BUT: CQEs already deposited by previous task work are sitting in
     * the shared CQ ring — we can drain those with zero syscalls. Only
     * enter the kernel when the ring is empty and we want fresh events.
     * Under load this collapses the get_events syscall rate from "one
     * per poll-loop turn" to "one per CQE-batch drained", which on AMD
     * with Spectre mitigations is a multi-percent CPU win.
     */
    struct io_uring_cqe *cqes[64], *cqe;

    cq_count = io_uring_peek_batch_cqe(&ctx->ring, cqes, 64);
    if (cq_count == 0) {
        /* Entering the ring costs a syscall, and on a poll-mode loop that finds
         * the queue empty most turns it is the single largest cost -- more so on
         * CPUs where the speculation mitigations make the entry expensive.  Both
         * ring configurations publish IORING_SQ_TASKRUN when completion task
         * work is waiting to run (that is what TASKRUN_FLAG and DEFER_TASKRUN
         * are for), so only pay for the enter when there is something to
         * collect, or when the CQ overflowed and the kernel is holding
         * completions back. */
        unsigned int sq_flags = atomic_load_explicit(
            (_Atomic unsigned int *) ctx->ring.sq.kflags, memory_order_relaxed);

        if (sq_flags & (IORING_SQ_TASKRUN | IORING_SQ_CQ_OVERFLOW)) {
            io_uring_get_events(&ctx->ring);
            cq_count = io_uring_peek_batch_cqe(&ctx->ring, cqes, 64);
        }
    }

    for (int i = 0; i < cq_count; i++) {
        cqe =   cqes[i];

        req = (struct evpl_io_uring_request *) io_uring_cqe_get_data64(cqe);

        req->res          = cqe->res;
        req->flags        = cqe->flags;
        req->cqe_extra[0] = cqe->big_cqe[0];
        req->cqe_extra[1] = cqe->big_cqe[1];

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

        if (ctx->recv_ring) {
            buf_count = evpl_io_uring_fill_recv_ring(evpl, ctx);
            io_uring_buf_ring_advance(ctx->recv_ring, buf_count);
        }
        io_uring_cq_advance(&ctx->ring, cq_count);

        evpl_activity(evpl);
    }

#ifdef HAVE_IO_URING_ZCRX
    /* Publish any pending ZCRX rqe posts in one release-store. Cheap
     * if tail_cached hasn't moved (we'd be writing the value the
     * kernel already sees), but kept unconditional so the kernel can
     * always observe just-released frags within one poll-loop
     * iteration of the release.
     */
    for (int zi = 0; zi < ctx->num_zcrx; zi++) {
        atomic_store_explicit((_Atomic uint32_t *) ctx->zcrx[zi]->rq_ktail,
                              ctx->zcrx[zi]->tail_cached,
                              memory_order_release);
    }
#endif /* ifdef HAVE_IO_URING_ZCRX */

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

/* Block queues do not need TCP provided-buffer support or receive buffers. */
void
evpl_io_uring_init_recv_ring(struct evpl_io_uring_context *ctx)
{
    int ret;

    if (ctx->recv_ring) {
        return;
    }

    ctx->recv_ring_size = ctx->ring.sq.ring_entries;
    if (ctx->recv_ring_size > 8192) {
        ctx->recv_ring_size = 8192;
    }
    /* Each provided buffer must fit in one allocator buffer. The allocator
     * releases a partial allocation when max_iovecs=1 cannot hold the size. */
    ctx->recv_buffer_size = evpl_shared->config->buffer_size;
    if (ctx->recv_buffer_size > 65536) {
        ctx->recv_buffer_size = 65536;
    }

    ctx->recv_ring = io_uring_setup_buf_ring(&ctx->ring, ctx->recv_ring_size,
                                             EVPL_IO_URING_BUFGROUP_ID,
                                             0, &ret);

    evpl_io_uring_abort_if(ret < 0, "io_uring_setup_buf_ring() failed: %s (%d)", strerror(-ret), ret);

    ctx->recv_ring_mask = io_uring_buf_ring_mask(ctx->recv_ring_size);

    ctx->recv_ring_iov_empty = evpl_zalloc((ctx->recv_ring_size / 64) * sizeof(uint64_t));
    memset(ctx->recv_ring_iov_empty, 0xff, (ctx->recv_ring_size / 64) * sizeof(uint64_t));

    ctx->recv_ring_iov = evpl_zalloc(ctx->recv_ring_size * sizeof(struct evpl_iovec));



} /* evpl_io_uring_init_recv_ring */

static void
evpl_io_uring_probe_caps(struct evpl_io_uring_context *ctx)
{
    struct io_uring_probe *probe;
    unsigned int           send_zc_supported = 0;

#ifdef HAVE_IO_URING_OP_RECV_ZC
    unsigned int           recv_zc_supported = 0;
#endif /* ifdef HAVE_IO_URING_OP_RECV_ZC */

    probe = io_uring_get_probe_ring(&ctx->ring);

    if (probe) {
#ifdef HAVE_IO_URING_OP_RECV_ZC
        recv_zc_supported = io_uring_opcode_supported(probe, IORING_OP_RECV_ZC);
#endif /* ifdef HAVE_IO_URING_OP_RECV_ZC */
        send_zc_supported = io_uring_opcode_supported(probe, IORING_OP_SEND_ZC);
        io_uring_free_probe(probe);
    }

#ifdef HAVE_IO_URING_REGISTER_IFQ
    ctx->caps.have_register_ifq = 1;
#endif /* ifdef HAVE_IO_URING_REGISTER_IFQ */

#ifdef HAVE_IO_URING_OP_RECV_ZC
    ctx->caps.have_op_recv_zc = recv_zc_supported ? 1 : 0;
#endif /* ifdef HAVE_IO_URING_OP_RECV_ZC */

#ifdef HAVE_IO_URING_PREP_SEND_ZC
    ctx->caps.have_op_send_zc = send_zc_supported ? 1 : 0;
#endif /* ifdef HAVE_IO_URING_PREP_SEND_ZC */

#ifdef HAVE_IO_URING_RECVSEND_BUNDLE
    ctx->caps.have_recvsend_bundle = 1;
#endif /* ifdef HAVE_IO_URING_RECVSEND_BUNDLE */

#ifdef HAVE_IO_URING_RECVSEND_FIXED_BUF
    ctx->caps.have_recvsend_fixed_buf = 1;
#endif /* ifdef HAVE_IO_URING_RECVSEND_FIXED_BUF */

#ifdef HAVE_IO_URING_IOSQE_FIXED_FILE
    ctx->caps.have_iosqe_fixed_file = 1;
#endif /* ifdef HAVE_IO_URING_IOSQE_FIXED_FILE */

#ifdef HAVE_IO_URING_REGISTER_BUFFERS_SPARSE
    ctx->caps.have_register_buffers = 1;
#endif /* ifdef HAVE_IO_URING_REGISTER_BUFFERS_SPARSE */

#ifdef HAVE_IO_URING_REGISTER_FILES_SPARSE
    ctx->caps.have_register_files = 1;
#endif /* ifdef HAVE_IO_URING_REGISTER_FILES_SPARSE */
} /* evpl_io_uring_probe_caps */

static void
evpl_io_uring_resolve_effective(
    struct evpl_io_uring_context *ctx,
    int                           sqpoll_in_use)
{
    struct evpl_global_config *cfg = evpl_shared->config;

    /* FIXED_FILE */
    if (evpl_io_uring_mode_wants(cfg->io_uring_registered_files) &&
        ctx->caps.have_register_files && ctx->caps.have_iosqe_fixed_file) {
        ctx->effective.fixed_file = 1;
    } else if (evpl_io_uring_mode_required(cfg->io_uring_registered_files)) {
        evpl_io_uring_abort(
            "io_uring_registered_files=ON but kernel/liburing lacks support");
    }

    /* FIXED_BUF (registered buffers) */
    if (evpl_io_uring_mode_wants(cfg->io_uring_registered_buffers) &&
        ctx->caps.have_register_buffers && ctx->caps.have_recvsend_fixed_buf) {
        ctx->effective.fixed_buf = 1;
    } else if (evpl_io_uring_mode_required(cfg->io_uring_registered_buffers)) {
        evpl_io_uring_abort(
            "io_uring_registered_buffers=ON but kernel/liburing lacks support");
    }

    /* SEND_ZC.  Deliberately not taken on AUTO.  Measured on a 200GbE link it
    * does remove the payload copy, and the page zeroing behind it, but costs
    * more than it saves: each send pins its pages and maps them through the
    * IOMMU, and the completion is deferred until the NIC has finished with the
    * buffer.  With one send outstanding per socket that deferral stalls the
    * pipeline -- a single stream measured roughly half the throughput of the
    * copying path.  Making it pay wants several sends in flight and registered
    * buffers to pin once rather than per send, so until then it is opt-in. */
    if (evpl_io_uring_mode_required(cfg->io_uring_send_zc) &&
        ctx->caps.have_op_send_zc && ctx->effective.fixed_buf) {
        ctx->effective.send_zc = 1;
    } else if (evpl_io_uring_mode_required(cfg->io_uring_send_zc)) {
        evpl_io_uring_abort(
            "io_uring_send_zc=ON but kernel/liburing lacks support "
            "(or registered buffers are unavailable)");
    }

    /* RECV bundle */
    if (evpl_io_uring_mode_wants(cfg->io_uring_recv_bundle) &&
        ctx->caps.have_recvsend_bundle) {
        ctx->effective.recv_bundle = 1;
    } else if (evpl_io_uring_mode_required(cfg->io_uring_recv_bundle)) {
        evpl_io_uring_abort(
            "io_uring_recv_bundle=ON but kernel/liburing lacks support");
    }

    /* ZCRX — incompatible with SQPOLL, requires interface name */
    if (evpl_io_uring_mode_wants(cfg->io_uring_zerocopy_rx) &&
        ctx->caps.have_register_ifq && ctx->caps.have_op_recv_zc &&
        cfg->io_uring_zcrx_interface && !sqpoll_in_use) {
        ctx->effective.zcrx = 1;
    } else if (evpl_io_uring_mode_required(cfg->io_uring_zerocopy_rx)) {
        if (sqpoll_in_use) {
            evpl_io_uring_abort(
                "io_uring_zerocopy_rx=ON is incompatible with SQPOLL "
                "(ring was set up with SQPOLL)");
        }
        if (!cfg->io_uring_zcrx_interface) {
            evpl_io_uring_abort(
                "io_uring_zerocopy_rx=ON but no zcrx interface configured");
        }
        evpl_io_uring_abort(
            "io_uring_zerocopy_rx=ON but kernel/liburing lacks ZCRX support");
    }

    evpl_io_uring_info(
        "io_uring effective caps: fixed_file=%u fixed_buf=%u send_zc=%u recv_bundle=%u zcrx=%u",
        ctx->effective.fixed_file, ctx->effective.fixed_buf,
        ctx->effective.send_zc, ctx->effective.recv_bundle,
        ctx->effective.zcrx);
} /* evpl_io_uring_resolve_effective */

#ifdef HAVE_IO_URING_ZCRX
#include <linux/netlink.h>
#include <linux/genetlink.h>
#include <linux/netdev.h>

/* Ask the kernel which NAPI instance services receive queue rxq of if_idx,
 * through the generic-netlink "netdev" family (the same table
 * SO_INCOMING_NAPI_ID reports from).  Returns 0 if it cannot be learned,
 * in which case sockets cannot be matched to this ifq. */
static uint32_t
evpl_io_uring_rxq_napi_id(
    unsigned int if_idx,
    unsigned int rxq)
{
#ifdef NETDEV_FAMILY_NAME
    struct {
        struct nlmsghdr   nlh;
        struct genlmsghdr genl;
        char              attrs[256];
    } msg;
    struct sockaddr_nl sa = { .nl_family = AF_NETLINK };
    struct nlattr     *nla;
    struct nlmsghdr   *rh;
    char               rbuf[4096];
    uint16_t           family = 0;
    uint32_t           napi   = 0;
    uint32_t           v;
    int                fd, len, off, acked, rounds;

    fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_GENERIC);

    if (fd < 0) {
        evpl_io_uring_info("zcrx: netlink socket: %s", strerror(errno));
        return 0;
    }

#define EVPL_NLA_ADD(type, ptr, plen)                                        \
        do {                                                                    \
            nla           = (struct nlattr *) ((char *) &msg + msg.nlh.nlmsg_len); \
            nla->nla_type = (type);                                             \
            nla->nla_len  = NLA_HDRLEN + (plen);                                \
            memcpy((char *) nla + NLA_HDRLEN, (ptr), (plen));                   \
            msg.nlh.nlmsg_len += NLA_ALIGN(nla->nla_len);                       \
        } while (0)

    /* Every request is acknowledged separately from its reply, so each
     * exchange reads until the ACK arrives; otherwise the ACK of one request
     * is mistaken for the reply of the next. */

    /* 1. Resolve the family id of "netdev". */
    memset(&msg, 0, sizeof(msg));
    msg.nlh.nlmsg_len   = NLMSG_LENGTH(GENL_HDRLEN);
    msg.nlh.nlmsg_type  = GENL_ID_CTRL;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg.nlh.nlmsg_seq   = 1;
    msg.genl.cmd        = CTRL_CMD_GETFAMILY;
    msg.genl.version    = 1;
    EVPL_NLA_ADD(CTRL_ATTR_FAMILY_NAME, NETDEV_FAMILY_NAME,
                 (int) strlen(NETDEV_FAMILY_NAME) + 1);

    if (sendto(fd, &msg, msg.nlh.nlmsg_len, 0, (struct sockaddr *) &sa,
               sizeof(sa)) < 0) {
        evpl_io_uring_info("zcrx: genetlink family query: %s", strerror(errno));
        goto out;
    }

    for (acked = 0, rounds = 0; !acked && rounds < 8; rounds++) {
        len = recv(fd, rbuf, sizeof(rbuf), 0);

        for (rh = (struct nlmsghdr *) rbuf; len > 0 && NLMSG_OK(rh, (unsigned) len);
             rh = NLMSG_NEXT(rh, len)) {
            if (rh->nlmsg_type == NLMSG_ERROR) {
                acked = 1;
                continue;
            }
            if (rh->nlmsg_type != GENL_ID_CTRL) {
                continue;
            }
            off = NLMSG_HDRLEN + GENL_HDRLEN;
            while (off + (int) NLA_HDRLEN <= (int) rh->nlmsg_len) {
                nla = (struct nlattr *) ((char *) rh + off);
                if (nla->nla_len < NLA_HDRLEN) {
                    break;
                }
                if (nla->nla_type == CTRL_ATTR_FAMILY_ID) {
                    memcpy(&family, (char *) nla + NLA_HDRLEN, sizeof(family));
                }
                off += NLA_ALIGN(nla->nla_len);
            }
        }
    }

    if (!family) {
        evpl_io_uring_info("zcrx: genetlink family '%s' not found", NETDEV_FAMILY_NAME);
        goto out;
    }

    /* 2. Fetch the receive queue's attributes. */
    memset(&msg, 0, sizeof(msg));
    msg.nlh.nlmsg_len   = NLMSG_LENGTH(GENL_HDRLEN);
    msg.nlh.nlmsg_type  = family;
    msg.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
    msg.nlh.nlmsg_seq   = 2;
    msg.genl.cmd        = NETDEV_CMD_QUEUE_GET;
    msg.genl.version    = 1;
    v                   = if_idx;
    EVPL_NLA_ADD(NETDEV_A_QUEUE_IFINDEX, &v, sizeof(v));
    v = NETDEV_QUEUE_TYPE_RX;
    EVPL_NLA_ADD(NETDEV_A_QUEUE_TYPE, &v, sizeof(v));
    v = rxq;
    EVPL_NLA_ADD(NETDEV_A_QUEUE_ID, &v, sizeof(v));

    if (sendto(fd, &msg, msg.nlh.nlmsg_len, 0, (struct sockaddr *) &sa,
               sizeof(sa)) < 0) {
        evpl_io_uring_info("zcrx: netdev queue-get: %s", strerror(errno));
        goto out;
    }

    for (acked = 0, rounds = 0; !acked && rounds < 8; rounds++) {
        len = recv(fd, rbuf, sizeof(rbuf), 0);

        for (rh = (struct nlmsghdr *) rbuf; len > 0 && NLMSG_OK(rh, (unsigned) len);
             rh = NLMSG_NEXT(rh, len)) {
            if (rh->nlmsg_type == NLMSG_ERROR) {
                struct nlmsgerr *e = (struct nlmsgerr *) NLMSG_DATA(rh);

                if (e->error) {
                    evpl_io_uring_info("zcrx: netdev queue-get(if %u rxq %u): %s",
                                       if_idx, rxq, strerror(-e->error));
                }
                acked = 1;
                continue;
            }
            if (rh->nlmsg_type != family) {
                continue;
            }
            off = NLMSG_HDRLEN + GENL_HDRLEN;
            while (off + (int) NLA_HDRLEN <= (int) rh->nlmsg_len) {
                nla = (struct nlattr *) ((char *) rh + off);
                if (nla->nla_len < NLA_HDRLEN) {
                    break;
                }
                if (nla->nla_type == NETDEV_A_QUEUE_NAPI_ID) {
                    memcpy(&napi, (char *) nla + NLA_HDRLEN, sizeof(napi));
                }
                off += NLA_ALIGN(nla->nla_len);
            }
        }
    }

    if (!napi) {
        evpl_io_uring_info("zcrx: no NAPI id reported for if %u rxq %u", if_idx, rxq);
    }

#undef EVPL_NLA_ADD
 out:
    close(fd);
    return napi;
#else  /* ifdef NETDEV_FAMILY_NAME */
    (void) if_idx;
    (void) rxq;
    return 0;
#endif /* ifdef NETDEV_FAMILY_NAME */
} /* evpl_io_uring_rxq_napi_id */

static int
evpl_io_uring_zcrx_setup(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx,
    unsigned int                  rxq)
{
    struct evpl_global_config       *cfg = evpl_shared->config;
    struct evpl_io_uring_zcrx_state *z;
    struct io_uring_zcrx_ifq_reg     ifq_reg;
    struct io_uring_zcrx_area_reg    area_reg;
    struct io_uring_region_desc      region;
    size_t                           rq_ring_bytes;
    size_t                           area_bytes;
    unsigned int                     if_idx;
    int                              rc;

    if_idx = if_nametoindex(cfg->io_uring_zcrx_interface);
    if (if_idx == 0) {
        if (evpl_io_uring_mode_required(cfg->io_uring_zerocopy_rx)) {
            evpl_io_uring_abort(
                "io_uring_zerocopy_rx=ON: interface '%s' not found",
                cfg->io_uring_zcrx_interface);
        }
        evpl_io_uring_info("zcrx interface '%s' not found, falling back",
                           cfg->io_uring_zcrx_interface);
        return -1;
    }

    z = evpl_zalloc(sizeof(*z));

    area_bytes = cfg->io_uring_zcrx_area_size;
    if (area_bytes == 0) {
        area_bytes = 256 * 1024 * 1024;
    }
    area_bytes = (area_bytes + 4095) & ~((size_t) 4095);

    /* Every buffer in the area may be outstanding at once and is handed back
     * through the refill ring, which is only published once per poll loop.
     * If the area holds more buffers than the ring has entries, a burst of
     * releases can overwrite entries the kernel has not consumed yet, the
     * buffers are lost, the queue's page pool runs dry and packets drop
     * (seen as rx_buff_alloc_err / rx_pp_alloc_empty on mlx5 with 4 KB
     * buffers).  So size the ring to the buffer count, and shrink the area to
     * the kernel's ring limit when the buffers are small. */
    {
        size_t buf_len = cfg->io_uring_zcrx_rx_buf_len ? cfg->io_uring_zcrx_rx_buf_len : 4096;
        size_t nbuf    = area_bytes / buf_len;

        if (nbuf > 32768) {
            nbuf       = 32768;
            area_bytes = nbuf * buf_len;
            evpl_io_uring_info("zcrx: area capped at %zu MiB so its %zu buffers of %zu "
                               "bytes fit the refill ring", area_bytes >> 20, nbuf, buf_len);
        }

        z->rq_entries_wanted = (unsigned int) nbuf;
    }

    z->area_size = area_bytes;
    /* The kernel caps the receive buffer size at the smallest DMA segment of
     * this area, so a 4 KiB-backed mapping can never carry a buffer larger than
     * one page no matter what rx_buf_len asks for.  Try explicit huge pages
     * first, then fall back to an ordinary mapping with a transparent-huge-page
     * hint, then to plain pages. */
    z->area = MAP_FAILED;

    if ((area_bytes & ((2 * 1024 * 1024) - 1)) == 0) {
        z->area = mmap(NULL, area_bytes, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB |
                       MAP_HUGE_2MB, -1, 0);
        if (z->area != MAP_FAILED) {
            z->area_huge = 1;
        }
    }

    if (z->area == MAP_FAILED) {
        z->area = mmap(NULL, area_bytes, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

        if (z->area != MAP_FAILED) {
#ifdef MADV_HUGEPAGE
            /* Best effort; a refusal just means page-sized buffers. */
            (void) madvise(z->area, area_bytes, MADV_HUGEPAGE);
#endif /* ifdef MADV_HUGEPAGE */
            /* Fault the area in so the huge-page hint is applied before the
             * kernel pins it and builds the DMA scatterlist. */
            memset(z->area, 0, area_bytes);
        }
    }

    if (z->area == MAP_FAILED) {
        if (evpl_io_uring_mode_required(cfg->io_uring_zerocopy_rx)) {
            evpl_io_uring_abort("zcrx area mmap failed: %s", strerror(errno));
        }
        evpl_io_uring_info("zcrx area mmap failed: %s — falling back",
                           strerror(errno));
        evpl_free(z);
        return -1;
    }

    z->rq_entries = cfg->io_uring_zcrx_rq_entries;


    if (z->rq_entries < z->rq_entries_wanted) {


        z->rq_entries = z->rq_entries_wanted;


    }
    if (z->rq_entries == 0) {
        z->rq_entries = 4096;
    }

    /* Round rq_entries to a power of 2 (kernel requires this). */
    {
        unsigned int p = 1;
        while (p < z->rq_entries) {
            p <<= 1;
        }
        z->rq_entries = p;
    }
    z->rq_mask = z->rq_entries - 1;

    rq_ring_bytes = z->rq_entries * sizeof(struct io_uring_zcrx_rqe) +
        2 * sizeof(uint32_t);
    rq_ring_bytes = (rq_ring_bytes + 4095) & ~((size_t) 4095);

    z->rq_ring_size = rq_ring_bytes;
    z->rq_ring      = mmap(NULL, rq_ring_bytes, PROT_READ | PROT_WRITE,
                           MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (z->rq_ring == MAP_FAILED) {
        if (evpl_io_uring_mode_required(cfg->io_uring_zerocopy_rx)) {
            evpl_io_uring_abort("zcrx rq region mmap failed: %s",
                                strerror(errno));
        }
        munmap(z->area, z->area_size);
        evpl_free(z);
        return -1;
    }

    memset(&area_reg, 0, sizeof(area_reg));
    area_reg.addr = (uintptr_t) z->area;
    area_reg.len  = z->area_size;
    /* Kernel UAPI adds enum zcrx_reg_flags { ZCRX_REG_IMPORT = 1 }. Some
     * driver paths only accept a user-supplied area when this flag is set;
     * older kernels treat the flags field as reserved and ignore unknown
     * bits, so setting it is safe to do unconditionally on a kernel that
     * supports IORING_OP_RECV_ZC.
     */
    if (cfg->io_uring_zcrx_area_import) {
        area_reg.flags = 1; /* ZCRX_REG_IMPORT */
    }

    memset(&region, 0, sizeof(region));
    region.user_addr = (uintptr_t) z->rq_ring;
    region.size      = z->rq_ring_size;
    region.flags     = IORING_MEM_REGION_TYPE_USER;

    memset(&ifq_reg, 0, sizeof(ifq_reg));
    ifq_reg.if_idx     = if_idx;
    ifq_reg.if_rxq     = rxq;
    ifq_reg.rq_entries = z->rq_entries;
    ifq_reg.area_ptr   = (uintptr_t) &area_reg;
    ifq_reg.region_ptr = (uintptr_t) &region;

    /* The trailing __resv2 slot in io_uring_zcrx_ifq_reg was renamed to
     * rx_buf_len on kernels that landed ZCRX_FEATURE_RX_PAGE_SIZE. Field
     * semantics:
     *   rx_buf_len == 0  -> let the driver pick (PAGE_SIZE by default).
     *                       Required on drivers that don't yet advertise
     *                       QCFG_RX_PAGE_SIZE (e.g. mlx5 v7.0); a non-zero
     *                       value there is rejected with -EOPNOTSUPP
     *                       "device does not support: rx_page_size".
     *   rx_buf_len != 0  -> request a specific page size. Driver must
     *                       advertise QCFG_RX_PAGE_SIZE.
     * Default behaviour: pass through whatever the user configured
     * (default 0). The installed liburing header may still call this
     * field __resv2; byte layout is identical either way.
     */
    ifq_reg.__resv2 = cfg->io_uring_zcrx_rx_buf_len;

    rc = io_uring_register_ifq(&ctx->ring, &ifq_reg);

    if (rc < 0) {
        /* -EEXIST means another io_uring ring in this process has already
         * registered an ifq on this rxq (kernel allows only one memory
         * provider per queue). This is expected in libevpl's multi-ring
         * model: the listener thread's ring gets the ZCRX page-pool first,
         * and subsequent per-thread rings (workers) hit EEXIST. Treat that
         * as "ZCRX already established for this queue" and downgrade THIS
         * ring's recv path to non-ZC, even when zerocopy_rx=ON. Packets
         * still land in the ZCRX area; the kernel falls back to
         * io_zcrx_copy_chunk for non-ZC consumers — data flows, just not
         * zero-copy on this ring.
         */
        if (rc != -EEXIST &&
            evpl_io_uring_mode_required(cfg->io_uring_zerocopy_rx)) {
            evpl_io_uring_abort(
                "io_uring_register_ifq(if=%s rxq=%u) failed: %s",
                cfg->io_uring_zcrx_interface, rxq,
                strerror(-rc));
        }
        evpl_io_uring_info(
            "io_uring_register_ifq failed: %s%s",
            strerror(-rc),
            rc == -EEXIST
              ? " (queue already has a ZCRX ifq — using non-ZC recv on this ring)"
              : " — falling back");
        munmap(z->rq_ring, z->rq_ring_size);
        munmap(z->area, z->area_size);
        evpl_free(z);
        return -1;
    }

    /* On success the kernel writes back the receive buffer size it settled on,
     * in the same slot rx_buf_len was passed in. */
    z->rx_buf_len = ifq_reg.__resv2;

    z->zcrx_id  = ifq_reg.zcrx_id;
    z->rq_khead = (uint32_t *) ((char *) z->rq_ring + ifq_reg.offsets.head);
    z->rq_ktail = (uint32_t *) ((char *) z->rq_ring + ifq_reg.offsets.tail);
    z->rq_rqes  = (struct io_uring_zcrx_rqe *)
        ((char *) z->rq_ring + ifq_reg.offsets.rqes);

    /* tail_cached starts where the kernel's tail starts (0 after fresh
     * register); frag releases bump it locally and a single
     * release-store at poll-loop end publishes it.
     */
    z->tail_cached = atomic_load_explicit(
        (_Atomic uint32_t *) z->rq_ktail, memory_order_relaxed);

    z->rxq     = rxq;
    z->napi_id = evpl_io_uring_rxq_napi_id(if_idx, rxq);

    if (ctx->num_zcrx >= EVPL_IO_URING_ZCRX_MAX_IFQ) {
        evpl_io_uring_abort("too many zcrx ifqs on one ring (max %d)",
                            EVPL_IO_URING_ZCRX_MAX_IFQ);
    }

    ctx->zcrx[ctx->num_zcrx++] = z;

    /* DEFER_TASKRUN only runs completion task work when this thread enters the
     * ring, so the loop must not fall back to sleeping on the eventfd. */
    if (ctx->num_zcrx == 1) {
        evpl_poll_pin(evpl);
    }

    evpl_io_uring_info(
        "zcrx registered: if=%s if_idx=%u rxq=%u napi_id=%u rq_entries=%u "
        "zcrx_id=%u area=%zu MiB (%s pages) rx_buf_len=%u",
        cfg->io_uring_zcrx_interface, if_idx, rxq, z->napi_id,
        z->rq_entries, z->zcrx_id, z->area_size >> 20,
        z->area_huge ? "huge" : "normal", z->rx_buf_len);

    return 0;
} /* evpl_io_uring_zcrx_setup */

static void
evpl_io_uring_zcrx_teardown(
    struct evpl                  *evpl,
    struct evpl_io_uring_context *ctx)
{
    struct evpl_io_uring_zcrx_state *z;
    int                              zi;

    if (ctx->num_zcrx == 0) {
        return;
    }

    evpl_poll_unpin(evpl);

    if (ctx->stat_zcrx_unmatched) {
        evpl_io_uring_info(
            "zcrx: %lu sockets arrived on a queue without an ifq and were "
            "received through the first ifq by copy",
            (unsigned long) ctx->stat_zcrx_unmatched);
    }

    for (zi = 0; zi < ctx->num_zcrx; zi++) {
        z = ctx->zcrx[zi];

        if (z->stat_frags) {
            evpl_io_uring_info(
                "zcrx rxq %u stats: %lu completions, %lu bytes, %lu "
                "bytes/completion (rx_buf_len=%u)",
                z->rxq, (unsigned long) z->stat_frags,
                (unsigned long) z->stat_bytes,
                (unsigned long) (z->stat_bytes / z->stat_frags), z->rx_buf_len);
        }

        if (z->rq_ring && z->rq_ring != MAP_FAILED) {
            munmap(z->rq_ring, z->rq_ring_size);
        }

        if (z->area && z->area != MAP_FAILED) {
            munmap(z->area, z->area_size);
        }

        evpl_free(z);
        ctx->zcrx[zi] = NULL;
    }

    ctx->num_zcrx = 0;
} /* evpl_io_uring_zcrx_teardown */
#endif /* HAVE_IO_URING_ZCRX */

static void *
evpl_io_uring_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_global_config    *cfg = evpl_shared->config;
    struct evpl_io_uring_context *ctx;
    int                           ret;
    struct io_uring_params        params;
    int                           sqpoll_in_use;

    (void) private_data;

    evpl_io_uring_params(&params);

    /* evpl_io_uring_params() drops SQPOLL when ZCRX is wanted, so ask the
     * parameters themselves rather than re-deriving the decision here. */
    sqpoll_in_use = (params.flags & IORING_SETUP_SQPOLL) != 0;

    ctx = evpl_zalloc(sizeof(*ctx));

    ctx->next_send_group_id = EVPL_IO_URING_BUFGROUP_ID + 1;

    ret = io_uring_queue_init_params(cfg->io_uring_entries, &ctx->ring,
                                     &params);

    evpl_io_uring_abort_if(ret < 0,
                           "io_uring_queue_init_params() failed: %s (%d)",
                           strerror(-ret), ret);

    /* Register the ring fd so subsequent io_uring_enter calls skip the
     * per-syscall fget on the ring fd. With DEFER_TASKRUN we enter the
     * kernel every poll-loop turn to drive task work, so fget shows up
     * as multiple percent of the per-CPU profile under load. Cheap to
     * set up; ignored on kernels too old to support it.
     */
    (void) io_uring_register_ring_fd(&ctx->ring);

    evpl_io_uring_probe_caps(ctx);
    evpl_io_uring_resolve_effective(ctx, sqpoll_in_use);

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

#ifdef HAVE_IO_URING_REGISTER_FILES_SPARSE
    if (ctx->effective.fixed_file) {
        ctx->direct_fd_count = EVPL_IO_URING_MAX_REGISTERED_FILES;
        ret                  = io_uring_register_files_sparse(&ctx->ring,
                                                              ctx->direct_fd_count);
        if (ret < 0) {
            evpl_io_uring_info(
                "io_uring_register_files_sparse(%u) failed: %s — disabling fixed_file",
                ctx->direct_fd_count, strerror(-ret));
            ctx->effective.fixed_file = 0;
            ctx->direct_fd_count      = 0;
        } else {
            unsigned int i;
            ctx->direct_fd_slot = evpl_zalloc(ctx->direct_fd_count *
                                              sizeof(int));
            ctx->direct_fd_free = evpl_zalloc(ctx->direct_fd_count *
                                              sizeof(int));
            for (i = 0; i < ctx->direct_fd_count; i++) {
                ctx->direct_fd_slot[i] = -1;
                ctx->direct_fd_free[i] = (int) (ctx->direct_fd_count - 1 - i);
            }
            ctx->direct_fd_free_top = ctx->direct_fd_count;
        }
    }
#endif /* ifdef HAVE_IO_URING_REGISTER_FILES_SPARSE */

#ifdef HAVE_IO_URING_REGISTER_BUFFERS_SPARSE
    if (ctx->effective.fixed_buf) {
        ret = io_uring_register_buffers_sparse(
            &ctx->ring, EVPL_IO_URING_MAX_REGISTERED_BUFFERS);
        if (ret < 0) {
            evpl_io_uring_info(
                "io_uring_register_buffers_sparse(%u) failed: %s — disabling fixed_buf",
                EVPL_IO_URING_MAX_REGISTERED_BUFFERS, strerror(-ret));
            ctx->effective.fixed_buf = 0;
            ctx->effective.send_zc   = 0;
        }
        /* Do NOT bulk-sync existing slabs here: each slab is up to slab_size
         * bytes (default 1 GiB) and io_uring_register_buffers_update_tag pins
         * those pages synchronously. Pinning many slabs at ctx-create time
         * can block the worker thread long enough to miss its first accept.
         * Instead, sync registers ONE slab per call from the pump/complete
         * paths; iov_to_fixed checks ctx->buf_high_water and the pump falls
         * back to the legacy provided-buffer-ring path for any iov whose
         * slab has not yet been registered on this ring.
         */
    }
#endif /* ifdef HAVE_IO_URING_REGISTER_BUFFERS_SPARSE */

#ifdef HAVE_IO_URING_ZCRX
    if (ctx->effective.zcrx) {
        /* Pick the rxq this ctx should own:
         *   - zcrx_rxq_override (set by listen_distributed handoff to a
         *     specific worker) takes precedence — that's the per-worker
         *     queue assignment from the protocol's listen_distributed.
         *   - Otherwise fall back to the single global rxq config; this
         *     is the centralized / single-thread path that pre-dates
         *     distributed listen.
         *   - If neither applies (override == 0 AND distributed listen
         *     is in use), skip setup so the listener thread's ctx does
         *     not claim the queue's ifq first.
         */
        unsigned int my_rxq = evpl->zcrx_rxq_override;

        evpl_io_uring_info("zcrx: config rxq=%u rxq_count=%u ifq_count=%u override=%u",
                           cfg->io_uring_zcrx_rxq, cfg->io_uring_zcrx_rxq_count,
                           cfg->io_uring_zcrx_ifq_count, evpl->zcrx_rxq_override);

        if (my_rxq == 0 && cfg->io_uring_zcrx_rxq_count <= 1) {
            my_rxq = cfg->io_uring_zcrx_rxq;
        }
        if (my_rxq == 0 && evpl->zcrx_rxq_override == 0 &&
            cfg->io_uring_zcrx_rxq_count > 1) {
            /* Distributed mode; this ctx wasn't handed an rxq.
             * Don't claim one — workers' own ctxs will register their
             * assigned queues.
             */
            ctx->effective.zcrx = 0;
        } else if (evpl_io_uring_zcrx_setup(evpl, ctx, my_rxq) < 0) {
            ctx->effective.zcrx = 0;
        } else {
            /* Several queues on one thread: each further consecutive queue
             * gets its own ifq (the listen handoff only names the first);
             * if one cannot be registered, carry on with the ones that were. */
            unsigned int i;

            for (i = 1; i < cfg->io_uring_zcrx_ifq_count; i++) {
                if (evpl_io_uring_zcrx_setup(evpl, ctx, my_rxq + i) < 0) {
                    evpl_io_uring_info("zcrx: stopping after %d ifq(s)",
                                       ctx->num_zcrx);
                    break;
                }
            }
        }
    }
#endif /* ifdef HAVE_IO_URING_ZCRX */

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
    int                           i;
    int                           drains;

    /* Drain any in-flight completions so their requests can be reclaimed
     * before we tear the ring down. The bind/socket objects may have
     * already been freed by evpl_destroy, so we must NOT invoke the
     * per-request callbacks; just sweep CQEs and free reqs directly.
     */
    for (drains = 0; drains < 64; drains++) {
        struct io_uring_cqe     *cqes[64];
        struct __kernel_timespec ts = { .tv_sec  = 0,
                                        .tv_nsec = 50 * 1000 * 1000 };
        int                      cq;

        io_uring_submit(&ctx->ring);

        cq = io_uring_peek_batch_cqe(&ctx->ring, cqes, 64);

        if (cq == 0) {
            struct io_uring_cqe *cqe = NULL;
            int                  rc  = io_uring_wait_cqe_timeout(&ctx->ring, &cqe, &ts);
            if (rc < 0) {
                break;
            }
            cq = io_uring_peek_batch_cqe(&ctx->ring, cqes, 64);
        }

        for (int i = 0; i < cq; i++) {
            struct evpl_io_uring_request *r =
                (struct evpl_io_uring_request *) io_uring_cqe_get_data64(cqes[i]);
            if (!r) {
                continue;
            }
            /* Release iov on terminal CQEs for FIXED_BUF / SEND_ZC sends —
             * normally done in the send_callback, but during shutdown we
             * bypass the callback (the bind/socket may already be freed).
             */
            if (r->req_type == EVPL_IO_URING_REQ_TCP &&
                !(cqes[i]->flags & IORING_CQE_F_MORE) &&
                (r->tcp.use_fixed_buf || r->tcp.is_send_zc) &&
                r->tcp.send_iov.data != NULL) {
                evpl_iovec_release(evpl, &r->tcp.send_iov);
            }
            if (!(cqes[i]->flags & IORING_CQE_F_MORE)) {
                evpl_io_uring_request_free(ctx, r);
            }
        }

        io_uring_cq_advance(&ctx->ring, cq);
    }

    if (ctx->stat_zc_sends) {
        evpl_io_uring_info(
            "zero-copy send batching: %lu sends, %lu iovecs (%.1f per send), "
            "%lu bytes (%.2f MB per send)",
            (unsigned long) ctx->stat_zc_sends,
            (unsigned long) ctx->stat_zc_iovs,
            (double) ctx->stat_zc_iovs / ctx->stat_zc_sends,
            (unsigned long) ctx->stat_zc_bytes,
            (double) ctx->stat_zc_bytes / ctx->stat_zc_sends / 1000000.0);
    }

    if (ctx->stat_zc_notifs) {
        evpl_io_uring_info(
            "zero-copy send: %lu notifications, %lu reported a copy fallback",
            (unsigned long) ctx->stat_zc_notifs,
            (unsigned long) ctx->stat_zc_copied);
    }

    while (ctx->free_requests) {
        req = ctx->free_requests;
        LL_DELETE(ctx->free_requests, req);
        evpl_free(req);
    }

    if (ctx->recv_ring) {
        io_uring_free_buf_ring(&ctx->ring, ctx->recv_ring, ctx->recv_ring_size,
                               EVPL_IO_URING_BUFGROUP_ID);
    }

#ifdef HAVE_IO_URING_ZCRX
    evpl_io_uring_zcrx_teardown(evpl, ctx);
#endif /* ifdef HAVE_IO_URING_ZCRX */

    if (ctx->direct_fd_slot) {
        evpl_free(ctx->direct_fd_slot);
    }
    if (ctx->direct_fd_free) {
        evpl_free(ctx->direct_fd_free);
    }

    io_uring_queue_exit(&ctx->ring);

    close(ctx->eventfd);

    /* Empty slots have transferred their reference to a socket's receive
     * queue. Release only buffers still owned by the provided-buffer ring. */
    for (i = 0; i < ctx->recv_ring_size; i++) {
        if (!(ctx->recv_ring_iov_empty[i >> 6] & (1ULL << (i & 63)))) {
            evpl_iovecs_release_internal(evpl, &ctx->recv_ring_iov[i], 1);
        }
    }

    evpl_free(ctx->recv_ring_iov_empty);
    evpl_free(ctx->recv_ring_iov);
    evpl_free(ctx->deliver_iov);

    evpl_free(ctx);
} /* evpl_io_uring_destroy */

struct evpl_framework evpl_framework_io_uring = {
    .id                = EVPL_FRAMEWORK_IO_URING,
    .name              = "IO_URING",
    .init              = evpl_io_uring_init,
    .cleanup           = evpl_io_uring_cleanup,
    .create            = evpl_io_uring_create,
    .destroy           = evpl_io_uring_destroy,
    .register_memory   = evpl_io_uring_register_memory,
    .unregister_memory = evpl_io_uring_unregister_memory,
};
