// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE
#include <string.h>
#include <errno.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <stdatomic.h>
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

    unsigned int                  flags = atomic_load_explicit((_Atomic unsigned int *) &ctx->ring.flags,
                                                               memory_order_relaxed);

    if (flags & IORING_SQ_NEED_WAKEUP) {
        io_uring_enter(ctx->ring.ring_fd, 0, 0, IORING_ENTER_SQ_WAKEUP, NULL);
        evpl_io_uring_info("had to wake up the kernel sqpoll thread");
    }

    io_uring_submit(&ctx->ring);
} /* evpl_io_uring_flush */


static void *
evpl_io_uring_init(void)
{
    struct evpl_io_uring_shared *shared;
    struct io_uring_params       params;
    struct rlimit                rlim;
    int                          rc;

    memset(&params, 0, sizeof(params));

    params.flags         |= IORING_SETUP_SQPOLL;
    params.sq_thread_idle = 1000;

    /* Try to bump RLIMIT_MEMLOCK to RLIM_INFINITY so that
     * io_uring_register_buffers can pin enough pages for our slabs.
     * Older kernels enforce MEMLOCK on registered buffers; newer ones
     * (6.2+) only enforce when the caller lacks CAP_IPC_LOCK. Either way,
     * raising the limit is safe — if we lack the privilege the syscall
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

    shared = evpl_zalloc(sizeof(*shared));

    pthread_mutex_init(&shared->buf_lock, NULL);
    shared->buf_count = 0;

    rc = io_uring_queue_init_params(256, &shared->ring, &params);

    if (rc < 0) {
        pthread_mutex_destroy(&shared->buf_lock);
        evpl_free(shared);
        return NULL;
    }

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

    pthread_mutex_lock(&shared->buf_lock);

    if (shared->buf_count >= EVPL_IO_URING_MAX_REGISTERED_BUFFERS) {
        pthread_mutex_unlock(&shared->buf_lock);
        evpl_io_uring_info(
            "registered buffer table full (%u entries), slab will not be fixed-buf eligible",
            shared->buf_count);
        return NULL;
    }

    shared->buf_slabs[shared->buf_count].addr = buffer;
    shared->buf_slabs[shared->buf_count].len  = size;
    idx_plus_one                              = (uintptr_t) (shared->buf_count + 1);
    shared->buf_count++;

    pthread_mutex_unlock(&shared->buf_lock);

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

    io_uring_queue_exit(&shared->ring);

    pthread_mutex_destroy(&shared->buf_lock);

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
    struct io_uring_cqe          *cqes[64], *cqe;

    cq_count = io_uring_peek_batch_cqe(&ctx->ring, cqes, 64);

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

    io_uring_unregister_eventfd(&ctx->ring);
    evpl_io_uring_complete(evpl, ctx);
} /* evpl_io_uring_poll_enter */

static void
evpl_io_uring_poll_exit(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_io_uring_context *ctx = private_data;

    io_uring_register_eventfd(&ctx->ring, ctx->eventfd);
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

    rc = read(ctx->eventfd, &value, sizeof(value));

    if (rc != sizeof(value)) {
        evpl_event_mark_unreadable(evpl, &ctx->event);
        return;
    }

    do {
        n = evpl_io_uring_complete(evpl, ctx);
    } while (n);
} /* evpl_io_uring_complete */

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

static void
evpl_io_uring_probe_caps(struct evpl_io_uring_context *ctx)
{
    struct io_uring_probe *probe;
    unsigned int           recv_zc_supported = 0;
    unsigned int           send_zc_supported = 0;

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

    /* SEND_ZC — requires fixed_buf */
    if (evpl_io_uring_mode_wants(cfg->io_uring_send_zc) &&
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
static int
evpl_io_uring_zcrx_setup(struct evpl_io_uring_context *ctx)
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

    z->area_size = area_bytes;
    z->area      = mmap(NULL, area_bytes, PROT_READ | PROT_WRITE,
                        MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

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

    memset(&region, 0, sizeof(region));
    region.user_addr = (uintptr_t) z->rq_ring;
    region.size      = z->rq_ring_size;
    region.flags     = IORING_MEM_REGION_TYPE_USER;

    memset(&ifq_reg, 0, sizeof(ifq_reg));
    ifq_reg.if_idx     = if_idx;
    ifq_reg.if_rxq     = cfg->io_uring_zcrx_rxq;
    ifq_reg.rq_entries = z->rq_entries;
    ifq_reg.area_ptr   = (uintptr_t) &area_reg;
    ifq_reg.region_ptr = (uintptr_t) &region;

    rc = io_uring_register_ifq(&ctx->ring, &ifq_reg);

    if (rc < 0) {
        if (evpl_io_uring_mode_required(cfg->io_uring_zerocopy_rx)) {
            evpl_io_uring_abort(
                "io_uring_register_ifq(if=%s rxq=%u) failed: %s",
                cfg->io_uring_zcrx_interface, cfg->io_uring_zcrx_rxq,
                strerror(-rc));
        }
        evpl_io_uring_info(
            "io_uring_register_ifq failed: %s — falling back",
            strerror(-rc));
        munmap(z->rq_ring, z->rq_ring_size);
        munmap(z->area, z->area_size);
        evpl_free(z);
        return -1;
    }

    z->zcrx_id  = ifq_reg.zcrx_id;
    z->rq_khead = (uint32_t *) ((char *) z->rq_ring + ifq_reg.offsets.head);
    z->rq_ktail = (uint32_t *) ((char *) z->rq_ring + ifq_reg.offsets.tail);
    z->rq_rqes  = (struct io_uring_zcrx_rqe *)
        ((char *) z->rq_ring + ifq_reg.offsets.rqes);

    ctx->zcrx = z;

    evpl_io_uring_info(
        "zcrx registered: if=%s if_idx=%u rxq=%u rq_entries=%u zcrx_id=%u area=%zu MiB",
        cfg->io_uring_zcrx_interface, if_idx, cfg->io_uring_zcrx_rxq,
        z->rq_entries, z->zcrx_id, z->area_size >> 20);

    return 0;
} /* evpl_io_uring_zcrx_setup */

static void
evpl_io_uring_zcrx_teardown(struct evpl_io_uring_context *ctx)
{
    struct evpl_io_uring_zcrx_state *z = ctx->zcrx;

    if (!z) {
        return;
    }

    if (z->rq_ring && z->rq_ring != MAP_FAILED) {
        munmap(z->rq_ring, z->rq_ring_size);
    }
    if (z->area && z->area != MAP_FAILED) {
        munmap(z->area, z->area_size);
    }

    evpl_free(z);
    ctx->zcrx = NULL;
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
    int                           want_zcrx;

    /* If zcrx is wanted (ON or AUTO with a configured interface), drop SQPOLL
     * — zcrx is incompatible with SQPOLL.
     */
    want_zcrx = evpl_io_uring_mode_wants(cfg->io_uring_zerocopy_rx) &&
        cfg->io_uring_zcrx_interface != NULL;
#ifndef HAVE_IO_URING_ZCRX
    want_zcrx = 0;
#endif /* ifndef HAVE_IO_URING_ZCRX */
    sqpoll_in_use = want_zcrx ? 0 : 1;

    memset(&params, 0, sizeof(params));

    params.flags = IORING_SETUP_SINGLE_ISSUER | IORING_SETUP_SQE128 |
        IORING_SETUP_CQE32;

    if (sqpoll_in_use) {
        params.flags         |= IORING_SETUP_SQPOLL;
        params.sq_thread_idle = 1000;
    } else {
        params.flags |= IORING_SETUP_DEFER_TASKRUN;
    }

    ctx = evpl_zalloc(sizeof(*ctx));

    ctx->next_send_group_id = EVPL_IO_URING_BUFGROUP_ID + 1;

    ret = io_uring_queue_init_params(cfg->io_uring_entries, &ctx->ring,
                                     &params);

    evpl_io_uring_abort_if(ret < 0,
                           "io_uring_queue_init_params() failed: %s (%d)",
                           strerror(-ret), ret);

    evpl_io_uring_probe_caps(ctx);
    evpl_io_uring_resolve_effective(ctx, sqpoll_in_use);

    ctx->eventfd = eventfd(0, EFD_NONBLOCK);

    evpl_io_uring_abort_if(ctx->eventfd < 0, "eventfd");

    io_uring_register_eventfd(&ctx->ring, ctx->eventfd);

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

    ctx->recv_ring_iov_empty = evpl_zalloc((ctx->recv_ring_size / 64) *
                                           sizeof(uint64_t));
    memset(ctx->recv_ring_iov_empty, 0xff,
           (ctx->recv_ring_size / 64) * sizeof(uint64_t));

    ctx->recv_ring_iov = evpl_zalloc(ctx->recv_ring_size *
                                     sizeof(struct evpl_iovec));

    evpl_io_uring_abort_if(ret < 0, "io_uring_setup_buf_ring");

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
        if (evpl_io_uring_zcrx_setup(ctx) < 0) {
            ctx->effective.zcrx = 0;
        }
    }
#endif /* ifdef HAVE_IO_URING_ZCRX */

    ctx->poll = evpl_add_poll(evpl, evpl_io_uring_poll_enter,
                              evpl_io_uring_poll_exit,
                              evpl_io_uring_poll, ctx);

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

#ifdef HAVE_IO_URING_ZCRX
    evpl_io_uring_zcrx_teardown(ctx);
#endif /* ifdef HAVE_IO_URING_ZCRX */

    if (ctx->direct_fd_slot) {
        evpl_free(ctx->direct_fd_slot);
    }
    if (ctx->direct_fd_free) {
        evpl_free(ctx->direct_fd_free);
    }

    io_uring_queue_exit(&ctx->ring);

    close(ctx->eventfd);

    evpl_iovecs_release(evpl, ctx->recv_ring_iov, ctx->recv_ring_size);

    evpl_free(ctx->recv_ring_iov_empty);
    evpl_free(ctx->recv_ring_iov);

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