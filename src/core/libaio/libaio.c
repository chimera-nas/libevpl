// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <errno.h>
#include <string.h>
#include <sys/eventfd.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "libaio_internal.h"

#include "core/evpl_shared.h"
#include "core/libaio/libaio.h"
#include "core/poll.h"

static void
evpl_libaio_flush_submit(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_libaio_context *ctx = private_data;
    int                         rc;

    (void) evpl;

    if (ctx->num_pending == 0) {
        return;
    }

    do {
        rc = io_submit(ctx->io_ctx, ctx->num_pending, ctx->pending_iocbs);
    } while (rc == -EINTR);

    /* Ring saturated by in-flight requests: nothing accepted this round.
     * Leave the iocbs queued; a completion frees ring slots and re-arms this
     * flush (see evpl_libaio_complete), so the remainder goes out on a later
     * event-loop iteration rather than spinning here. */
    if (rc == -EAGAIN) {
        rc = 0;
    }

    evpl_libaio_abort_if(rc < 0, "io_submit failed: %d", rc);

    /* io_submit() accepts iocbs one at a time and may take fewer than
     * requested (a short submit) under load.  Keep the unsubmitted tail for a
     * later attempt rather than dropping it -- a dropped iocb never completes,
     * so its callback never runs and the caller hangs forever. */
    if (rc < ctx->num_pending) {
        ctx->num_pending -= rc;
        memmove(ctx->pending_iocbs, &ctx->pending_iocbs[rc],
                ctx->num_pending * sizeof(ctx->pending_iocbs[0]));
    } else {
        ctx->num_pending = 0;
    }
} /* evpl_libaio_flush_submit */

static void *
evpl_libaio_init(void)
{
    /* libaio does not need global shared state, but the framework
     * pattern requires a non-NULL return to indicate success */
    return (void *) 1;
} /* evpl_libaio_init */

static void
evpl_libaio_cleanup(void *private_data)
{
    /* Nothing to clean up for global state */
} /* evpl_libaio_cleanup */

static inline int
evpl_libaio_complete(
    struct evpl                *evpl,
    struct evpl_libaio_context *ctx)
{
    struct io_event             events[64];
    struct evpl_libaio_request *req;
    struct timespec             timeout = { 0, 0 };
    int                         n, i;
    uint64_t                    debounce_offset;

    n = io_getevents(ctx->io_ctx, 0, 64, events, &timeout);

    if (n <= 0) {
        return 0;
    }

    for (i = 0; i < n; i++) {
        req = (struct evpl_libaio_request *) events[i].data;

        req->res = events[i].res;

        if (req->res < 0) {
            evpl_libaio_error("libaio complete res %ld", events[i].res);
        }

        if (req->need_debounce) {
            debounce_offset = 0;

            for (int j = 0; j < req->niov; j++) {
                memcpy(req->iov[j].iov_base, req->bounce + debounce_offset,
                       req->iov[j].iov_len);
                debounce_offset += req->iov[j].iov_len;
            }
        }

        {
            int rc;

            if (req->res < 0) {
                rc = -req->res;
            } else if (req->res != req->length) {
                rc = EIO;
            } else {
                rc = 0;
            }

            req->callback(evpl, rc, req->private_data);
        }

        if (req->bounce) {
            evpl_free(req->bounce);
        }

        evpl_libaio_request_free(ctx, req);
    }

    if (n) {
        evpl_activity(evpl);

        /* Reaping freed ring slots: resubmit any iocbs that hit backpressure
        * on an earlier flush.  Gating the re-arm on n > 0 means we only retry
        * after a completion actually made room, so this never busy-spins. */
        if (ctx->num_pending) {
            evpl_defer(evpl, &ctx->flush);
        }
    }

    return n;
} /* evpl_libaio_complete */

static void
evpl_libaio_poll_enter(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_libaio_complete(evpl, private_data);
} /* evpl_libaio_poll_enter */

static void
evpl_libaio_poll_exit(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_libaio_complete(evpl, private_data);
} /* evpl_libaio_poll_exit */

static void
evpl_libaio_poll(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_libaio_complete(evpl, private_data);
} /* evpl_libaio_poll */

static void
evpl_libaio_complete_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_libaio_context *ctx = evpl_framework_private(evpl, EVPL_FRAMEWORK_LIBAIO);
    uint64_t                    value;
    int                         rc, n;

    do {
        rc = read(ctx->eventfd, &value, sizeof(value));
    } while (rc < 0 && errno == EINTR);

    if (rc != sizeof(value)) {
        evpl_event_mark_unreadable(evpl, &ctx->event);
        return;
    }

    do {
        n = evpl_libaio_complete(evpl, ctx);
    } while (n);
} /* evpl_libaio_complete_event */

static void *
evpl_libaio_create(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_libaio_context *ctx;
    int                         rc;

    ctx = evpl_zalloc(sizeof(*ctx));

    ctx->max_pending   = evpl_shared->config->libaio_max_pending;
    ctx->pending_iocbs = evpl_zalloc(ctx->max_pending * sizeof(struct iocb *));

    memset(&ctx->io_ctx, 0, sizeof(ctx->io_ctx));

    rc = io_setup(ctx->max_pending, &ctx->io_ctx);

    evpl_libaio_abort_if(rc < 0, "io_setup failed: %d", rc);

    ctx->eventfd = eventfd(0, EFD_NONBLOCK);

    evpl_libaio_abort_if(ctx->eventfd < 0, "eventfd");

    evpl_add_event(evpl, &ctx->event, ctx->eventfd,
                   evpl_libaio_complete_event, NULL, NULL);

    evpl_event_read_interest(evpl, &ctx->event);

    evpl_deferral_init(&ctx->flush, evpl_libaio_flush_submit, ctx);

    ctx->num_pending = 0;

    ctx->poll = evpl_add_poll(evpl, evpl_libaio_poll_enter, evpl_libaio_poll_exit, evpl_libaio_poll, ctx);

    return ctx;
} /* evpl_libaio_create */

static void
evpl_libaio_destroy(
    struct evpl *evpl,
    void        *private_data)
{
    struct evpl_libaio_context *ctx = private_data;
    struct evpl_libaio_request *req;

    while (ctx->free_requests) {
        req = ctx->free_requests;
        LL_DELETE(ctx->free_requests, req);
        evpl_free(req);
    }

    io_destroy(ctx->io_ctx);

    close(ctx->eventfd);

    evpl_free(ctx->pending_iocbs);
    evpl_free(ctx);
} /* evpl_libaio_destroy */

struct evpl_framework evpl_framework_libaio = {
    .id      = EVPL_FRAMEWORK_LIBAIO,
    .name    = "LIBAIO",
    .init    = evpl_libaio_init,
    .cleanup = evpl_libaio_cleanup,
    .create  = evpl_libaio_create,
    .destroy = evpl_libaio_destroy,
};
