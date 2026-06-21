// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <complex.h>
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <utlist.h>
#include <uthash.h>

#include "core/evpl.h"
#include "evpl/evpl_rpc2.h"
#include "evpl/evpl_rpc2_gss.h"
#include "evpl/evpl_rdma.h"

#include "rpc2/common.h"
#include "rpc2_xdr.h"
#include "rpcrdma1_xdr.h"
#include "evpl/evpl_rpc2_program.h"
#include "evpl/evpl.h"
#include "core/timing.h"
#include "core/macros.h"

#include "prometheus-c.h"
#include "core/evpl_shared.h"

#include "rpc2/rpc2_cursor.h"

/* Roles for the evpl_rpc2_queue_depth gauge: a request is in flight on the
 * server (CALL received, reply not yet sent) or the client (CALL sent,
 * reply not yet received).  Each rpc2 thread keeps one gauge instance per
 * role so the scrape can break out offered depth by direction and thread.
 */
#define EVPL_RPC2_ROLE_SERVER 0
#define EVPL_RPC2_ROLE_CLIENT 1
#define EVPL_RPC2_NUM_ROLES   2

static const char *evpl_rpc2_role_names[EVPL_RPC2_NUM_ROLES] = {
    [EVPL_RPC2_ROLE_SERVER] = "server",
    [EVPL_RPC2_ROLE_CLIENT] = "client",
};

/* Monotonic id stamped onto each rpc2 thread to label its gauge series.
 * Bumped atomically since threads initialize on their own cores. */
static int         evpl_rpc2_next_thread_id = 0;

/*
 * evpl_rpc2_msg represents a single received RPC message (either a CALL or REPLY).
 *
 * Each msg has its own dbuf for dynamic allocations during unmarshalling.
 * The recv_iov holds references to the received data buffers.
 */
struct evpl_rpc2_msg {
    struct xdr_dbuf       dbuf;
    struct evpl_iovec    *recv_iov;
    int                   recv_niov;
    struct evpl_iovec    *req_iov;
    int                   req_niov;
    struct evpl_rpc2_msg *next;
};

/*
 * evpl_rpc2_request represents an RPC exchange (call + reply).
 *
 * For server: created when a CALL is received, freed after reply is sent.
 * For client: created when making a call, freed after reply is received.
 *
 * The request holds metadata about the exchange (xid, proc, RDMA info)
 * and points to the associated msg containing the received data.
 */
struct evpl_rpc2_request {
    uint32_t                              xid;
    uint32_t                              proc;
    uint32_t                              rdma_credits;
    uint16_t                              pending_reads;
    uint8_t                               dbg_reply_sent; /* RNR diag: 1 once reply SENT */
    struct evpl_bind                     *bind;
    struct evpl_rpc2_conn                *conn;
    struct evpl_rpc2_thread              *thread;
    struct evpl_rpc2_program             *program;
    struct prometheus_stopwatch           timestamp;
    struct prometheus_histogram_instance *metric;
    struct prometheus_gauge_instance     *m_inflight;
    void                                 *callback;
    void                                 *callback_arg;
    struct UT_hash_handle                 hh;
    struct evpl_rpc2_rdma_chunk           read_chunk;
    struct evpl_rpc2_rdma_chunk           write_chunk;
    /* The write_chunk iovecs are a borrowed caller buffer (read-into), not
     * libevpl-allocated -- do not release them when the request is freed. */
    int                                   write_chunk_borrowed;
    struct evpl_rpc2_rdma_segment_list    reply_segments;
    struct evpl_rpc2_rdma_segment_list    write_segments;
    struct evpl_iovec                     reply_segment_iov;
    struct evpl_rpc2_msg                 *msg;
    struct evpl_rpc2_request             *next;
    struct evpl_rpc2_encoding             encoding; /* Public interface for apps */

    /* RPCSEC_GSS state for a verified DATA request.  The authenticated
     * principal is copied in (rather than holding a context pointer) so the
     * context can be reaped concurrently without dangling into the request.
     * gss_handle + gss_seq let the reply path re-find the context (under the
     * global lock) to compute the integrity checksum over the results. */
    int                                   gss_authenticated;
    uint32_t                              gss_service;
    uint32_t                              gss_handle;
    uint32_t                              gss_seq;
    char                                  gss_principal[EVPL_RPC2_GSS_PRINCIPAL_MAX];
    /* Pre-computed reply verifier (e.g. a GSS MIC).  When reply_verf_flavor
     * is RPCSEC_GSS, evpl_rpc2_send_reply emits this as the accepted-reply
     * verifier instead of an AUTH_NONE verifier.  reply_verf_data is owned
     * by the request and freed in evpl_rpc2_request_free. */
    void                                 *reply_verf_data;
    uint32_t                              reply_verf_len;
    uint32_t                              reply_verf_flavor;
};

/*
 * Get the request from an encoding pointer.
 * Used internally by libevpl to access the full request from the public encoding.
 */
static inline struct evpl_rpc2_request *
evpl_rpc2_request_from_encoding(struct evpl_rpc2_encoding *encoding)
{
    return container_of(encoding, struct evpl_rpc2_request, encoding);
} /* evpl_rpc2_request_from_encoding */

/*
 * Initialize a credential from AUTH_SYS parameters.
 *
 * Converts from the XDR authsys_parms structure to the simple C types
 * used in evpl_rpc2_cred. The gids and machinename pointers are copied
 * directly (they point to dbuf-allocated storage from unmarshalling).
 */
static inline void
evpl_rpc2_cred_init_authsys(
    struct evpl_rpc2_cred      *cred,
    const struct authsys_parms *parms)
{
    cred->flavor = AUTH_SYS;

    cred->authsys.uid             = parms->uid;
    cred->authsys.gid             = parms->gid;
    cred->authsys.num_gids        = parms->num_gids;
    cred->authsys.gids            = parms->gids;
    cred->authsys.machinename     = parms->machinename.str;
    cred->authsys.machinename_len = parms->machinename.len;

    /* Clamp gids count to max allowed */
    if (cred->authsys.num_gids > EVPL_RPC2_AUTH_SYS_MAX_GIDS) {
        cred->authsys.num_gids = EVPL_RPC2_AUTH_SYS_MAX_GIDS;
    }
} /* evpl_rpc2_cred_init_authsys */

struct evpl_rpc2_server {
    struct evpl_listener      *listener;
    struct evpl_rpc2_program **programs;
    int                        nprograms;
};

struct evpl_rpc2_server_binding {
    struct evpl_rpc2_thread                *thread;
    struct evpl_rpc2_server                *server;
    struct evpl_listener_binding           *binding;
    struct prometheus_histogram_instance ***metrics;
    void                                   *private_data;
    struct evpl_rpc2_server_binding        *prev;
    struct evpl_rpc2_server_binding        *next;
};

struct evpl_rpc2_thread {
    struct evpl                         *evpl;
    struct evpl_rpc2_program           **programs;
    int                                  nprograms;
    struct evpl_rpc2_conn               *conns;
    evpl_rpc2_notify_callback_t          notify_callback;
    void                                *private_data;
    struct evpl_rpc2_msg                *free_msg;
    struct evpl_rpc2_request            *free_requests;
    struct evpl_rpc2_server_binding     *servers;
    xdr_dbuf                            *client_dbuf;
    int                                  id;
    struct prometheus_gauge_series      *m_inflight_series[EVPL_RPC2_NUM_ROLES];
    struct prometheus_gauge_instance    *m_inflight[EVPL_RPC2_NUM_ROLES];

    /* RPCSEC_GSS acceptor provider (NULL == RPCSEC_GSS disabled). */
    const struct evpl_rpc2_gss_provider *gss_provider;
    void                                *gss_provider_arg;
};

static struct evpl_rpc2_msg *
evpl_rpc2_msg_alloc(struct evpl_rpc2_thread *thread)
{
    struct evpl_rpc2_msg *msg;

    if (thread->free_msg) {
        msg = thread->free_msg;
        LL_DELETE(thread->free_msg, msg);
    } else {
        msg = evpl_zalloc(sizeof(*msg));
        xdr_dbuf_init(&msg->dbuf, 128 * 1024);
    }

    xdr_dbuf_reset(&msg->dbuf);
    msg->recv_niov = 0;
    msg->req_niov  = 0;

    return msg;
} /* evpl_rpc2_msg_alloc */

static inline void
evpl_rpc2_msg_free(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_msg    *msg)
{
    struct evpl *evpl = thread->evpl;

    evpl_iovecs_release_internal(evpl, msg->recv_iov, msg->recv_niov);
    evpl_iovecs_release_internal(evpl, msg->req_iov, msg->req_niov);

    LL_PREPEND(thread->free_msg, msg);
} /* evpl_rpc2_msg_free */

static struct evpl_rpc2_request *
evpl_rpc2_request_alloc(struct evpl_rpc2_thread *thread)
{
    struct evpl_rpc2_request *request;

    if (thread->free_requests) {
        request = thread->free_requests;
        LL_DELETE(thread->free_requests, request);
    } else {
        request = evpl_zalloc(sizeof(*request));
    }

    request->thread                      = thread;
    request->m_inflight                  = NULL;
    request->rdma_credits                = 1;
    request->dbg_reply_sent              = 0;
    request->pending_reads               = 0;
    request->read_chunk.niov             = 0;
    request->read_chunk.length           = 0;
    request->write_chunk.niov            = 0;
    request->write_chunk.length          = 0;
    request->write_chunk.max_length      = 0;
    request->write_chunk_borrowed        = 0;
    request->write_segments.num_segments = 0;
    request->reply_segments.num_segments = 0;
    request->msg                         = NULL;
    request->gss_authenticated           = 0;
    request->gss_service                 = 0;
    request->gss_handle                  = 0;
    request->gss_seq                     = 0;
    request->reply_verf_data             = NULL;
    request->reply_verf_len              = 0;
    request->reply_verf_flavor           = AUTH_NONE;
    /* Reset any reply-capture hook left over from the previous use of
     * this recycled request -- the application must re-arm per-call. */
    request->encoding.reply_capture_cb      = NULL;
    request->encoding.reply_capture_private = NULL;

    return request;
} /* evpl_rpc2_request_alloc */

static inline void
evpl_rpc2_request_free(
    struct evpl_rpc2_thread  *thread,
    struct evpl_rpc2_request *request)
{
    struct evpl *evpl = thread->evpl;

    /* Drop the in-flight count for whichever role (server/client) claimed
     * this request at allocation.  Centralized here so every teardown path
     * -- reply sent, reply received, connection error -- balances the inc. */
    if (request->m_inflight) {
        prometheus_gauge_add(request->m_inflight, -1);
        request->m_inflight = NULL;
    }

    evpl_iovecs_release_internal(evpl, request->read_chunk.iov, request->read_chunk.niov);
    /* A borrowed write-chunk (read-into) is owned by the caller -- never release
     * it here.  On the normal reply path write_chunk.niov is already 0 (moved to
     * read_chunk); this guards the abort/error path where it is still set. */
    if (!request->write_chunk_borrowed) {
        evpl_iovecs_release_internal(evpl, request->write_chunk.iov, request->write_chunk.niov);
    }

    if (request->msg) {
        evpl_rpc2_msg_free(thread, request->msg);
        request->msg = NULL;
    }

    if (request->reply_verf_data) {
        free(request->reply_verf_data);
        request->reply_verf_data   = NULL;
        request->reply_verf_len    = 0;
        request->reply_verf_flavor = AUTH_NONE;
    }

    LL_PREPEND(thread->free_requests, request);
} /* evpl_rpc2_request_free */

static FORCE_INLINE uint32_t
rpc2_hton32(uint32_t value)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return __builtin_bswap32(value);
#else  /* if __BYTE_ORDER == __LITTLE_ENDIAN */
    return value;
#endif /* if __BYTE_ORDER == __LITTLE_ENDIAN */
} /* rpc2_hton32 */

static FORCE_INLINE uint32_t
rpc2_ntoh32(uint32_t value)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return __builtin_bswap32(value);
#else  /* if __BYTE_ORDER == __LITTLE_ENDIAN */
    return value;
#endif /* if __BYTE_ORDER == __LITTLE_ENDIAN */
} /* rpc2_ntoh32 */

static int
rpc2_segment_callback(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *private_data)
{
    uint32_t hdr;
    int      length;

    length = evpl_peek(evpl, bind, &hdr, sizeof(hdr));

    if (length < (int) sizeof(hdr)) {
        return 0;
    }

    hdr = rpc2_ntoh32(hdr);

    /* Deliver one TCP record-mark fragment (4-byte mark + payload).
     * Multi-fragment reassembly is performed in evpl_rpc2_recv_msg. */
    return (hdr & 0x7FFFFFFF) + 4;
} /* rpc2_segment_callback */

/* Cap on a single reassembled RPC message (DoS guard). Well above
 * realistic NFS COMPOUND sizes (typical rsize/wsize <= 1 MiB). */
#define EVPL_RPC2_MAX_REASM_LENGTH (16u * 1024u * 1024u)

#define EVPL_RPC2_REASM_INIT_CAP   8

/* Upper bound on the payload iovec count handed downstream.  A real client
 * keeps a message's payload in a handful of large iovecs; only a peer that
 * fragments one RPC into hundreds of tiny record marks (a conformance test)
 * exceeds this.  When it does, the payload is flattened into a minimal
 * contiguous copy so consumers can assume a bounded count -- in particular
 * the diskfs backend stages write iovecs into a fixed array (cap 260), so
 * this stays comfortably below that. */
#define EVPL_RPC2_MAX_PAYLOAD_NIOV 256

static inline int
evpl_rpc2_iovec_skip(
    struct evpl_iovec *out_iov,
    struct evpl_iovec *in_iov,
    int                niov,
    int                offset)
{
    struct evpl_iovec *outc = out_iov;
    struct evpl_iovec *inc  = in_iov;
    int                left = offset;

    while (left) {

        if (inc->length <= left) {
            left -= inc->length;
            inc++;
        } else {
            evpl_iovec_clone_segment(outc, inc, left, inc->length - left);
            inc++;
            outc++;
            left = 0;
        }
    }

    while (inc < in_iov + niov) {
        evpl_iovec_clone(outc, inc);
        inc++;
        outc++;
    }

    return outc - out_iov;
} /* evpl_rpc2_iovec_skip */

/*
 * Collapse a heavily fragmented payload into a minimal contiguous copy.
 *
 * A peer that splits one RPC into hundreds of tiny record-mark fragments
 * (only a conformance-test client does this -- real clients keep the payload
 * in a few large fragments) hands us a payload iovec list with far more
 * entries than config->max_num_iovec.  Some consumers (e.g. VFS backends that
 * stage the write iovecs into a fixed array) bound that count, so flatten the
 * list here, once, into freshly allocated buffers and let the rest of the
 * stack assume a small iovec count.  This is a cold path; the memcpy cost is
 * irrelevant.
 *
 * Fills @dst (capacity @dst_cap) with the @length payload bytes drawn from
 * @src and returns the number of destination iovecs, or -1 if @length does
 * not fit in @dst_cap buffers.
 */
static int
evpl_rpc2_flatten_iovecs(
    struct evpl       *evpl,
    struct evpl_iovec *src,
    int                src_niov,
    int                length,
    struct evpl_iovec *dst,
    int                dst_cap)
{
    int    dst_niov, si = 0;
    size_t soff = 0;

    dst_niov = evpl_iovec_alloc(evpl, length, 0, dst_cap, 0, dst);

    if (unlikely(dst_niov <= 0)) {
        return -1;
    }

    for (int di = 0; di < dst_niov; di++) {
        char  *d     = dst[di].data;
        size_t dleft = dst[di].length;

        while (dleft && si < src_niov) {
            size_t savail = src[si].length - soff;
            size_t n      = dleft < savail ? dleft : savail;

            memcpy(d, (char *) src[si].data + soff, n);

            d     += n;
            dleft -= n;
            soff  += n;

            if (soff == src[si].length) {
                si++;
                soff = 0;
            }
        }
    }

    return dst_niov;
} /* evpl_rpc2_flatten_iovecs */

static void
evpl_rpc2_reasm_reset(
    struct evpl           *evpl,
    struct evpl_rpc2_conn *rpc2_conn)
{
    if (rpc2_conn->reasm_iov) {
        evpl_iovecs_release_internal(evpl, rpc2_conn->reasm_iov, rpc2_conn->reasm_niov);
        evpl_free(rpc2_conn->reasm_iov);
    }
    rpc2_conn->reasm_iov    = NULL;
    rpc2_conn->reasm_niov   = 0;
    rpc2_conn->reasm_cap    = 0;
    rpc2_conn->reasm_length = 0;
} /* evpl_rpc2_reasm_reset */

/*
 * Drives ONC RPC TCP record-mark reassembly.
 *
 * Caller delivers one fragment (the segment callback returns one
 * record-mark's worth of bytes at a time). This helper inspects the
 * 4-byte mark, accumulates payload iovecs across L=0 fragments on the
 * connection, and on the L=1 terminal fragment hands back a single
 * iovec list spanning all payload bytes from all fragments (with no
 * leading mark).
 *
 * Return:
 *   1  -> dispatch (*io_iovec, *io_niov, *io_length, *io_offset).
 *         Fast path (L=1, no pending fragments): inputs unchanged,
 *         *io_offset = 4. Reassembled path: inputs rewritten to the
 *         accumulator, *io_offset = 0, *io_length = total payload.
 *         When *io_offset == 0 the caller must evpl_free(*io_iovec)
 *         after releasing the iovec refs.
 *   0  -> intermediate fragment consumed; caller must return.
 *  -1  -> cap exceeded; caller must close the bind.
 */
static int
evpl_rpc2_reassemble(
    struct evpl           *evpl,
    struct evpl_rpc2_conn *rpc2_conn,
    struct evpl_iovec    **io_iovec,
    int                   *io_niov,
    int                   *io_length,
    int                   *io_offset)
{
    struct evpl_iovec *iovec = *io_iovec;
    int                niov  = *io_niov;
    uint32_t           mark;
    uint32_t           frag_len;
    int                last;
    int                added;

    mark     = rpc2_ntoh32(*(uint32_t *) iovec->data);
    last     = (mark & 0x80000000) != 0;
    frag_len = mark & 0x7FFFFFFF;

    /* Fast path: lone L=1 fragment, no fragments stashed. */
    if (last && rpc2_conn->reasm_niov == 0) {
        *io_offset = 4;
        return 1;
    }

    /* Cap check, overflow-safe. */
    if (frag_len > EVPL_RPC2_MAX_REASM_LENGTH - rpc2_conn->reasm_length) {
        evpl_rpc2_error(
            "RPC reassembled message exceeds %u-byte cap, dropping connection",
            EVPL_RPC2_MAX_REASM_LENGTH);
        evpl_rpc2_reasm_reset(evpl, rpc2_conn);
        evpl_iovecs_release_internal(evpl, iovec, niov);
        return -1;
    }

    /* Grow accumulator to fit reasm_niov + niov entries. */
    if (rpc2_conn->reasm_niov + niov > rpc2_conn->reasm_cap) {
        int                new_cap = rpc2_conn->reasm_cap
                ? rpc2_conn->reasm_cap : EVPL_RPC2_REASM_INIT_CAP;
        struct evpl_iovec *new_iov;
        int                k;

        while (new_cap < rpc2_conn->reasm_niov + niov) {
            new_cap *= 2;
        }

        new_iov = evpl_zalloc(sizeof(*new_iov) * new_cap);
        if (rpc2_conn->reasm_iov) {
            /* evpl_iovec_move transfers the ref (and, with iovec
             * tracing, rebinds the canary's owner to the new slot)
             * without a refcount round-trip. */
            for (k = 0; k < rpc2_conn->reasm_niov; k++) {
                evpl_iovec_move(&new_iov[k], &rpc2_conn->reasm_iov[k]);
            }
            evpl_free(rpc2_conn->reasm_iov);
        }
        rpc2_conn->reasm_iov = new_iov;
        rpc2_conn->reasm_cap = new_cap;
    }

    /* Clone payload iovecs (skipping the 4-byte mark) into the
     * accumulator. Each clone bumps the buffer refcount. */
    added = evpl_rpc2_iovec_skip(
        &rpc2_conn->reasm_iov[rpc2_conn->reasm_niov],
        iovec, niov, 4);
    rpc2_conn->reasm_niov   += added;
    rpc2_conn->reasm_length += frag_len;

    /* Drop the delivery refs; accumulator clones now own the buffer
     * references on behalf of the conn. */
    evpl_iovecs_release_internal(evpl, iovec, niov);

    if (!last) {
        return 0;
    }

    /* Terminal fragment: hand the accumulator off to the caller as a
     * single iovec list with no leading record mark. */
    *io_iovec  = rpc2_conn->reasm_iov;
    *io_niov   = rpc2_conn->reasm_niov;
    *io_length = (int) rpc2_conn->reasm_length;
    *io_offset = 0;

    rpc2_conn->reasm_iov    = NULL;
    rpc2_conn->reasm_niov   = 0;
    rpc2_conn->reasm_cap    = 0;
    rpc2_conn->reasm_length = 0;

    return 1;
} /* evpl_rpc2_reassemble */

static void
evpl_rpc2_dispatch_reply(
    struct evpl              *evpl,
    struct evpl_rpc2_request *request,
    struct evpl_iovec        *reply_iov,
    int                       reply_niov,
    int                       reply_length)
{
    struct evpl_rpc2_thread *thread = request->thread;

    evpl_sendv(
        evpl,
        request->bind,
        reply_iov,
        reply_niov,
        reply_length,
        EVPL_SEND_FLAG_TAKE_REF);

    evpl_rpc2_request_free(thread, request);
} /* evpl_rpc2_dispatch_reply */

/* Defined in the RPCSEC_GSS section below; used by evpl_rpc2_send_reply to
 * wrap an integrity-service (krb5i) reply body as rpc_gss_integ_data. */
static int
evpl_rpc2_gss_wrap_reply_integrity(
    struct evpl              *evpl,
    struct evpl_rpc2_request *request,
    struct evpl_iovec        *msg_iov,
    int                       msg_niov,
    int                       length,
    int                       reserve,
    struct evpl_iovec        *out_iov,
    int                      *out_length);

static int
evpl_rpc2_send_reply(
    struct evpl                 *evpl,
    struct evpl_rpc2_request    *request,
    const struct evpl_rpc2_verf *verf,
    struct evpl_iovec           *msg_iov,
    int                          msg_niov,
    int                          length,
    int                          reserve,
    reply_stat                   rstat,
    int                          error_stat)
{
    struct evpl_iovec             iov, reply_iov;
    int                           reply_len, reply_niov, offset, rpc_len, reply_chunk_len;
    uint32_t                      hdr, write_left, left, chunk;
    struct rpc_msg                rpc_reply;
    struct rdma_msg               rdma_msg;
    struct xdr_write_chunk        reply_chunk;
    struct xdr_write_list         write_list;
    struct xdr_rdma_segment      *target;
    struct evpl_iovec            *segment_iov, *reply_segment_iov;
    struct evpl_rpc2_iovec_cursor write_cursor, reply_cursor;
    int                           segment_niov;
    int                           i, reduce = 0, rdma = request->conn->rdma;
    struct evpl_iovec            *final_reply_iov;
    int                           final_reply_niov, final_reply_length;
    struct evpl_iovec             gss_wrapped_iov;

    /* RNR diag: affirm exactly one reply SEND per request.  A second reply for
     * the same request would post a SEND the client reserved no receive for
     * (an RNR source independent of credits).  Abort to capture it definitively. */
    evpl_rpc2_abort_if(rdma && request->dbg_reply_sent,
                       "DOUBLE REPLY SEND on xid=%u proc=%u -- second SEND with no client recv",
                       request->xid, request->proc);
    request->dbg_reply_sent = 1;

    rpc_reply.xid             = request->xid;
    rpc_reply.body.mtype      = REPLY;
    rpc_reply.body.rbody.stat = rstat;

    if (rstat == MSG_ACCEPTED) {
        (void) verf;
        if (request->reply_verf_flavor == RPCSEC_GSS) {
            /* Emit the GSS reply verifier precomputed at call-verification
             * time (a MIC over the request seq_num, or over the seq_window
             * for a completed context-establishment response). */
            rpc_reply.body.rbody.areply.verf.flavor          = RPCSEC_GSS;
            rpc_reply.body.rbody.areply.verf.rpcsec_gss.data = request->reply_verf_data;
            rpc_reply.body.rbody.areply.verf.rpcsec_gss.len  = request->reply_verf_len;
        } else {
            /* AUTH_SHORT is not implemented - always use AUTH_NONE verifier */
            rpc_reply.body.rbody.areply.verf.flavor = AUTH_NONE;
        }
        rpc_reply.body.rbody.areply.reply_data.stat = error_stat;

        /* Integrity service (krb5i): reframe the proc results as
         * rpc_gss_integ_data before the RPC header is prepended.  Non-RDMA
         * only (GSS over RDMA is not a supported transport).  On failure we
         * fall through with the unwrapped body -- the client will reject the
         * reply's missing integrity, which is the safe outcome. */
        if (!rdma && error_stat == SUCCESS &&
            request->gss_service == EVPL_RPC2_GSS_SVC_INTEGRITY) {
            int wrapped_len;

            if (evpl_rpc2_gss_wrap_reply_integrity(evpl, request, msg_iov,
                                                   msg_niov, length, reserve,
                                                   &gss_wrapped_iov,
                                                   &wrapped_len) == 0) {
                msg_iov  = &gss_wrapped_iov;
                msg_niov = 1;
                length   = wrapped_len;
            }
        }
    } else {
        /* MSG_DENIED - currently only AUTH_ERROR is supported */
        rpc_reply.body.rbody.rreply.stat = AUTH_ERROR;
        rpc_reply.body.rbody.rreply.auth = error_stat;
    }

    rpc_len         = marshall_length_rpc_msg(&rpc_reply);
    reply_chunk_len = rpc_len + length - reserve;

    evpl_rpc2_abort_if(reply_chunk_len < 0,
                       "negative RPC2 RDMA reply chunk length %d", reply_chunk_len);

    if (rdma) {

        rdma_msg.rdma_xid                       = request->xid;
        rdma_msg.rdma_vers                      = 1;
        rdma_msg.rdma_credit                    = request->rdma_credits;
        rdma_msg.rdma_body.proc                 = RDMA_MSG;
        rdma_msg.rdma_body.rdma_msg.rdma_reads  = NULL;
        rdma_msg.rdma_body.rdma_msg.rdma_writes = NULL;
        rdma_msg.rdma_body.rdma_msg.rdma_reply  = NULL;

        if (request->write_segments.num_segments > 0) {
            write_list.entry.num_target = request->write_segments.num_segments;
            write_list.entry.target     = (struct xdr_rdma_segment *) request->write_segments.segments;
            write_list.next             = NULL;

            rdma_msg.rdma_body.rdma_msg.rdma_writes = &write_list;
        }

        if (request->reply_segments.num_segments > 0) {
            reply_chunk.num_target                 = request->reply_segments.num_segments;
            reply_chunk.target                     = (struct xdr_rdma_segment *) request->reply_segments.segments;
            rdma_msg.rdma_body.rdma_msg.rdma_reply = &reply_chunk;
        }

        write_left = request->write_chunk.length;

        if (request->write_segments.num_segments > 0) {

            evpl_rpc2_iovec_cursor_init(&write_cursor, request->write_chunk.iov, request->write_chunk.niov);

            for (i = 0; i < write_list.entry.num_target; i++) {
                target = &write_list.entry.target[i];

                if (write_left < target->length) {
                    target->length = write_left;
                    write_left     = 0;
                } else {
                    write_left -= target->length;
                }

                if (target->length) {

                    segment_niov = evpl_rpc2_iovec_cursor_move(&write_cursor, &request->msg->dbuf, &segment_iov,
                                                               target->length);

                    if (unlikely(segment_niov < 0)) {
                        evpl_rpc2_abort("Failed to move segment iovec");
                    }

                    evpl_rdma_write(evpl, request->bind,
                                    target->handle, target->offset,
                                    segment_iov, segment_niov,
                                    EVPL_RDMA_FLAG_TAKE_REF,
                                    NULL, NULL);
                }
            }
        }

        if (request->reply_segments.num_segments > 0) {

            if (reply_chunk_len > 512) {
                reduce = 1;

                rdma_msg.rdma_body.proc                  = RDMA_NOMSG;
                rdma_msg.rdma_body.rdma_nomsg.rdma_reads = NULL;

                left = reply_chunk_len;

                for (i = 0; i < reply_chunk.num_target; i++) {

                    chunk = reply_chunk.target[i].length;

                    if (left < chunk) {
                        chunk = left;
                    }

                    reply_chunk.target[ i].length = chunk;

                    left -= chunk;
                }

            } else {

                for (i = 0; i < reply_chunk.num_target; i++) {
                    reply_chunk.target[ i].length = 0;
                }
            }
        }

        offset = marshall_length_rdma_msg(&rdma_msg);

        msg_iov[0].data   += reserve - (rpc_len + offset);
        msg_iov[0].length -= reserve - (rpc_len + offset);
        length            -= reserve - (rpc_len + offset);

        reply_niov = 1;
        iov        = msg_iov[0];

        marshall_rdma_msg(&rdma_msg, &iov, &reply_iov, &reply_niov, NULL, 0);

        /* Release the RDMA header iovec - marshall_rpc_msg will create its own */
        evpl_iovec_release_internal(evpl, &reply_iov);

    } else {
        offset = 4;

        msg_iov[0].data   += reserve - (rpc_len + offset);
        msg_iov[0].length -= reserve - (rpc_len + offset);
        length            -= reserve - (rpc_len + offset);
    }

    iov = msg_iov[0];

    reply_niov = 1;
    reply_len  = marshall_rpc_msg(&rpc_reply, &iov, &reply_iov, &reply_niov, NULL, offset);

    evpl_iovec_release_internal(evpl, &reply_iov);

    evpl_rpc2_abort_if(reply_len != rpc_len + offset,
                       "marshalled reply length mismatch %d != %d", reply_len, rpc_len + offset);

    if (!rdma) {
        hdr = rpc2_hton32((length - 4) | 0x80000000);
        memcpy(msg_iov[0].data, &hdr, sizeof(hdr));
    }

    if (request->metric) {
        prometheus_time_histogram_sample(request->metric, &request->timestamp);
    }

    if (reduce) {

        final_reply_iov = xdr_dbuf_alloc_space(sizeof(*final_reply_iov), &request->msg->dbuf);

        evpl_rpc2_abort_if(final_reply_iov == NULL, "Failed to allocate reply iovec");

        evpl_iovec_clone_segment(final_reply_iov, &msg_iov[0], 0, offset);
        final_reply_niov   = 1;
        final_reply_length = offset;

        msg_iov[0].data   += offset;
        msg_iov[0].length -= offset;

        evpl_rpc2_iovec_cursor_init(&reply_cursor, msg_iov, msg_niov);

        for (i = 0; i < reply_chunk.num_target; i++) {

            if (reply_chunk.target[i].length == 0) {
                continue;
            }

            segment_niov = evpl_rpc2_iovec_cursor_move(&reply_cursor, &request->msg->dbuf, &reply_segment_iov,
                                                       reply_chunk.target[i].length);

            if (unlikely(segment_niov < 0)) {
                evpl_rpc2_abort("Failed to move reply segment iovec");
            }

            evpl_rdma_write(evpl, request->bind,
                            reply_chunk.target[i].handle,
                            reply_chunk.target[i].offset,
                            reply_segment_iov, segment_niov,
                            EVPL_RDMA_FLAG_TAKE_REF,
                            NULL, NULL);
        }

        /*
         * Release msg_iov - we've taken new references for final_reply_iov
         * and reply_segment_iov. The original msg_iov is no longer needed.
         */
        evpl_iovecs_release_internal(evpl, msg_iov, msg_niov);

    } else {
        final_reply_iov    = msg_iov;
        final_reply_niov   = msg_niov;
        final_reply_length = length;
    }

    /* If the application requested reply capture (e.g. for an NFS4.1
     * SEQUENCE replay cache), invoke the callback now -- the iovec
     * array is fully populated and still valid; dispatch_reply will
     * free the request (and therefore the iovec metadata) below. */
    if (request->encoding.reply_capture_cb) {
        request->encoding.reply_capture_cb(
            final_reply_iov,
            final_reply_niov,
            final_reply_length,
            request->encoding.reply_capture_private);
    }

    evpl_rpc2_dispatch_reply(evpl, request, final_reply_iov, final_reply_niov, final_reply_length);

    return 0;
} /* evpl_rpc2_send_reply */


static inline int
evpl_rpc2_send_reply_error(
    struct evpl              *evpl,
    struct evpl_rpc2_request *request,
    int                       accept_error)
{
    struct evpl_iovec msg_iov;
    int               msg_niov = 1;

    msg_niov = evpl_iovec_alloc(evpl, 4096, 0, 1, 0, &msg_iov);

    return evpl_rpc2_send_reply(evpl, request, NULL, &msg_iov, msg_niov, 4096, 4096,
                                MSG_ACCEPTED, accept_error);
} /* evpl_rpc2_send_reply_error */

/*
 * Send an authentication error reply (MSG_DENIED, AUTH_ERROR).
 *
 * This is used to reject calls with invalid authentication flavors.
 */
static inline int
evpl_rpc2_send_reply_denied(
    struct evpl              *evpl,
    struct evpl_rpc2_request *request,
    int                       auth_error)
{
    struct evpl_iovec msg_iov;
    int               msg_niov = 1;

    msg_niov = evpl_iovec_alloc(evpl, 4096, 0, 1, 0, &msg_iov);

    return evpl_rpc2_send_reply(evpl, request, NULL, &msg_iov, msg_niov, 4096, 4096,
                                MSG_DENIED, auth_error);
} /* evpl_rpc2_send_reply_denied */


static inline int
evpl_rpc2_send_reply_success(
    struct evpl                 *evpl,
    struct evpl_rpc2_encoding   *encoding,
    const struct evpl_rpc2_verf *verf,
    struct evpl_iovec           *msg_iov,
    int                          msg_niov,
    int                          length)
{
    struct evpl_rpc2_request *request = evpl_rpc2_request_from_encoding(encoding);

    return evpl_rpc2_send_reply(evpl, request, verf, msg_iov, msg_niov, length,
                                request->program->reserve, MSG_ACCEPTED, SUCCESS);
} /* evpl_rpc2_send_reply_success */

/* ===================== RPCSEC_GSS (RFC 2203 / RFC 5403) =====================
 *
 * libevpl owns the RPC-level framing: the rpc_gss_cred_t credential, the
 * context-establishment handshake (carried on the program NULL procedure),
 * the per-request call verifier and sequence-number replay window, and the
 * reply verifier.  A registered provider (evpl_rpc2_set_gss_provider) wraps
 * the actual GSS mechanism (Kerberos).  This first cut implements the
 * authentication service (rpc_gss_svc_none, i.e. sec=krb5); integrity and
 * privacy are rejected with AUTH_TOOWEAK until wrapping is wired up.
 */

/* rpc_gss_proc_t */
#define RPCSEC_GSS_DATA             0
#define RPCSEC_GSS_INIT             1
#define RPCSEC_GSS_CONTINUE_INIT    2
#define RPCSEC_GSS_DESTROY          3

#define RPCSEC_GSS_VERS_1           1
/* Per RFC 2203: sequence numbers must stay below this; past it the client
 * is expected to create a new context. */
#define RPCSEC_GSS_MAXSEQ           0x80000000u
/* Replay window we advertise and enforce.  Bounded by the uint64 bitmap. */
#define RPCSEC_GSS_SEQ_WINDOW       64

/* GSS major status values emitted in rpc_gss_init_res. */
#define EVPL_GSS_S_COMPLETE         0x00000000u
#define EVPL_GSS_S_CONTINUE_NEEDED  0x00000001u
#define EVPL_GSS_S_FAILURE          0x000d0000u

/* Additional auth_stat values defined by RPCSEC_GSS (RFC 2203 sec 5).
 * The client treats these as "discard the context and re-establish". */
#define RPCSEC_GSS_CREDPROBLEM      13
#define RPCSEC_GSS_CTXPROBLEM       14

/* Headroom reserved at the front of an init-response buffer for the RPC
 * reply header plus an RPCSEC_GSS verifier (a GSS MIC). */
#define EVPL_RPC2_GSS_REPLY_RESERVE 1024

struct evpl_rpc2_gss_context {
    uint32_t               handle;      /* server-minted; uthash key */
    void                  *gss_ctx;     /* provider context cookie */
    int                    established;
    uint32_t               service;     /* last service seen (informational) */
    /* Sliding replay window: seq_high is the largest accepted seq_num;
     * bit i of seq_mask marks (seq_high - i) as already seen. */
    uint32_t               seq_high;
    uint64_t               seq_mask;
    char                   principal[EVPL_RPC2_GSS_PRINCIPAL_MAX];
    /* The connection that established this context.  RPCSEC_GSS handles are
     * server-global (a context established on one connection may be presented
     * on another -- NFSv4.1 session trunking / BIND_CONN_TO_SESSION), so the
     * table below is process-wide rather than per-connection.  We still reap a
     * context when its creating connection drops (unless explicitly destroyed
     * sooner), which covers the common single-connection case without leaking. */
    struct evpl_rpc2_conn *creator_conn;
    struct UT_hash_handle  hh;
};

/*
 * Process-global RPCSEC_GSS context registry.  Handles are unique server-wide
 * so a context can be looked up regardless of which connection (or rpc2
 * thread) a DATA request arrives on.  The mutex is held across both the table
 * operations and the provider crypto calls that touch a context, so a single
 * gss_ctx_id_t is never used concurrently from two threads.
 */
static struct evpl_rpc2_gss_context *evpl_rpc2_gss_table       = NULL;
static pthread_mutex_t               evpl_rpc2_gss_lock        = PTHREAD_MUTEX_INITIALIZER;
static uint32_t                      evpl_rpc2_gss_next_handle = 0;

/* Decoded rpc_gss_cred_t (version 1). */
struct evpl_rpc2_gss_cred {
    uint32_t       version;
    uint32_t       proc;
    uint32_t       seq;
    uint32_t       service;
    const uint8_t *handle;
    uint32_t       handle_len;
};

/* --- minimal big-endian XDR cursors over contiguous byte buffers --- */

static inline uint32_t
evpl_rpc2_gss_pad4(uint32_t len)
{
    return (len + 3) & ~3u;
} /* evpl_rpc2_gss_pad4 */

static int
evpl_rpc2_gss_rd_u32(
    const uint8_t **p,
    const uint8_t  *end,
    uint32_t       *v)
{
    if (*p + 4 > end) {
        return -1;
    }
    *v = ((uint32_t) (*p)[0] << 24) | ((uint32_t) (*p)[1] << 16) |
        ((uint32_t) (*p)[2] << 8) | (uint32_t) (*p)[3];
    *p += 4;
    return 0;
} /* evpl_rpc2_gss_rd_u32 */

static int
evpl_rpc2_gss_rd_opaque(
    const uint8_t **p,
    const uint8_t  *end,
    const uint8_t **data,
    uint32_t       *len)
{
    uint32_t l, padded;

    if (evpl_rpc2_gss_rd_u32(p, end, &l)) {
        return -1;
    }
    padded = evpl_rpc2_gss_pad4(l);
    if (*p + padded > end) {
        return -1;
    }
    *data = *p;
    *len  = l;
    *p   += padded;
    return 0;
} /* evpl_rpc2_gss_rd_opaque */

static int
evpl_rpc2_gss_wr_u32(
    uint8_t **p,
    uint8_t  *end,
    uint32_t  v)
{
    if (*p + 4 > end) {
        return -1;
    }
    (*p)[0] = (v >> 24) & 0xff;
    (*p)[1] = (v >> 16) & 0xff;
    (*p)[2] = (v >> 8) & 0xff;
    (*p)[3] = v & 0xff;
    *p     += 4;
    return 0;
} /* evpl_rpc2_gss_wr_u32 */

static int
evpl_rpc2_gss_wr_opaque(
    uint8_t   **p,
    uint8_t    *end,
    const void *data,
    uint32_t    len)
{
    uint32_t padded = evpl_rpc2_gss_pad4(len);

    if (evpl_rpc2_gss_wr_u32(p, end, len)) {
        return -1;
    }
    if (*p + padded > end) {
        return -1;
    }
    memcpy(*p, data, len);
    if (padded > len) {
        memset(*p + len, 0, padded - len);
    }
    *p += padded;
    return 0;
} /* evpl_rpc2_gss_wr_opaque */

/* Copy `len` bytes starting at byte offset `off` across an iovec array. */
static int
evpl_rpc2_iov_gather(
    struct evpl_iovec *iov,
    int                niov,
    uint32_t           off,
    void              *dst,
    uint32_t           len)
{
    uint8_t *d      = dst;
    uint32_t copied = 0;
    int      i;

    for (i = 0; i < niov && copied < len; i++) {
        uint32_t ilen = iov[i].length;
        uint32_t avail, n;

        if (off >= ilen) {
            off -= ilen;
            continue;
        }
        avail = ilen - off;
        n     = len - copied;
        if (n > avail) {
            n = avail;
        }
        memcpy(d + copied, (uint8_t *) iov[i].data + off, n);
        copied += n;
        off     = 0;
    }
    return copied == len ? 0 : -1;
} /* evpl_rpc2_iov_gather */

static int
evpl_rpc2_gss_decode_cred(
    const void                *blob,
    uint32_t                   bloblen,
    struct evpl_rpc2_gss_cred *c)
{
    const uint8_t *p   = blob;
    const uint8_t *end = (const uint8_t *) blob + bloblen;

    if (evpl_rpc2_gss_rd_u32(&p, end, &c->version) ||
        evpl_rpc2_gss_rd_u32(&p, end, &c->proc) ||
        evpl_rpc2_gss_rd_u32(&p, end, &c->seq) ||
        evpl_rpc2_gss_rd_u32(&p, end, &c->service) ||
        evpl_rpc2_gss_rd_opaque(&p, end, &c->handle, &c->handle_len)) {
        return -1;
    }
    return 0;
} /* evpl_rpc2_gss_decode_cred */

/* --- process-global context table --- */
/* The following helpers operate on the global table and assume the caller
 * holds evpl_rpc2_gss_lock (except evpl_rpc2_gss_conn_cleanup, which locks
 * itself). */

static struct evpl_rpc2_gss_context *
evpl_rpc2_gss_ctx_lookup(uint32_t handle)
{
    struct evpl_rpc2_gss_context *ctx;

    HASH_FIND(hh, evpl_rpc2_gss_table, &handle, sizeof(handle), ctx);
    return ctx;
} /* evpl_rpc2_gss_ctx_lookup */

static struct evpl_rpc2_gss_context *
evpl_rpc2_gss_ctx_create(struct evpl_rpc2_conn *conn)
{
    struct evpl_rpc2_gss_context *ctx = evpl_zalloc(sizeof(*ctx));

    /* Handle 0 is reserved to mean "no handle" on the wire (INIT). */
    do {
        ctx->handle = ++evpl_rpc2_gss_next_handle;
    } while (ctx->handle == 0 || evpl_rpc2_gss_ctx_lookup(ctx->handle));

    ctx->creator_conn = conn;
    HASH_ADD(hh, evpl_rpc2_gss_table, handle, sizeof(ctx->handle), ctx);
    return ctx;
} /* evpl_rpc2_gss_ctx_create */

static void
evpl_rpc2_gss_ctx_destroy(
    struct evpl_rpc2_thread      *thread,
    struct evpl_rpc2_gss_context *ctx)
{
    HASH_DELETE(hh, evpl_rpc2_gss_table, ctx);
    if (ctx->gss_ctx && thread->gss_provider && thread->gss_provider->destroy) {
        thread->gss_provider->destroy(thread->gss_provider_arg, ctx->gss_ctx);
    }
    evpl_free(ctx);
} /* evpl_rpc2_gss_ctx_destroy */

/*
 * Connection teardown does NOT reap GSS contexts.  RPCSEC_GSS context handles
 * are server-global and routinely outlive the connection they were
 * established on: the Linux client establishes contexts via rpc.gssd on a
 * short-lived dedicated connection, then presents the handle on the separate
 * (long-lived) NFS connection.  Reaping on the establishing connection's
 * disconnect would make every such handle unusable.  Contexts are instead
 * reclaimed on an explicit RPCSEC_GSS_DESTROY (which clients send on unmount).
 *
 * TODO: add a lifetime/idle-based GC to bound the footprint of contexts whose
 * client departs without sending DESTROY (e.g. a crashed client).
 */
static void
evpl_rpc2_gss_conn_cleanup(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_conn   *conn)
{
    (void) thread;
    (void) conn;
} /* evpl_rpc2_gss_conn_cleanup */

/*
 * Advance the replay window for a DATA request.  Returns 0 if the sequence
 * number is fresh and acceptable, -1 if it is a replay or has fallen out of
 * the window (caller should silently drop per RFC 2203).
 */
static int
evpl_rpc2_gss_seq_check(
    struct evpl_rpc2_gss_context *ctx,
    uint32_t                      seq)
{
    uint32_t diff;

    if (seq > RPCSEC_GSS_MAXSEQ) {
        return -1;
    }

    if (seq > ctx->seq_high) {
        uint32_t shift = seq - ctx->seq_high;

        if (shift >= 64) {
            ctx->seq_mask = 0;
        } else {
            ctx->seq_mask <<= shift;
        }
        ctx->seq_mask |= 1;
        ctx->seq_high  = seq;
        return 0;
    }

    diff = ctx->seq_high - seq;
    if (diff >= RPCSEC_GSS_SEQ_WINDOW) {
        return -1; /* too old */
    }
    if (ctx->seq_mask & (1ULL << diff)) {
        return -1; /* replay */
    }
    ctx->seq_mask |= (1ULL << diff);
    return 0;
} /* evpl_rpc2_gss_seq_check */

/*
 * Integrity service (krb5i): the call arguments are wrapped as
 *   rpc_gss_integ_data { opaque databody<>; opaque checksum<>; }
 * where databody = XDR(seq_num) || XDR(proc_args) and checksum is a GSS MIC
 * over databody.  Verify the checksum and the embedded seq, then repoint
 * (*iov_p, *niov_p, *len_p) to the inner proc arguments (databody after the
 * 4-byte seq), so normal program dispatch sees the unwrapped call.
 *
 * Must be called with evpl_rpc2_gss_lock held (it touches ctx->gss_ctx).
 * Returns 0 on success, -1 on a framing/verification failure.
 */
static int
evpl_rpc2_gss_unwrap_integrity(
    struct evpl_rpc2_request     *request,
    struct evpl_rpc2_gss_context *ctx,
    uint32_t                      seq,
    struct evpl_iovec           **iov_p,
    int                          *niov_p,
    int                          *len_p)
{
    struct evpl_rpc2_thread *thread = request->thread;
    struct evpl             *evpl   = thread->evpl;
    struct xdr_dbuf         *dbuf   = &request->msg->dbuf;
    struct evpl_iovec       *iov    = *iov_p;
    int                      niov   = *niov_p;
    uint8_t                  lenbuf[4];
    const uint8_t           *lp;
    uint32_t                 db_len, ck_off, ck_len, embedded, inner_len;
    uint8_t                 *databody, *checksum;
    struct evpl_iovec       *inner;
    int                      ninner;

    /* databody length prefix */
    if (evpl_rpc2_iov_gather(iov, niov, 0, lenbuf, 4)) {
        return -1;
    }
    lp = lenbuf;
    if (evpl_rpc2_gss_rd_u32(&lp, lenbuf + 4, &db_len) || db_len < 4) {
        return -1;
    }

    databody = xdr_dbuf_alloc_space(db_len, dbuf);
    if (!databody || evpl_rpc2_iov_gather(iov, niov, 4, databody, db_len)) {
        return -1;
    }

    /* checksum opaque follows the (padded) databody */
    ck_off = 4 + evpl_rpc2_gss_pad4(db_len);
    if (evpl_rpc2_iov_gather(iov, niov, ck_off, lenbuf, 4)) {
        return -1;
    }
    lp = lenbuf;
    evpl_rpc2_gss_rd_u32(&lp, lenbuf + 4, &ck_len);
    checksum = xdr_dbuf_alloc_space(ck_len ? ck_len : 1, dbuf);
    if (!checksum || evpl_rpc2_iov_gather(iov, niov, ck_off + 4, checksum, ck_len)) {
        return -1;
    }

    if (thread->gss_provider->verify_mic(thread->gss_provider_arg, ctx->gss_ctx,
                                         databody, db_len, checksum, ck_len)) {
        evpl_rpc2_debug("rpcsec_gss: integ databody MIC failed db_len=%u "
                        "ck_len=%u niov=%d", db_len, ck_len, niov);
        return -1;
    }

    /* The seq embedded in databody must match the credential seq. */
    lp = databody;
    evpl_rpc2_gss_rd_u32(&lp, databody + 4, &embedded);
    if (embedded != seq) {
        evpl_rpc2_debug("rpcsec_gss: integ seq mismatch embedded=%u cred=%u",
                        embedded, seq);
        return -1;
    }

    /* The inner proc arguments are databody after the 4-byte seq.  Copy them
     * into a fresh, ref-counted iovec: the generated unmarshallers zero-copy
     * clone opaque fields (e.g. WRITE payload), which requires a real buffer
     * reference -- a view into the dbuf would have none.  Swap it into the msg
     * so the existing teardown releases it. */
    inner_len = db_len - 4;
    inner     = xdr_dbuf_alloc_space(sizeof(*inner), dbuf);
    if (!inner) {
        return -1;
    }
    ninner = evpl_iovec_alloc(evpl, inner_len ? inner_len : 1, 8, 1, 0, inner);
    if (ninner != 1) {
        return -1;
    }
    inner->length = inner_len;
    if (inner_len) {
        memcpy(inner->data, databody + 4, inner_len);
    }

    evpl_iovecs_release(evpl, request->msg->req_iov, request->msg->req_niov);
    request->msg->req_iov  = inner;
    request->msg->req_niov = 1;

    *iov_p  = inner;
    *niov_p = 1;
    *len_p  = (int) inner_len;
    return 0;
} /* evpl_rpc2_gss_unwrap_integrity */

/*
 * Integrity service reply wrap: reframe the marshalled proc results as
 *   rpc_gss_integ_data { databody = seq_num || results; checksum = MIC; }
 * into a fresh buffer that keeps `reserve` bytes of RPC-header headroom at the
 * front (matching the unwrapped reply convention).  The original reply iovecs
 * are released.  Returns 0 and fills out_iov/out_length, or -1 on failure.
 */
static int
evpl_rpc2_gss_wrap_reply_integrity(
    struct evpl              *evpl,
    struct evpl_rpc2_request *request,
    struct evpl_iovec        *msg_iov,
    int                       msg_niov,
    int                       length,
    int                       reserve,
    struct evpl_iovec        *out_iov,
    int                      *out_length)
{
    struct evpl_rpc2_thread      *thread = request->thread;
    struct evpl_rpc2_gss_context *ctx;
    uint32_t                      bodylen = length - reserve;
    uint32_t                      db_len  = 4 + bodylen; /* seq || results */
    uint32_t                      db_pad  = evpl_rpc2_gss_pad4(db_len);
    uint32_t                      cap, newbodylen;
    uint8_t                      *p, *databody, *cksum_pos, *pp;
    void                         *mic     = NULL;
    size_t                        mic_len = 0;
    int                           niov;

    /* reserve headroom + db_len prefix + padded databody + checksum opaque
     * (4 + padded MIC; krb5 MICs are well under 512). */
    cap  = reserve + 4 + db_pad + 4 + 512;
    niov = evpl_iovec_alloc(evpl, cap, 8, 1, 0, out_iov);
    if (niov != 1) {
        return -1;
    }

    p = (uint8_t *) out_iov->data + reserve;

    /* databody length prefix */
    pp = p;
    if (evpl_rpc2_gss_wr_u32(&pp, p + 4, db_len)) {
        goto fail;
    }
    databody = p + 4;

    /* databody = seq || results (written contiguously so we can MIC it) */
    pp = databody;
    if (evpl_rpc2_gss_wr_u32(&pp, databody + 4, request->gss_seq)) {
        goto fail;
    }
    if (bodylen &&
        evpl_rpc2_iov_gather(msg_iov, msg_niov, reserve, databody + 4, bodylen)) {
        goto fail;
    }
    if (db_pad > db_len) {
        memset(databody + db_len, 0, db_pad - db_len);
    }

    /* checksum = MIC over databody, under the global context lock */
    pthread_mutex_lock(&evpl_rpc2_gss_lock);
    ctx = evpl_rpc2_gss_ctx_lookup(request->gss_handle);
    if (ctx) {
        thread->gss_provider->get_mic(thread->gss_provider_arg, ctx->gss_ctx,
                                      databody, db_len, &mic, &mic_len);
    }
    pthread_mutex_unlock(&evpl_rpc2_gss_lock);

    if (!mic || mic_len > 512) {
        if (mic) {
            free(mic);
        }
        goto fail;
    }

    cksum_pos = databody + db_pad;
    pp        = cksum_pos;
    if (evpl_rpc2_gss_wr_opaque(&pp, cksum_pos + 4 + evpl_rpc2_gss_pad4(mic_len),
                                mic, mic_len)) {
        free(mic);
        goto fail;
    }
    free(mic);

    newbodylen      = 4 + db_pad + 4 + evpl_rpc2_gss_pad4(mic_len);
    out_iov->length = reserve + newbodylen;
    *out_length     = reserve + newbodylen;

    evpl_iovecs_release(evpl, msg_iov, msg_niov);
    return 0;

 fail:
    evpl_iovec_release(evpl, out_iov);
    return -1;
} /* evpl_rpc2_gss_wrap_reply_integrity */

/*
 * Emit an rpc_gss_init_res reply for the context-establishment handshake.
 * The response body (handle, major, minor, seq_window, token) is marshalled
 * into a fresh buffer with header headroom and sent as MSG_ACCEPTED/SUCCESS.
 * On a completed context, the reply verifier is a GSS MIC over the
 * advertised seq_window (RFC 2203 sec 5.2.3.1); on an intermediate leg the
 * verifier is AUTH_NONE.
 */
static void
evpl_rpc2_gss_send_init_res(
    struct evpl                  *evpl,
    struct evpl_rpc2_request     *request,
    struct evpl_rpc2_gss_context *ctx,
    uint32_t                      gss_major,
    const void                   *token,
    uint32_t                      token_len,
    int                           complete)
{
    struct evpl_rpc2_thread *thread = request->thread;
    struct evpl_iovec        iov;
    uint8_t                 *p, *end, *body;
    uint32_t                 body_len;
    int                      niov;

    niov = evpl_iovec_alloc(evpl, EVPL_RPC2_GSS_REPLY_RESERVE + 512 + token_len,
                            8, 1, 0, &iov);
    evpl_rpc2_abort_if(niov != 1, "Failed to allocate gss init reply iovec");

    body = (uint8_t *) iov.data + EVPL_RPC2_GSS_REPLY_RESERVE;
    p    = body;
    end  = (uint8_t *) iov.data + iov.length;

    if (evpl_rpc2_gss_wr_opaque(&p, end, &ctx->handle, sizeof(ctx->handle)) ||
        evpl_rpc2_gss_wr_u32(&p, end, gss_major) ||
        evpl_rpc2_gss_wr_u32(&p, end, 0 /* gss_minor */) ||
        evpl_rpc2_gss_wr_u32(&p, end, RPCSEC_GSS_SEQ_WINDOW) ||
        evpl_rpc2_gss_wr_opaque(&p, end, token, token_len)) {
        evpl_rpc2_abort("Failed to marshall rpc_gss_init_res");
    }

    body_len = p - body;

    /* On completion, sign the seq_window so the client can verify us. */
    if (complete && thread->gss_provider && thread->gss_provider->get_mic) {
        uint32_t window_be = rpc2_hton32(RPCSEC_GSS_SEQ_WINDOW);
        void    *mic       = NULL;
        size_t   mic_len   = 0;

        if (thread->gss_provider->get_mic(thread->gss_provider_arg, ctx->gss_ctx,
                                          &window_be, sizeof(window_be),
                                          &mic, &mic_len) == 0) {
            request->reply_verf_data   = mic;
            request->reply_verf_len    = mic_len;
            request->reply_verf_flavor = RPCSEC_GSS;
        }
    }

    iov.length = EVPL_RPC2_GSS_REPLY_RESERVE + body_len;

    evpl_rpc2_send_reply(evpl, request, NULL, &iov, 1,
                         EVPL_RPC2_GSS_REPLY_RESERVE + body_len,
                         EVPL_RPC2_GSS_REPLY_RESERVE, MSG_ACCEPTED, SUCCESS);
} /* evpl_rpc2_gss_send_init_res */

/*
 * Handle a context-establishment leg (INIT / CONTINUE_INIT).  The argument
 * is an rpc_gss_init_arg, i.e. a single opaque GSS token at the front of the
 * call args.  Always consumes the request (sends a reply or drops it).
 */
static void
evpl_rpc2_gss_handle_init(
    struct evpl_rpc2_request        *request,
    const struct evpl_rpc2_gss_cred *cred,
    struct evpl_iovec               *req_iov,
    int                              req_niov,
    uint32_t                         request_length)
{
    struct evpl_rpc2_thread      *thread = request->thread;
    struct evpl                  *evpl   = thread->evpl;
    struct evpl_rpc2_conn        *conn   = request->conn;
    struct evpl_rpc2_gss_context *ctx;
    uint8_t                       lenbuf[4];
    const uint8_t                *lp = lenbuf;
    uint32_t                      token_len, gss_major;
    void                         *in_token  = NULL;
    void                         *out_token = NULL;
    size_t                        out_len   = 0;
    int                           complete  = 0;
    int                           rc;

    if (!thread->gss_provider) {
        evpl_rpc2_send_reply_denied(evpl, request, AUTH_REJECTEDCRED);
        return;
    }

    pthread_mutex_lock(&evpl_rpc2_gss_lock);

    /* INIT starts a new context; CONTINUE_INIT resumes an existing one. */
    if (cred->proc == RPCSEC_GSS_INIT) {
        ctx = evpl_rpc2_gss_ctx_create(conn);
    } else {
        uint32_t handle = 0;

        if (cred->handle_len == sizeof(handle)) {
            memcpy(&handle, cred->handle, sizeof(handle));
        }
        ctx = evpl_rpc2_gss_ctx_lookup(handle);
        if (!ctx) {
            pthread_mutex_unlock(&evpl_rpc2_gss_lock);
            evpl_rpc2_send_reply_denied(evpl, request, RPCSEC_GSS_CTXPROBLEM);
            return;
        }
    }

    /* Pull the GSS token (opaque<>) out of the call arguments. */
    if (evpl_rpc2_iov_gather(req_iov, req_niov, 0, lenbuf, 4)) {
        goto ctx_problem;
    }
    if (evpl_rpc2_gss_rd_u32(&lp, lenbuf + 4, &token_len)) {
        goto ctx_problem;
    }
    if (4 + (uint64_t) token_len > request_length) {
        goto ctx_problem;
    }

    if (token_len) {
        in_token = malloc(token_len);
        evpl_rpc2_abort_if(in_token == NULL, "Failed to allocate gss token");
        if (evpl_rpc2_iov_gather(req_iov, req_niov, 4, in_token, token_len)) {
            free(in_token);
            goto ctx_problem;
        }
    }

    rc = thread->gss_provider->accept(thread->gss_provider_arg, &ctx->gss_ctx,
                                      in_token, token_len,
                                      &out_token, &out_len, &complete,
                                      ctx->principal, sizeof(ctx->principal));
    free(in_token);

    if (rc) {
        evpl_rpc2_debug("rpcsec_gss: accept_sec_context failed");
        if (out_token) {
            free(out_token);
        }
        evpl_rpc2_gss_ctx_destroy(thread, ctx);
        pthread_mutex_unlock(&evpl_rpc2_gss_lock);
        evpl_rpc2_send_reply_denied(evpl, request, RPCSEC_GSS_CTXPROBLEM);
        return;
    }

    if (complete) {
        ctx->established = 1;
        gss_major        = EVPL_GSS_S_COMPLETE;
        evpl_rpc2_info("rpcsec_gss: context established for principal '%s'",
                       ctx->principal);
    } else {
        gss_major = EVPL_GSS_S_CONTINUE_NEEDED;
    }

    /* Builds the reply (and, on completion, the seq_window MIC verifier);
     * touches ctx->gss_ctx so it stays under the lock. */
    evpl_rpc2_gss_send_init_res(evpl, request, ctx, gss_major,
                                out_token, (uint32_t) out_len, complete);

    pthread_mutex_unlock(&evpl_rpc2_gss_lock);

    if (out_token) {
        free(out_token);
    }
    return;

 ctx_problem:
    if (cred->proc == RPCSEC_GSS_INIT) {
        evpl_rpc2_gss_ctx_destroy(thread, ctx);
    }
    pthread_mutex_unlock(&evpl_rpc2_gss_lock);
    evpl_rpc2_send_reply_denied(evpl, request, RPCSEC_GSS_CTXPROBLEM);
} /* evpl_rpc2_gss_handle_init */

/*
 * Front door for an incoming RPCSEC_GSS call.  Returns:
 *   1  -- a DATA request that passed verification; the caller should proceed
 *         to normal program dispatch (request->gss_context is populated).
 *   0  -- the request was fully handled here (init handshake, destroy,
 *         replay drop, or auth failure); the caller must not dispatch it.
 */
static int
evpl_rpc2_gss_handle_call(
    struct evpl_rpc2_request *request,
    const void               *cred_blob,
    uint32_t                  cred_blob_len,
    uint32_t                  verf_flavor,
    const void               *verf_blob,
    uint32_t                  verf_blob_len,
    uint32_t                  hdr_offset,
    struct evpl_iovec       **req_iov_p,
    int                      *req_niov_p,
    int                      *request_length_p)
{
    struct evpl_rpc2_thread      *thread = request->thread;
    struct evpl                  *evpl   = thread->evpl;
    struct evpl_rpc2_gss_cred     cred;
    struct evpl_rpc2_gss_context *ctx;
    uint32_t                      handle, seq_be, signed_len;
    uint8_t                       signed_buf[512];
    void                         *mic     = NULL;
    size_t                        mic_len = 0;

    if (!thread->gss_provider) {
        evpl_rpc2_send_reply_denied(evpl, request, AUTH_REJECTEDCRED);
        return 0;
    }

    if (evpl_rpc2_gss_decode_cred(cred_blob, cred_blob_len, &cred) ||
        cred.version != RPCSEC_GSS_VERS_1) {
        evpl_rpc2_send_reply_denied(evpl, request, AUTH_BADCRED);
        return 0;
    }

    switch (cred.proc) {
        case RPCSEC_GSS_INIT:
        case RPCSEC_GSS_CONTINUE_INIT:
            evpl_rpc2_gss_handle_init(request, &cred, *req_iov_p, *req_niov_p,
                                      *request_length_p);
            return 0;

        case RPCSEC_GSS_DESTROY:
            handle = 0;
            if (cred.handle_len == sizeof(handle)) {
                memcpy(&handle, cred.handle, sizeof(handle));
            }
            pthread_mutex_lock(&evpl_rpc2_gss_lock);
            ctx = evpl_rpc2_gss_ctx_lookup(handle);
            if (ctx) {
                evpl_rpc2_gss_ctx_destroy(thread, ctx);
            }
            pthread_mutex_unlock(&evpl_rpc2_gss_lock);
            /* Acknowledge with an empty successful reply. */
            evpl_rpc2_send_reply_error(evpl, request, SUCCESS);
            return 0;

        case RPCSEC_GSS_DATA:
            break;

        default:
            evpl_rpc2_send_reply_denied(evpl, request, AUTH_BADCRED);
            return 0;
    } /* switch */

    /* DATA: authentication (krb5) and integrity (krb5i) are supported.
     * Privacy (krb5p) wrapping is not yet implemented. */
    if (cred.service != EVPL_RPC2_GSS_SVC_NONE &&
        cred.service != EVPL_RPC2_GSS_SVC_INTEGRITY) {
        evpl_rpc2_debug("rpcsec_gss: DATA proc=%u service=%u unsupported "
                        "-> AUTH_TOOWEAK", cred.proc, cred.service);
        evpl_rpc2_send_reply_denied(evpl, request, AUTH_TOOWEAK);
        return 0;
    }

    handle = 0;
    if (cred.handle_len == sizeof(handle)) {
        memcpy(&handle, cred.handle, sizeof(handle));
    }

    pthread_mutex_lock(&evpl_rpc2_gss_lock);

    ctx = evpl_rpc2_gss_ctx_lookup(handle);
    if (!ctx || !ctx->established) {
        pthread_mutex_unlock(&evpl_rpc2_gss_lock);
        evpl_rpc2_debug("rpcsec_gss: DATA ctx lookup miss handle=%u hlen=%u "
                        "found=%d proc=%u service=%u", handle, cred.handle_len,
                        ctx ? 1 : 0, cred.proc, cred.service);
        evpl_rpc2_send_reply_denied(evpl, request, RPCSEC_GSS_CTXPROBLEM);
        return 0;
    }

    /* Verify the call verifier: a GSS MIC over the RPC header from the xid
     * through the credential (everything signed by the client before verf). */
    signed_len = 24 + 8 + evpl_rpc2_gss_pad4(cred_blob_len);
    if (verf_flavor != RPCSEC_GSS || signed_len > sizeof(signed_buf) ||
        evpl_rpc2_iov_gather(request->msg->recv_iov, request->msg->recv_niov,
                             hdr_offset, signed_buf, signed_len)) {
        pthread_mutex_unlock(&evpl_rpc2_gss_lock);
        evpl_rpc2_send_reply_denied(evpl, request, AUTH_BADVERF);
        return 0;
    }

    if (thread->gss_provider->verify_mic(thread->gss_provider_arg, ctx->gss_ctx,
                                         signed_buf, signed_len,
                                         verf_blob, verf_blob_len)) {
        pthread_mutex_unlock(&evpl_rpc2_gss_lock);
        evpl_rpc2_debug("rpcsec_gss: HEADER verify_mic failed proc=%u service=%u",
                        cred.proc, cred.service);
        evpl_rpc2_send_reply_denied(evpl, request, RPCSEC_GSS_CTXPROBLEM);
        return 0;
    }

    /* Replay/sequence-window enforcement; silently drop stale or replayed. */
    if (evpl_rpc2_gss_seq_check(ctx, cred.seq)) {
        pthread_mutex_unlock(&evpl_rpc2_gss_lock);
        evpl_rpc2_debug("rpcsec_gss: dropping replayed/stale seq %u", cred.seq);
        evpl_rpc2_request_free(thread, request);
        return 0;
    }

    /* For integrity, unwrap rpc_gss_integ_data -> inner proc args (verifies the
     * databody checksum + embedded seq).  The reply is wrapped symmetrically in
     * evpl_rpc2_send_reply, keyed on request->gss_service. */
    if (cred.service == EVPL_RPC2_GSS_SVC_INTEGRITY) {
        if (evpl_rpc2_gss_unwrap_integrity(request, ctx, cred.seq, req_iov_p,
                                           req_niov_p, request_length_p)) {
            pthread_mutex_unlock(&evpl_rpc2_gss_lock);
            evpl_rpc2_debug("rpcsec_gss: integrity UNWRAP failed proc=%u seq=%u "
                            "reqlen=%d", cred.proc, cred.seq, *request_length_p);
            evpl_rpc2_send_reply_denied(evpl, request, RPCSEC_GSS_CTXPROBLEM);
            return 0;
        }
    }

    /* Pre-compute the reply verifier: a GSS MIC over the request seq_num. */
    seq_be = rpc2_hton32(cred.seq);
    if (thread->gss_provider->get_mic(thread->gss_provider_arg, ctx->gss_ctx,
                                      &seq_be, sizeof(seq_be),
                                      &mic, &mic_len) == 0) {
        request->reply_verf_data   = mic;
        request->reply_verf_len    = mic_len;
        request->reply_verf_flavor = RPCSEC_GSS;
    }

    /* Copy out the principal so the request never dereferences the context
     * (which may be reaped concurrently once we drop the lock).  gss_handle +
     * gss_seq let the reply path re-find the context for the integrity MIC. */
    ctx->service = cred.service;
    snprintf(request->gss_principal, sizeof(request->gss_principal), "%s",
             ctx->principal);
    request->gss_authenticated = 1;
    request->gss_service       = cred.service;
    request->gss_handle        = handle;
    request->gss_seq           = cred.seq;

    pthread_mutex_unlock(&evpl_rpc2_gss_lock);

    return 1;
} /* evpl_rpc2_gss_handle_call */

SYMBOL_EXPORT void
evpl_rpc2_set_gss_provider(
    struct evpl_rpc2_thread             *thread,
    const struct evpl_rpc2_gss_provider *provider,
    void                                *provider_arg)
{
    thread->gss_provider     = provider;
    thread->gss_provider_arg = provider_arg;
} /* evpl_rpc2_set_gss_provider */

static void
evpl_rpc2_server_handle_request(
    struct evpl_rpc2_request   *request,
    struct evpl_iovec          *req_iov,
    int                         req_niov,
    int                         request_length,
    const struct authsys_parms *authsys,
    auth_flavor                 flavor)
{
    struct evpl_rpc2_conn   *conn   = request->conn;
    struct evpl_rpc2_thread *thread = request->thread;
    struct evpl             *evpl   = thread->evpl;
    struct evpl_rpc2_cred    cred;
    struct evpl_rpc2_cred   *cred_ptr = NULL;
    int                      error;

    /* Construct credential on stack from authsys data */
    if (flavor == AUTH_SYS && authsys) {
        evpl_rpc2_cred_init_authsys(&cred, authsys);
        cred_ptr = &cred;
    } else if (flavor == AUTH_NONE) {
        cred.flavor = AUTH_NONE;
        cred_ptr    = &cred;
    } else if (flavor == RPCSEC_GSS && request->gss_authenticated) {
        /* DATA request on an established GSS context (verified upstream in
         * evpl_rpc2_gss_handle_call).  Surface the authenticated principal
         * and service to the program layer. */
        cred.flavor        = EVPL_RPC2_AUTH_RPCSEC_GSS;
        cred.gss.principal = request->gss_principal;
        cred.gss.service   = request->gss_service;
        cred.gss.gss_ctx   = NULL;
        cred_ptr           = &cred;
    }
    /* cred_ptr remains NULL for unknown auth flavors */

    /* Initialize the encoding struct - the public interface for apps */
    request->encoding.program     = request->program;
    request->encoding.dbuf        = &request->msg->dbuf;
    request->encoding.read_chunk  = &request->read_chunk;
    request->encoding.write_chunk = &request->write_chunk;

    error = request->program->recv_call_dispatch(evpl, conn, &request->encoding,
                                                 request->proc,
                                                 request->program->program_data,
                                                 cred_ptr, req_iov, req_niov, request_length,
                                                 conn->server_private_data);

    if (unlikely(error)) {
        if (error == 1) {
            evpl_rpc2_error("rpc2 procedure %u not implemented", request->proc);
            evpl_rpc2_send_reply_error(evpl, request, PROC_UNAVAIL);
        } else if (error == 2) {
            evpl_rpc2_error("rpc2 failed to decode procedure %u arguments", request->proc);
            evpl_rpc2_send_reply_error(evpl, request, GARBAGE_ARGS);
        } else {
            evpl_rpc2_error("Failed to dispatch rpc2 call: %d", error);
            evpl_rpc2_send_reply_error(evpl, request, SYSTEM_ERR);
        }
    }

} /* evpl_rpc2_server_handle_request */

/*
 * Context for RDMA read completion callback.
 * Stores all data needed to dispatch the request after reads complete.
 */
struct evpl_rpc2_rdma_read_ctx {
    struct evpl_rpc2_request *request;
    struct evpl_iovec        *req_iov;
    int                       req_niov;
    int                       request_length;
    auth_flavor               flavor;
    /* authsys points into &request->msg->dbuf which persists */
};

static void
evpl_rpc2_read_segment_callback(
    int   status,
    void *private_data)
{
    struct evpl_rpc2_rdma_read_ctx *ctx     = private_data;
    struct evpl_rpc2_request       *request = ctx->request;
    const struct authsys_parms     *authsys;

    evpl_rpc2_abort_if(status, "Failed to read rdma segment");

    request->pending_reads--;

    if (request->pending_reads == 0) {
        /* authsys is stored right after the ctx in msg->dbuf */
        authsys = (ctx->flavor == AUTH_SYS) ? (const struct authsys_parms *) (ctx + 1) : NULL;
        evpl_rpc2_server_handle_request(request, ctx->req_iov, ctx->req_niov,
                                        ctx->request_length, authsys, ctx->flavor);
    }
} /* evpl_rpc2_read_segment_callback */

static void
evpl_rpc2_client_handle_reply(
    struct evpl_rpc2_request    *request,
    const struct evpl_rpc2_verf *verf,
    struct evpl_iovec           *reply_iov,
    int                          reply_niov,
    int                          reply_length)
{
    struct evpl_rpc2_thread *thread = request->thread;
    struct evpl_rpc2_conn   *conn   = request->conn;
    int                      error;
    struct evpl             *evpl = thread->evpl;

    if (request->read_chunk.niov) {
        /* Since server has replied, it will have finished reading our read chunk.
         * Release the iovecs we moved into request in evpl_rpc2_call. Since we used
         * evpl_iovec_move (not clone), the caller's original iovecs are now invalid
         * (data=NULL) and the caller does NOT need to release them. This matches
         * TCP behavior where marshalling moves iovecs inline.
         * This is functionally necessary to null now otherwise the xdr
         * unmarshalling code that comes next will incorrectly use it again
         * when unmarshalling the reply.
         */
        evpl_iovecs_release_internal(evpl, request->read_chunk.iov, request->read_chunk.niov);
        request->read_chunk.niov   = 0;
        request->read_chunk.length = 0;
    }

    if (request->write_chunk.niov) {
        /* Unmarshall code expects an RDMA chunk in this position */
        request->read_chunk.iov          = request->write_chunk.iov;
        request->read_chunk.niov         = request->write_chunk.niov;
        request->read_chunk.length       = request->write_chunk.length;
        request->read_chunk.xdr_position = UINT32_MAX;

        request->write_chunk.niov   = 0;
        request->write_chunk.length = 0;
    }

    error = request->program->recv_reply_dispatch(evpl, conn, &request->msg->dbuf,
                                                  request->proc,
                                                  &request->read_chunk,
                                                  verf, reply_iov, reply_niov, reply_length,
                                                  request->callback,
                                                  request->callback_arg);

    request->read_chunk.niov = 0;

    if (unlikely(error)) {
        evpl_rpc2_abort("Failed to dispatch rpc2 reply: %d", error);
    }

    evpl_rpc2_request_free(thread, request);
} /* evpl_rpc2_client_handle_reply */

static void
evpl_rpc2_recv_msg(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovec,
    int                niov,
    int                length,
    void              *private_data)
{
    struct evpl_rpc2_conn           *rpc2_conn = private_data;
    struct evpl_rpc2_thread         *thread    = rpc2_conn->thread;
    struct evpl_rpc2_msg            *msg;
    struct evpl_rpc2_request        *request;
    struct evpl_rpc2_server_binding *server_binding = rpc2_conn->server_binding;
    struct evpl_rpc2_program        *program;
    struct rpc_msg                   rpc_msg;
    struct rdma_msg                  rdma_msg;
    uint32_t                         hdr;
    struct evpl_iovec               *hdr_iov, *req_iov;
    int                              hdr_niov, req_niov;
    int                              i, rc, offset, rdma, request_length;
    struct xdr_read_list            *read_list;
    struct xdr_write_list           *write_list;
    struct evpl_iovec               *segment_iov;
    int                              segment_offset;
    auth_flavor                      flavor;
    struct authsys_parms            *authsys = NULL;

    /* Allocate msg first - this gives us a dbuf for unmarshalling */
    msg = evpl_rpc2_msg_alloc(thread);

    rdma = rpc2_conn->rdma;

    if (rdma) {
        /* RPC2 on RDMA has no header since its message based,
         * instead we should have an rdma_msg xdr structure
         * which describes the rdma particulars of the message */

        offset = unmarshall_rdma_msg(&rdma_msg,
                                     iovec,
                                     niov,
                                     NULL,
                                     &msg->dbuf);

    } else {
        /* We expect RPC2 on TCP to start with a 4 byte header.
         * Multi-fragment reassembly (RFC 5531 §11) is handled by
         * evpl_rpc2_reassemble; on the fast path (lone L=1 fragment)
         * it leaves iovec/niov/length untouched and sets offset=4. */

        rc = evpl_rpc2_reassemble(evpl, rpc2_conn,
                                  &iovec, &niov, &length, &offset);

        if (rc == 0) {
            /* Intermediate fragment stashed; await terminal fragment. */
            evpl_rpc2_msg_free(thread, msg);
            return;
        }

        if (rc < 0) {
            /* Cap exceeded; helper already released the delivered
             * iovecs and reset accumulator state. */
            evpl_rpc2_msg_free(thread, msg);
            evpl_close(evpl, bind);
            return;
        }

        if (offset == 4) {
            /* Fast path: validate the 4-byte record mark. */
            hdr = *(uint32_t *) iovec->data;
            hdr = rpc2_ntoh32(hdr);

            evpl_rpc2_abort_if((hdr & 0x7FFFFFFF) + 4 != length
                               ,
                               "RPC message length mismatch %d != %d",
                               (hdr & 0x7FFFFFFF) + 4, length);
        }
        /* offset == 0: reassembled iovec list with no leading mark. */
    }

    /* Pathological-fragmentation guard.  A peer that fragments one RPC into
     * hundreds of tiny record marks produces more payload iovecs than
     * config->max_num_iovec; flatten that into a minimal contiguous copy so
     * downstream consumers can rely on a bounded iovec count.  Only reachable
     * on the reassembled TCP path -- a single delivered fragment is already
     * capped at max_num_iovec -- so offset is 0 and the source array is the
     * heap accumulator owned here. */
    if (!rdma && niov > EVPL_RPC2_MAX_PAYLOAD_NIOV) {
        struct evpl_iovec *flat;
        int                flat_niov;

        flat = evpl_zalloc(sizeof(*flat) * EVPL_RPC2_MAX_PAYLOAD_NIOV);

        flat_niov = evpl_rpc2_flatten_iovecs(evpl, iovec, niov, length, flat,
                                             EVPL_RPC2_MAX_PAYLOAD_NIOV);

        evpl_rpc2_abort_if(flat_niov <= 0,
                           "Failed to flatten %d-iovec RPC payload (%d bytes)",
                           niov, length);

        evpl_iovecs_release_internal(evpl, iovec, niov);

        if (offset == 0) {
            /* Reassembled path: free the heap accumulator array. */
            evpl_free(iovec);
        }

        iovec  = flat;
        niov   = flat_niov;
        offset = 0;
    }

    hdr_iov = xdr_dbuf_alloc_space(sizeof(*hdr_iov) * niov, &msg->dbuf);

    evpl_rpc2_abort_if(hdr_iov == NULL, "Failed to allocate hdr iovec");

    hdr_niov = evpl_rpc2_iovec_skip(hdr_iov, iovec, niov, offset);

    rc = unmarshall_rpc_msg(&rpc_msg, hdr_iov, hdr_niov, NULL, &msg->dbuf);

    /* Clone recv iovecs to msg - this keeps the buffer data alive */
    msg->recv_iov = xdr_dbuf_alloc_space(sizeof(*msg->recv_iov) * niov, &msg->dbuf);

    evpl_rpc2_abort_if(msg->recv_iov == NULL, "Failed to allocate recv iovec");

    for (i = 0; i < niov; i++) {
        evpl_iovec_clone(&msg->recv_iov[i], &iovec[i]);
    }
    msg->recv_niov = niov;

    /* Release the original iovec array references from evpl_iovec_ring_copyv */
    evpl_iovecs_release_internal(evpl, iovec, niov);

    /* On the reassembled path, iovec points at the heap accumulator
     * array handed off by evpl_rpc2_reassemble; free it now that all
     * refs have been moved to msg->recv_iov. offset is set to 0 only
     * on the reassembled path (RDMA uses an unmarshalled RDMA header
     * length, TCP fast path uses 4). */
    if (!rdma && offset == 0) {
        evpl_free(iovec);
    }

    req_iov = xdr_dbuf_alloc_space(sizeof(*req_iov) * hdr_niov, &msg->dbuf);

    evpl_rpc2_abort_if(req_iov == NULL, "Failed to allocate req iovec");

    req_niov = evpl_rpc2_iovec_skip(req_iov, hdr_iov, hdr_niov, rc);

    /* Store req_iov in msg so it can be released when msg is freed */
    msg->req_iov  = req_iov;
    msg->req_niov = req_niov;

    /* Release hdr_iov references - they were addref'd by evpl_rpc2_iovec_skip */
    evpl_iovecs_release_internal(evpl, hdr_iov, hdr_niov);

    request_length = length - (rc + offset);

    switch (rpc_msg.body.mtype) {
        case CALL:
            /* Allocate request and attach msg */
            request      = evpl_rpc2_request_alloc(thread);
            request->msg = msg;

            request->m_inflight = thread->m_inflight[EVPL_RPC2_ROLE_SERVER];
            prometheus_gauge_add(request->m_inflight, 1);

            request->conn         = rpc2_conn;
            request->bind         = bind;
            request->xid          = rpc_msg.xid;
            request->encoding.xid = request->xid;
            request->proc         = rpc_msg.body.cbody.proc;
            prometheus_stopwatch_start(&request->timestamp);

            /* Parse credentials - authsys data is in msg->dbuf which persists */
            flavor = rpc_msg.body.cbody.cred.flavor;

            switch (flavor) {
                case AUTH_NONE:
                    /* No credential data needed for AUTH_NONE */
                    break;

                case AUTH_SYS:
                    /* authsys points into msg->dbuf - persists for request lifetime */
                    authsys = &rpc_msg.body.cbody.cred.authsys;
                    break;

                case RPCSEC_GSS:
                {
                    /* The credential and verifier bodies are opaque blobs in
                    * msg->dbuf; the GSS layer decodes/verifies them.  INIT,
                    * CONTINUE_INIT, DESTROY and replayed DATA are handled
                    * entirely there; a verified DATA request falls through to
                    * normal dispatch with request->gss_context populated. */
                    const void *cred_blob     = rpc_msg.body.cbody.cred.rpcsec_gss.data;
                    uint32_t    cred_blob_len = rpc_msg.body.cbody.cred.rpcsec_gss.len;
                    uint32_t    vflavor       = rpc_msg.body.cbody.verf.flavor;
                    const void *vblob         = NULL;
                    uint32_t    vlen          = 0;

                    if (vflavor == RPCSEC_GSS) {
                        vblob = rpc_msg.body.cbody.verf.rpcsec_gss.data;
                        vlen  = rpc_msg.body.cbody.verf.rpcsec_gss.len;
                    }

                    if (evpl_rpc2_gss_handle_call(request, cred_blob, cred_blob_len,
                                                  vflavor, vblob, vlen, offset,
                                                  &req_iov, &req_niov, &request_length) == 0) {
                        return;
                    }
                    break;
                }

                default:
                    /* Reject unsupported auth flavors */
                    evpl_rpc2_debug("Rejecting unsupported auth flavor %d", flavor);
                    evpl_rpc2_send_reply_denied(evpl, request, AUTH_TOOWEAK);
                    return;
            } /* switch */

            if (rdma) {
                /* Grant the requester exactly the credit it asked for.  Per
                 * RFC 8166 this is the max number of RPCs the client may keep
                 * outstanding on this connection; previously we shipped an
                 * uninitialized request->rdma_credits (always 0), which the
                 * Linux client floored to 1 -- serializing each connection.
                 * NOTE: experimental echo with no server-side ceiling; a
                 * proper grant should clamp to receive capacity. */
                request->rdma_credits = rdma_msg.rdma_credit ? rdma_msg.rdma_credit : 1;

                if (rdma_msg.rdma_body.proc == RDMA_MSG) {

                    read_list = rdma_msg.rdma_body.rdma_msg.rdma_reads;

                    if (read_list) {
                        request->read_chunk.xdr_position = read_list->entry.position - rc;
                    }

                    while (read_list) {
                        request->read_chunk.length += read_list->entry.target.length;

                        read_list = read_list->next;
                    }

                    request->read_chunk.iov = xdr_dbuf_alloc_space(sizeof(*request->read_chunk.iov), &msg->dbuf);

                    evpl_rpc2_abort_if(request->read_chunk.iov == NULL, "Failed to allocate read chunk iovec");

                    request->read_chunk.niov = evpl_iovec_alloc(evpl, request->read_chunk.length, 4096, 1, 0,
                                                                request->read_chunk.iov);

                    read_list = rdma_msg.rdma_body.rdma_msg.rdma_reads;

                    segment_offset = 0;

                    while (read_list) {
                        /* Allocate context for RDMA read callback */
                        struct evpl_rpc2_rdma_read_ctx *ctx;
                        size_t                          ctx_size = sizeof(*ctx);

                        /* If AUTH_SYS, allocate space for authsys after ctx */
                        if (flavor == AUTH_SYS) {
                            ctx_size += sizeof(struct authsys_parms);
                        }

                        ctx = xdr_dbuf_alloc_space(ctx_size, &msg->dbuf);
                        evpl_rpc2_abort_if(ctx == NULL, "Failed to allocate rdma read ctx");

                        ctx->request        = request;
                        ctx->req_iov        = req_iov;
                        ctx->req_niov       = req_niov;
                        ctx->request_length = request_length;
                        ctx->flavor         = flavor;

                        /* Copy authsys right after ctx if needed */
                        if (flavor == AUTH_SYS && authsys) {
                            struct authsys_parms *ctx_authsys = (struct authsys_parms *) (ctx + 1);
                            *ctx_authsys = *authsys;
                        }

                        segment_iov = xdr_dbuf_alloc_space(sizeof(*segment_iov), &msg->dbuf);

                        evpl_rpc2_abort_if(segment_iov == NULL, "Failed to allocate segment iovec");

                        evpl_iovec_clone_segment(segment_iov, request->read_chunk.iov, segment_offset,
                                                 read_list->entry.target.length);

                        evpl_rdma_read(evpl, request->bind,
                                       read_list->entry.target.handle, read_list->entry.target.offset,
                                       segment_iov, 1,
                                       evpl_rpc2_read_segment_callback, ctx);

                        /* evpl_rdma_read takes its own clone, so release our reference */
                        evpl_iovec_release_internal(evpl, segment_iov);

                        request->pending_reads++;

                        segment_offset += read_list->entry.target.length;

                        read_list = read_list->next;
                    }

                    write_list = rdma_msg.rdma_body.rdma_msg.rdma_writes;

                    while (write_list) {

                        for (i = 0; i < write_list->entry.num_target; i++) {
                            request->write_chunk.max_length += write_list->entry.target[i].length;
                        }

                        evpl_rpc2_abort_if(write_list->entry.num_target >
                                           (int) (sizeof(request->write_segments.segments) /
                                                  sizeof(request->write_segments.segments[0])),
                                           "Too many RPC2 RDMA write segments: %u",
                                           write_list->entry.num_target);

                        request->write_segments.num_segments = write_list->entry.num_target;
                        memcpy(request->write_segments.segments,
                               write_list->entry.target,
                               write_list->entry.num_target * sizeof(struct xdr_rdma_segment));

                        write_list = write_list->next;
                    }

                    if (rdma_msg.rdma_body.rdma_msg.rdma_reply) {
                        evpl_rpc2_abort_if(rdma_msg.rdma_body.rdma_msg.rdma_reply->num_target >
                                           (int) (sizeof(request->reply_segments.segments) /
                                                  sizeof(request->reply_segments.segments[0])),
                                           "Too many RPC2 RDMA reply segments: %u",
                                           rdma_msg.rdma_body.rdma_msg.rdma_reply->num_target);

                        request->reply_segments.num_segments =
                            rdma_msg.rdma_body.rdma_msg.rdma_reply->num_target;
                        memcpy(request->reply_segments.segments,
                               rdma_msg.rdma_body.rdma_msg.rdma_reply->target,
                               request->reply_segments.num_segments * sizeof(struct xdr_rdma_segment));
                    }

                } else {
                    evpl_rpc2_error("rpc2 received rdma msg with unhandled proc %d", rdma_msg.rdma_body.proc);
                }
            }

            request->program = NULL;

            for (i = 0; i < rpc2_conn->num_server_programs; i++) {
                program = rpc2_conn->server_programs[i];

                if (program->program == rpc_msg.body.cbody.prog &&
                    program->version == rpc_msg.body.cbody.vers) {

                    request->program = program;
                    request->metric  = server_binding ? server_binding->metrics[i][request->proc] : NULL;
                    break;
                }
            }

            if (unlikely(!request->program)) {
                evpl_rpc2_debug(
                    "rpc2 received call for unknown program %u vers %u",
                    rpc_msg.body.cbody.prog,
                    rpc_msg.body.cbody.vers);

                evpl_rpc2_send_reply_error(evpl, request, PROG_MISMATCH);
                return;
            }

            if (request->pending_reads == 0) {
                evpl_rpc2_server_handle_request(request, req_iov, req_niov, request_length, authsys, flavor);
            }
            break;
        case REPLY:
        {
            /* AUTH_SHORT is not implemented - pass empty verifier */
            struct evpl_rpc2_verf verf = { .data = NULL, .len = 0 };

            /* Find request by xid */
            HASH_FIND(hh, rpc2_conn->pending_calls, &rpc_msg.xid, sizeof(rpc_msg.xid), request);

            if (unlikely(!request)) {
                /* A REPLY that matches no outstanding call is benign: it is a
                 * late, duplicate, or already-timed-out reply (e.g. an NFSv4.1
                 * backchannel call we have already reaped).  ONC RPC has no way
                 * to acknowledge a reply, so the only correct action is to drop
                 * it.  Do not tear down the connection: each RDMA receive is a
                 * discrete message and each TCP record is independently framed,
                 * so a stray reply cannot desync the stream. */
                evpl_rpc2_debug("rpc2 dropping reply for unknown call %u", rpc_msg.xid);
                evpl_rpc2_msg_free(thread, msg);
                return;
            }

            HASH_DELETE(hh, rpc2_conn->pending_calls, request);

            /* Free the old msg allocated for the call, replace with reply msg */
            if (request->msg) {
                evpl_rpc2_msg_free(thread, request->msg);
            }
            request->msg = msg;

            evpl_rpc2_client_handle_reply(request, &verf, req_iov, req_niov, request_length);
        }
        break;
        default:
            evpl_rpc2_error("rpc2 received unexpected message type %d", rpc_msg.body.mtype);
            evpl_rpc2_msg_free(thread, msg);
            evpl_close(evpl, bind);
    } /* switch */

} /* evpl_rpc2_recv_msg */


static void
evpl_rpc2_event(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct evpl_rpc2_conn    *rpc2_conn   = private_data;
    struct evpl_rpc2_thread  *rpc2_thread = rpc2_conn->thread;
    struct evpl_rpc2_notify   rpc2_notify;
    struct evpl_rpc2_request *rpc2_request, *tmp;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            if (rpc2_conn->thread->notify_callback) {
                rpc2_notify.notify_type = EVPL_RPC2_NOTIFY_CONNECTED;
                rpc2_thread->notify_callback(rpc2_thread, rpc2_conn, &rpc2_notify, rpc2_thread->private_data
                                             );
            }
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            DL_DELETE(rpc2_thread->conns, rpc2_conn);
            HASH_ITER(hh, rpc2_conn->pending_calls, rpc2_request, tmp)
            {
                HASH_DELETE(hh, rpc2_conn->pending_calls, rpc2_request);
                evpl_rpc2_request_free(rpc2_conn->thread, rpc2_request);
            }
            if (rpc2_conn->thread->notify_callback) {
                rpc2_notify.notify_type = EVPL_RPC2_NOTIFY_DISCONNECTED;
                rpc2_conn->thread->notify_callback(rpc2_conn->thread, rpc2_conn, &rpc2_notify, rpc2_thread->private_data
                                                   );
            }
            /* Release any iovecs stashed mid-reassembly. */
            evpl_rpc2_reasm_reset(evpl, rpc2_conn);
            /* Tear down any RPCSEC_GSS contexts established on this conn. */
            evpl_rpc2_gss_conn_cleanup(rpc2_conn->thread, rpc2_conn);
            free(rpc2_conn);
            break;
        case EVPL_NOTIFY_RECV_MSG:

            evpl_rpc2_recv_msg(evpl,
                               bind,
                               notify->recv_msg.iovec, notify->recv_msg.niov, notify->recv_msg.length,
                               private_data);
            break;
    } /* switch */

} /* evpl_rpc2_event */

static void
evpl_rpc2_accept(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    struct evpl_rpc2_server_binding *server_binding = private_data;
    struct evpl_rpc2_conn           *rpc2_conn;
    struct evpl_rpc2_notify          rpc2_notify;

    rpc2_conn                 = evpl_zalloc(sizeof(*rpc2_conn));
    rpc2_conn->server_binding = server_binding;
    rpc2_conn->thread         = server_binding->thread;
    rpc2_conn->bind           = bind;
    rpc2_conn->protocol       = evpl_bind_get_protocol(bind);
    rpc2_conn->rdma           = evpl_bind_is_rdma(bind);

    memcpy(rpc2_conn->server_programs,
           server_binding->server->programs,
           server_binding->server->nprograms * sizeof(*rpc2_conn->server_programs));

    rpc2_conn->num_server_programs = server_binding->server->nprograms;
    rpc2_conn->server_private_data = server_binding->private_data;

    *notify_callback   = evpl_rpc2_event;
    *segment_callback  = rpc2_segment_callback;
    *conn_private_data = rpc2_conn;

    DL_APPEND(server_binding->thread->conns, rpc2_conn);

    if (server_binding->thread->notify_callback) {
        rpc2_notify.notify_type = EVPL_RPC2_NOTIFY_ACCEPTED;
        server_binding->thread->notify_callback(server_binding->thread,
                                                rpc2_conn,
                                                &rpc2_notify,
                                                server_binding->
                                                private_data);
    }

} /* evpl_rpc2_accept */

SYMBOL_EXPORT struct evpl_rpc2_thread *
evpl_rpc2_thread_init(
    struct evpl                *evpl,
    struct evpl_rpc2_program  **programs,
    int                         nprograms,
    evpl_rpc2_notify_callback_t notify_callback,
    void                       *private_data)
{
    struct evpl_rpc2_thread *thread;
    char                     thread_id_str[16];
    int                      role;

    thread = evpl_zalloc(sizeof(*thread));

    thread->evpl            = evpl;
    thread->nprograms       = nprograms;
    thread->notify_callback = notify_callback;
    thread->private_data    = private_data;
    thread->client_dbuf     = xdr_dbuf_alloc(128 * 1024);

    thread->id = __atomic_fetch_add(&evpl_rpc2_next_thread_id, 1,
                                    __ATOMIC_RELAXED);

    /* One in-flight gauge instance per role, labelled with role and thread
     * id.  The I/O path mutates the instance on this thread only. */
    snprintf(thread_id_str, sizeof(thread_id_str), "%d", thread->id);

    for (role = 0; role < EVPL_RPC2_NUM_ROLES; ++role) {
        thread->m_inflight_series[role] =
            evpl_rpc2_queue_depth_create_series(
                evpl_rpc2_role_names[role],
                thread_id_str);
        thread->m_inflight[role] = prometheus_gauge_series_create_instance(
            thread->m_inflight_series[role]);
    }

    if (nprograms) {
        thread->programs = evpl_zalloc(nprograms * sizeof(*programs));
        memcpy(thread->programs, programs, nprograms * sizeof(*programs));
    } else {
        thread->programs = NULL;
    }

    return thread;
} /* evpl_rpc2_thread_init */

SYMBOL_EXPORT void
evpl_rpc2_thread_destroy(struct evpl_rpc2_thread *thread)
{
    struct evpl_rpc2_msg     *msg;
    struct evpl_rpc2_request *request;
    struct evpl_rpc2_conn    *rpc2_conn;
    int                       role;

    DL_FOREACH(thread->conns, rpc2_conn)
    {
        evpl_close(thread->evpl, rpc2_conn->bind);
    }

    while (thread->conns) {
        evpl_continue(thread->evpl);
    }

    while (thread->free_msg) {
        msg = thread->free_msg;
        LL_DELETE(thread->free_msg, msg);
        xdr_dbuf_destroy(&msg->dbuf);
        evpl_free(msg);
    }

    while (thread->free_requests) {
        request = thread->free_requests;
        LL_DELETE(thread->free_requests, request);
        evpl_free(request);
    }

    if (thread->programs) {
        evpl_free(thread->programs);
    }

    if (thread->client_dbuf) {
        xdr_dbuf_free(thread->client_dbuf);
    }

    for (role = 0; role < EVPL_RPC2_NUM_ROLES; ++role) {
        if (thread->m_inflight[role]) {
            prometheus_gauge_series_destroy_instance(
                thread->m_inflight_series[role],
                thread->m_inflight[role]);
        }

        if (thread->m_inflight_series[role]) {
            evpl_rpc2_queue_depth_destroy_series(
                thread->m_inflight_series[role]);
        }
    }

    evpl_free(thread);
} /* evpl_rpc2_thread_destroy */

SYMBOL_EXPORT void *
evpl_rpc2_thread_get_client_dbuf(struct evpl_rpc2_thread *thread)
{
    xdr_dbuf_reset(thread->client_dbuf);
    return thread->client_dbuf;
} /* evpl_rpc2_thread_get_client_dbuf */

SYMBOL_EXPORT struct evpl_rpc2_server *
evpl_rpc2_server_init(
    struct evpl_rpc2_program **programs,
    int                        nprograms)
{
    struct evpl_rpc2_server *server;

    server = evpl_zalloc(sizeof(*server));

    server->listener = evpl_listener_create();

    server->programs  = evpl_zalloc(nprograms * sizeof(*programs));
    server->nprograms = nprograms;
    memcpy(server->programs, programs, nprograms * sizeof(*programs));

    for (int i = 0; i < nprograms; i++) {
        server->programs[i]->send_reply_dispatch = evpl_rpc2_send_reply_success;
    }

    return server;
} /* evpl_rpc2_listen */

SYMBOL_EXPORT void
evpl_rpc2_server_start(
    struct evpl_rpc2_server *server,
    int                      protocol,
    struct evpl_endpoint    *endpoint)
{
    evpl_listen(
        server->listener,
        protocol,
        endpoint);
} /* evpl_rpc2_start */

SYMBOL_EXPORT void
evpl_rpc2_server_attach(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_server *server,
    void                    *private_data)
{
    struct evpl_rpc2_server_binding *server_binding;
    struct evpl_rpc2_program        *program;
    int                              i, j;

    server_binding = evpl_zalloc(sizeof(*server_binding));

    server_binding->thread       = thread;
    server_binding->server       = server;
    server_binding->private_data = private_data;
    server_binding->metrics      = evpl_zalloc(server->nprograms * sizeof(*server_binding->metrics));

    for (i = 0; i < server->nprograms; i++) {

        program = server->programs[i];

        server_binding->metrics[i] = evpl_zalloc(
            (program->maxproc + 1) * sizeof(struct prometheus_histogram_instance *)
            );

        for (j = 0; j <= program->maxproc; j++) {
            if (program->metrics && program->metrics[j]) {
                server_binding->metrics[i][j] = prometheus_histogram_series_create_instance(program->metrics[j]);
            }
        }
    }

    server_binding->binding = evpl_listener_attach(
        thread->evpl,
        server->listener,
        evpl_rpc2_accept,
        server_binding);

    DL_APPEND(thread->servers, server_binding);

} /* evpl_rpc2_attach */

SYMBOL_EXPORT void
evpl_rpc2_server_detach(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_server *server)
{
    int                              i, j;
    struct evpl_rpc2_program        *program;
    struct evpl_rpc2_server_binding *server_binding;

    DL_FOREACH(thread->servers, server_binding)
    {
        if (server_binding->server == server) {
            break;
        }
    }

    evpl_rpc2_abort_if(!server_binding, "Server binding not found");

    DL_DELETE(thread->servers, server_binding);

    evpl_listener_detach(thread->evpl, server_binding->binding);

    for (i = 0; i < server->nprograms; i++) {
        program = server->programs[i];
        for (j = 0; j <= program->maxproc; j++) {
            if (server_binding->metrics[i][j]) {
                prometheus_histogram_series_destroy_instance(program->metrics[j], server_binding->metrics[i][j]);
            }
        }
    }

    for (i = 0; i < server->nprograms; i++) {
        evpl_free(server_binding->metrics[i]);
    }

    evpl_free(server_binding->metrics);
    evpl_free(server_binding);

} /* evpl_rpc2_detach */

SYMBOL_EXPORT void
evpl_rpc2_server_stop(struct evpl_rpc2_server *server)
{
    evpl_listener_destroy(server->listener);
    server->listener = NULL;
} /* evpl_rpc2_stop */

SYMBOL_EXPORT void
evpl_rpc2_server_destroy(struct evpl_rpc2_server *server)
{
    if (server->listener) {
        evpl_listener_destroy(server->listener);
    }

    evpl_free(server->programs);
    evpl_free(server);
} /* evpl_rpc2_server_destroy */

SYMBOL_EXPORT struct evpl_rpc2_conn *
evpl_rpc2_client_connect(
    struct evpl_rpc2_thread   *thread,
    int                        protocol,
    struct evpl_endpoint      *endpoint,
    struct evpl_rpc2_program **server_programs,
    int                        num_server_programs,
    void                      *server_private_data)
{
    struct evpl_rpc2_conn *conn;
    int                    i;

    conn = evpl_zalloc(sizeof(*conn));

    conn->thread         = thread;
    conn->protocol       = protocol;
    conn->server_binding = NULL;
    conn->next_xid       = 1;

    memcpy(conn->server_programs, server_programs, num_server_programs * sizeof(*conn->server_programs));
    conn->num_server_programs = num_server_programs;
    conn->server_private_data = server_private_data;

    for (i = 0; i < num_server_programs; i++) {
        conn->server_programs[i]->send_reply_dispatch = evpl_rpc2_send_reply_success;
    }

    DL_APPEND(thread->conns, conn);

    conn->bind = evpl_connect(
        thread->evpl,
        protocol,
        NULL,  /* local_endpoint - let system choose */
        endpoint,  /* remote_endpoint */
        evpl_rpc2_event,
        rpc2_segment_callback,
        conn);

    if (!conn->bind) {
        DL_DELETE(thread->conns, conn);
        evpl_free(conn);
        return NULL;
    }

    conn->rdma = evpl_bind_is_rdma(conn->bind);

    return conn;
} /* evpl_rpc2_client_connect */

SYMBOL_EXPORT void
evpl_rpc2_client_disconnect(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_conn   *conn)
{
    evpl_close(thread->evpl, conn->bind);
} /* evpl_rpc2_client_destroy */

SYMBOL_EXPORT int
evpl_rpc2_call(
    struct evpl                 *evpl,
    struct evpl_rpc2_program    *program,
    struct evpl_rpc2_conn       *conn,
    const struct evpl_rpc2_cred *cred,
    uint32_t                     procedure,
    struct evpl_iovec           *req_iov,
    int                          req_niov,
    int                          req_length,
    struct evpl_rpc2_rdma_chunk *rdma_chunk,
    int                          max_rdma_write_chunk,
    struct evpl_iovec           *write_chunk_iov,
    int                          write_chunk_niov,
    int                          max_rdma_reply_chunk,
    void                        *callback,
    void                        *private_data)
{
    struct evpl_rpc2_thread  *thread = conn->thread;
    struct evpl_rpc2_request *request;
    struct evpl_rpc2_msg     *msg;
    struct rpc_msg            rpc_msg;
    struct rdma_msg           rdma_msg;
    struct evpl_iovec         hdr_iov, hdr_out_iov;
    struct xdr_read_list      read_list;
    struct xdr_write_list     write_list;
    struct xdr_rdma_segment   write_chunk_segment;
    int                       transport_hdr_len, rpc_len, i;
    int                       out_niov   = 1;
    int                       pay_length = req_length - program->reserve;
    int                       total_length;
    int                       rdma = conn->rdma;

    /* Allocate request for the exchange */
    request = evpl_rpc2_request_alloc(thread);

    request->m_inflight = thread->m_inflight[EVPL_RPC2_ROLE_CLIENT];
    prometheus_gauge_add(request->m_inflight, 1);

    /* Allocate msg for client - needed for dbuf in RDMA case */
    msg          = evpl_rpc2_msg_alloc(thread);
    request->msg = msg;

    request->conn         = conn;
    request->program      = program;
    request->xid          = conn->next_xid++;
    request->proc         = procedure;
    request->callback     = callback;
    request->callback_arg = private_data;

    HASH_ADD(hh, conn->pending_calls, xid, sizeof(request->xid), request);

    rpc_msg.xid                    = request->xid;
    rpc_msg.body.mtype             = CALL;
    rpc_msg.body.cbody.rpcvers     = 2;
    rpc_msg.body.cbody.prog        = program->program;
    rpc_msg.body.cbody.vers        = program->version;
    rpc_msg.body.cbody.proc        = procedure;
    rpc_msg.body.cbody.verf.flavor = AUTH_NONE;

    /* Set credentials based on cred parameter */
    if (cred && cred->flavor == AUTH_SYS) {
        /* Populate authsys directly in the opaque_union - marshalling handles length prefix */
        rpc_msg.body.cbody.cred.flavor                  = AUTH_SYS;
        rpc_msg.body.cbody.cred.authsys.stamp           = 0;
        rpc_msg.body.cbody.cred.authsys.machinename.str = (char *) cred->authsys.machinename;
        rpc_msg.body.cbody.cred.authsys.machinename.len = cred->authsys.machinename_len;
        rpc_msg.body.cbody.cred.authsys.uid             = cred->authsys.uid;
        rpc_msg.body.cbody.cred.authsys.gid             = cred->authsys.gid;
        rpc_msg.body.cbody.cred.authsys.num_gids        = cred->authsys.num_gids;
        rpc_msg.body.cbody.cred.authsys.gids            = cred->authsys.gids;
    } else {
        rpc_msg.body.cbody.cred.flavor = AUTH_NONE;
    }

    rpc_len = marshall_length_rpc_msg(&rpc_msg);

    if (rdma) {
        rdma_msg.rdma_xid                       = request->xid;
        rdma_msg.rdma_vers                      = 1;
        rdma_msg.rdma_credit                    = 1;
        rdma_msg.rdma_body.proc                 = RDMA_MSG;
        rdma_msg.rdma_body.rdma_msg.rdma_reads  = NULL;
        rdma_msg.rdma_body.rdma_msg.rdma_writes = NULL;
        rdma_msg.rdma_body.rdma_msg.rdma_reply  = NULL;

        if (rdma_chunk && rdma_chunk->niov > 0) {
            evpl_rpc2_abort_if(rdma_chunk->niov > 1, "rdma_chunk niov is greater than 1");

            /* Get RDMA address BEFORE moving iovecs (move invalidates source) */
            rdma_msg.rdma_body.rdma_msg.rdma_reads = &read_list;
            read_list.next                         = NULL;
            read_list.entry.position               = rdma_chunk->xdr_position + rpc_len;
            read_list.entry.target.length          = rdma_chunk->length;

            evpl_rdma_get_address(evpl, conn->bind,
                                  rdma_chunk->iov,
                                  &read_list.entry.target.handle,
                                  &read_list.entry.target.offset);

            /* Move iovecs from caller to request (transfers ownership, invalidates caller's iovecs).
             * This matches TCP behavior where marshalling moves iovecs inline. */
            request->read_chunk.iov = xdr_dbuf_alloc_space(sizeof(*request->read_chunk.iov) * rdma_chunk->niov,
                                                           &msg->dbuf);

            evpl_rpc2_abort_if(request->read_chunk.iov == NULL, "Failed to allocate read chunk iovec");

            for (i = 0; i < rdma_chunk->niov; i++) {
                evpl_iovec_move(&request->read_chunk.iov[i], &rdma_chunk->iov[i]);
            }
            request->read_chunk.niov         = rdma_chunk->niov;
            request->read_chunk.length       = rdma_chunk->length;
            request->read_chunk.max_length   = rdma_chunk->max_length;
            request->read_chunk.xdr_position = rdma_chunk->xdr_position;
        }

        if (max_rdma_write_chunk) {

            request->write_chunk.iov = xdr_dbuf_alloc_space(sizeof(*request->write_chunk.iov), &msg->dbuf);

            evpl_rpc2_abort_if(request->write_chunk.iov == NULL, "Failed to allocate write chunk iovec");

            if (write_chunk_iov && write_chunk_niov == 1) {
                /* read-into: borrow the caller's buffer as the write-chunk
                 * destination so the server RDMA-writes the reply data straight
                 * into it (zero copy).  Shallow-copy the iovec (no ref taken --
                 * the caller keeps ownership and the buffer alive until the
                 * reply); write_chunk_borrowed keeps the free path from releasing
                 * it.  evpl_rdma_get_address reads the registration off the
                 * caller's (same-evpl, registered) buffer below. */
                request->write_chunk.iov[0]   = write_chunk_iov[0];
                request->write_chunk.niov     = 1;
                request->write_chunk.length   = max_rdma_write_chunk;
                request->write_chunk_borrowed = 1;
            } else {
                request->write_chunk.niov = evpl_iovec_alloc(evpl, max_rdma_write_chunk, 4096, 1, 0,
                                                             request->write_chunk.iov);
                request->write_chunk.length = max_rdma_write_chunk;
            }

            rdma_msg.rdma_body.rdma_msg.rdma_writes = &write_list;
            write_list.next                         = NULL;
            write_list.entry.num_target             = 1;
            write_list.entry.target                 = &write_chunk_segment;

            evpl_rdma_get_address(evpl, conn->bind,
                                  request->write_chunk.iov,
                                  &write_chunk_segment.handle,
                                  &write_chunk_segment.offset);

            write_chunk_segment.length = max_rdma_write_chunk;

        }


        transport_hdr_len = marshall_length_rdma_msg(&rdma_msg);
    } else {
        transport_hdr_len = 4;
    }

    total_length = transport_hdr_len + rpc_len + pay_length;

    /* Adjust iovec to point to where payload data starts */
    req_iov[0].data   = (char *) req_iov[0].data + (program->reserve - (rpc_len + transport_hdr_len));
    req_iov[0].length = req_iov[0].length - (program->reserve - (rpc_len + transport_hdr_len));

    hdr_iov = req_iov[0];

    marshall_rpc_msg(&rpc_msg, &hdr_iov, &hdr_out_iov, &out_niov, NULL, transport_hdr_len);

    if (out_niov > 0) {
        evpl_iovec_release_internal(evpl, &hdr_out_iov);
    }

    if (rdma) {
        marshall_rdma_msg(&rdma_msg, &hdr_iov, &hdr_out_iov, &out_niov, NULL, 0);
        /* Release the RDMA header iovec - the actual data is in req_iov which gets sent */
        evpl_iovec_release_internal(evpl, &hdr_out_iov);
    } else {
        /* Add 4-byte record marking header for TCP at the start of the output buffer */
        *(uint32_t *) req_iov[0].data = rpc2_hton32((total_length - 4) | 0x80000000);
    }

    /* Send the request - use out_iov which contains the marshalled header + payload */

    evpl_sendv(evpl, conn->bind, req_iov, req_niov, total_length, EVPL_SEND_FLAG_TAKE_REF);

    return 0;
} /* evpl_rpc2_call */

SYMBOL_EXPORT void
evpl_rpc2_conn_get_local_address(
    struct evpl_rpc2_conn *conn,
    char                  *str,
    int                    len)
{
    evpl_bind_get_local_address(conn->bind, str, len);
} /* evpl_rpc2_conn_get_local_address */

SYMBOL_EXPORT void
evpl_rpc2_conn_get_remote_address(
    struct evpl_rpc2_conn *conn,
    char                  *str,
    int                    len)
{
    evpl_bind_get_remote_address(conn->bind, str, len);
} /* evpl_rpc2_conn_get_remote_address */

SYMBOL_EXPORT void
evpl_rpc2_conn_set_private_data(
    struct evpl_rpc2_conn *conn,
    void                  *private_data)
{
    conn->private_data = private_data;
} /* evpl_rpc2_conn_set_private_data */

SYMBOL_EXPORT void *
evpl_rpc2_conn_get_private_data(struct evpl_rpc2_conn *conn)
{
    return conn->private_data;
} /* evpl_rpc2_conn_get_private_data */
