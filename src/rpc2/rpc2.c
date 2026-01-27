// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <complex.h>
#define _GNU_SOURCE
#include <time.h>
#include <utlist.h>
#include <uthash.h>

#include "core/evpl.h"
#include "evpl/evpl_rpc2.h"
#include "evpl/evpl_rdma.h"

#include "rpc2/common.h"
#include "rpc2_xdr.h"
#include "rpcrdma1_xdr.h"
#include "evpl/evpl_rpc2_program.h"
#include "evpl/evpl.h"
#include "core/timing.h"
#include "core/macros.h"

#include "prometheus-c.h"

#include "rpc2/rpc2_cursor.h"
#include "rpc2/rpc2_cred.h"

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
    struct evpl_bind                     *bind;
    struct evpl_rpc2_conn                *conn;
    struct evpl_rpc2_thread              *thread;
    struct evpl_rpc2_program             *program;
    struct timespec                       timestamp;
    struct prometheus_histogram_instance *metric;
    void                                 *callback;
    void                                 *callback_arg;
    struct UT_hash_handle                 hh;
    struct evpl_rpc2_rdma_chunk           read_chunk;
    struct evpl_rpc2_rdma_chunk           write_chunk;
    struct evpl_rpc2_rdma_segment_list    reply_segments;
    struct evpl_rpc2_rdma_segment_list    write_segments;
    struct evpl_iovec                     reply_segment_iov;
    struct evpl_rpc2_msg                 *msg;
    struct evpl_rpc2_request             *next;
    struct evpl_rpc2_encoding             encoding; /* Public interface for apps */
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
    struct evpl                     *evpl;
    struct evpl_rpc2_program       **programs;
    int                              nprograms;
    struct evpl_rpc2_conn           *conns;
    evpl_rpc2_notify_callback_t      notify_callback;
    void                            *private_data;
    struct evpl_rpc2_msg            *free_msg;
    struct evpl_rpc2_request        *free_requests;
    struct evpl_rpc2_server_binding *servers;
    xdr_dbuf                        *client_dbuf;
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

    evpl_iovecs_release(evpl, msg->recv_iov, msg->recv_niov);
    evpl_iovecs_release(evpl, msg->req_iov, msg->req_niov);

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
    request->pending_reads               = 0;
    request->read_chunk.niov             = 0;
    request->read_chunk.length           = 0;
    request->write_chunk.niov            = 0;
    request->write_chunk.length          = 0;
    request->write_chunk.max_length      = 0;
    request->write_segments.num_segments = 0;
    request->reply_segments.num_segments = 0;
    request->msg                         = NULL;

    return request;
} /* evpl_rpc2_request_alloc */

static inline void
evpl_rpc2_request_free(
    struct evpl_rpc2_thread  *thread,
    struct evpl_rpc2_request *request)
{
    struct evpl *evpl = thread->evpl;

    evpl_iovecs_release(evpl, request->read_chunk.iov, request->read_chunk.niov);
    evpl_iovecs_release(evpl, request->write_chunk.iov, request->write_chunk.niov);

    if (request->msg) {
        evpl_rpc2_msg_free(thread, request->msg);
        request->msg = NULL;
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

    if (unlikely(!(hdr & 0x80000000))) {
        evpl_rpc2_error(
            "Fragmented RPC messages are not yet supported, disconnecting...");
        return -1;
    }

    return (hdr & 0x7FFFFFFF) + 4;
} /* rpc2_segment_callback */

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
    int                           reply_len, reply_niov, offset, rpc_len;
    uint32_t                      hdr, write_left, left, chunk, reply_offset;
    struct rpc_msg                rpc_reply;
    struct rdma_msg               rdma_msg;
    struct xdr_write_chunk        reply_chunk;
    struct xdr_write_list         write_list;
    struct xdr_rdma_segment      *target;
    struct evpl_iovec            *segment_iov, *reply_segment_iov;
    struct evpl_rpc2_iovec_cursor write_cursor;
    int                           segment_niov;
    struct timespec               now;
    uint64_t                      elapsed;
    int                           i, reduce = 0, rdma = request->conn->rdma;
    struct evpl_iovec            *final_reply_iov;
    int                           final_reply_niov, final_reply_length;

    rpc_reply.xid             = request->xid;
    rpc_reply.body.mtype      = REPLY;
    rpc_reply.body.rbody.stat = rstat;

    if (rstat == MSG_ACCEPTED) {
        /* AUTH_SHORT is not implemented - always use AUTH_NONE verifier */
        (void) verf;
        rpc_reply.body.rbody.areply.verf.flavor     = AUTH_NONE;
        rpc_reply.body.rbody.areply.reply_data.stat = error_stat;
    } else {
        /* MSG_DENIED - currently only AUTH_ERROR is supported */
        rpc_reply.body.rbody.rreply.stat = AUTH_ERROR;
        rpc_reply.body.rbody.rreply.auth = error_stat;
    }

    rpc_len = marshall_length_rpc_msg(&rpc_reply);

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

            if (rpc_len + length > 512) {
                reduce = 1;

                rdma_msg.rdma_body.proc                  = RDMA_NOMSG;
                rdma_msg.rdma_body.rdma_nomsg.rdma_reads = NULL;

                left = rpc_len + length;

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
        evpl_iovec_release(evpl, &reply_iov);

    } else {
        offset = 4;

        msg_iov[0].data   += reserve - (rpc_len + offset);
        msg_iov[0].length -= reserve - (rpc_len + offset);
        length            -= reserve - (rpc_len + offset);
    }

    iov = msg_iov[0];

    reply_niov = 1;
    reply_len  = marshall_rpc_msg(&rpc_reply, &iov, &reply_iov, &reply_niov, NULL, offset);

    evpl_iovec_release(evpl, &reply_iov);

    evpl_rpc2_abort_if(reply_len != rpc_len + offset,
                       "marshalled reply length mismatch %d != %d", reply_len, rpc_len + offset);

    if (!rdma) {
        hdr = rpc2_hton32((length - 4) | 0x80000000);
        memcpy(msg_iov[0].data, &hdr, sizeof(hdr));
    }

    evpl_get_hf_monotonic_time(evpl, &now);

    elapsed = evpl_ts_interval(&now, &request->timestamp);

    if (request->metric) {
        prometheus_histogram_sample(request->metric, elapsed);
    }

    if (reduce) {

        final_reply_iov = xdr_dbuf_alloc_space(sizeof(*final_reply_iov), &request->msg->dbuf);

        evpl_rpc2_abort_if(final_reply_iov == NULL, "Failed to allocate reply iovec");

        evpl_iovec_clone_segment(final_reply_iov, &msg_iov[0], 0, offset);
        final_reply_niov   = 1;
        final_reply_length = offset;

        msg_iov[0].data   += offset;
        msg_iov[0].length -= offset;

        reply_offset = 0;

        for (i = 0; i < reply_chunk.num_target; i++) {

            if (reply_chunk.target[i].length == 0) {
                continue;
            }

            reply_segment_iov = &request->reply_segment_iov;

            evpl_iovec_clone_segment(reply_segment_iov, &msg_iov[0], reply_offset, reply_chunk.target[i].length);

            evpl_rdma_write(evpl, request->bind,
                            reply_chunk.target[i].handle,
                            reply_chunk.target[i].offset,
                            reply_segment_iov, 1,
                            EVPL_RDMA_FLAG_TAKE_REF,
                            NULL, NULL);

            reply_offset += reply_chunk.target[i].length;
        }

        /*
         * Release msg_iov - we've taken new references for final_reply_iov
         * and reply_segment_iov. The original msg_iov is no longer needed.
         */
        evpl_iovecs_release(evpl, msg_iov, msg_niov);

    } else {
        final_reply_iov    = msg_iov;
        final_reply_niov   = msg_niov;
        final_reply_length = length;
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
        evpl_iovecs_release(evpl, request->read_chunk.iov, request->read_chunk.niov);
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
    struct timespec                  now;
    auth_flavor                      flavor;
    struct authsys_parms            *authsys = NULL;

    /* Allocate msg first - this gives us a dbuf for unmarshalling */
    msg = evpl_rpc2_msg_alloc(thread);

    rdma = rpc2_conn->rdma;

    evpl_get_hf_monotonic_time(evpl, &now);

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
        /* We expect RPC2 on TCP to start with a 4 byte header */

        offset = 4;
        hdr    = *(uint32_t *) iovec->data;
        hdr    = rpc2_ntoh32(hdr);

        evpl_rpc2_abort_if((hdr & 0x7FFFFFFF) + 4 != length
                           ,
                           "RPC message length mismatch %d != %d",
                           (hdr & 0x7FFFFFFF) + 4, length);
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
    evpl_iovecs_release(evpl, iovec, niov);

    req_iov = xdr_dbuf_alloc_space(sizeof(*req_iov) * hdr_niov, &msg->dbuf);

    evpl_rpc2_abort_if(req_iov == NULL, "Failed to allocate req iovec");

    req_niov = evpl_rpc2_iovec_skip(req_iov, hdr_iov, hdr_niov, rc);

    /* Store req_iov in msg so it can be released when msg is freed */
    msg->req_iov  = req_iov;
    msg->req_niov = req_niov;

    /* Release hdr_iov references - they were addref'd by evpl_rpc2_iovec_skip */
    evpl_iovecs_release(evpl, hdr_iov, hdr_niov);

    request_length = length - (rc + offset);

    switch (rpc_msg.body.mtype) {
        case CALL:
            /* Allocate request and attach msg */
            request      = evpl_rpc2_request_alloc(thread);
            request->msg = msg;

            request->conn      = rpc2_conn;
            request->bind      = bind;
            request->xid       = rpc_msg.xid;
            request->proc      = rpc_msg.body.cbody.proc;
            request->timestamp = now;

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

                default:
                    /* Reject unsupported auth flavors */
                    evpl_rpc2_debug("Rejecting unsupported auth flavor %d", flavor);
                    evpl_rpc2_send_reply_denied(evpl, request, AUTH_TOOWEAK);
                    return;
            } /* switch */

            if (rdma) {
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
                        evpl_iovec_release(evpl, segment_iov);

                        request->pending_reads++;

                        segment_offset += read_list->entry.target.length;

                        read_list = read_list->next;
                    }

                    write_list = rdma_msg.rdma_body.rdma_msg.rdma_writes;

                    while (write_list) {

                        for (i = 0; i < write_list->entry.num_target; i++) {
                            request->write_chunk.max_length += write_list->entry.target[i].length;
                        }

                        request->write_segments.num_segments = write_list->entry.num_target;
                        memcpy(request->write_segments.segments,
                               write_list->entry.target,
                               write_list->entry.num_target * sizeof(struct xdr_rdma_segment));

                        write_list = write_list->next;
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
                evpl_rpc2_error("rpc2 received reply for unknown call %u", rpc_msg.xid);
                evpl_rpc2_msg_free(thread, msg);
                evpl_close(evpl, bind);
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

    thread = evpl_zalloc(sizeof(*thread));

    thread->evpl            = evpl;
    thread->nprograms       = nprograms;
    thread->notify_callback = notify_callback;
    thread->private_data    = private_data;
    thread->client_dbuf     = xdr_dbuf_alloc(128 * 1024);

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

        evpl_rpc2_debug("AUTH_SYS: machinename=%.*s (len=%d) uid=%u gid=%u num_gids=%u",
                        cred->authsys.machinename_len, cred->authsys.machinename,
                        cred->authsys.machinename_len, cred->authsys.uid,
                        cred->authsys.gid, cred->authsys.num_gids);
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

            request->write_chunk.niov = evpl_iovec_alloc(evpl, max_rdma_write_chunk, 4096, 1, 0,
                                                         request->write_chunk.iov);
            request->write_chunk.length = max_rdma_write_chunk;

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
        evpl_iovec_release(evpl, &hdr_out_iov);
    }

    if (rdma) {
        marshall_rdma_msg(&rdma_msg, &hdr_iov, &hdr_out_iov, &out_niov, NULL, 0);
        /* Release the RDMA header iovec - the actual data is in req_iov which gets sent */
        evpl_iovec_release(evpl, &hdr_out_iov);
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
