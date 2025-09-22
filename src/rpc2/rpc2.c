// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE
#include <time.h>
#include <utlist.h>

#include "core/evpl.h"
#include "evpl/evpl_rpc2.h"

#include "rpc2/common.h"
#include "rpc2_xdr.h"
#include "rpcrdma1_xdr.h"
#include "evpl/evpl_rpc2_program.h"
#include "evpl/evpl.h"
#include "core/timing.h"
#include "core/macros.h"

#include "prometheus-c.h"

struct evpl_rpc2_server {
    struct evpl_listener      *listener;
    struct evpl_rpc2_program **programs;
    int                        nprograms;
};

struct evpl_rpc2_thread {
    struct evpl                            *evpl;
    struct evpl_rpc2_server                *server;
    struct evpl_rpc2_msg                   *free_msg;
    struct evpl_listener_binding           *binding;
    struct prometheus_histogram_instance ***metrics;
    void                                   *private_data;
};

static struct evpl_rpc2_msg *
evpl_rpc2_msg_alloc(struct evpl_rpc2_thread *thread)
{
    struct evpl_rpc2_msg *msg;

    if (thread->free_msg) {
        msg = thread->free_msg;
        LL_DELETE(thread->free_msg, msg);
    } else {
        msg         = evpl_zalloc(sizeof(*msg));
        msg->dbuf   = xdr_dbuf_alloc(128 * 1024);
        msg->thread = thread;
    }

    xdr_dbuf_reset(msg->dbuf);

    msg->pending_reads          = 0;
    msg->pending_writes         = 0;
    msg->read_chunk.niov        = 0;
    msg->read_chunk.length      = 0;
    msg->write_chunk.niov       = 0;
    msg->write_chunk.length     = 0;
    msg->write_chunk.max_length = 0;

    return msg;
} /* evpl_rpc2_msg_alloc */

static inline void
evpl_rpc2_msg_free(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_msg    *msg)
{
    int i;

    for (i = 0; i < msg->req_niov; ++i) {
        evpl_iovec_release(&msg->req_iov[i]);
    }

    for (i = 0; i < msg->read_chunk.niov; ++i) {
        evpl_iovec_release(&msg->read_chunk.iov[i]);
    }

    for (i = 0; i < msg->write_chunk.niov; ++i) {
        evpl_iovec_release(&msg->write_chunk.iov[i]);
    }

    LL_PREPEND(thread->free_msg, msg);
} /* evpl_rpc2_msg_free */

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
            outc->data         = inc->data + left;
            outc->length       = inc->length - left;
            outc->private_data = inc->private_data;
            inc++;
            outc++;
            left = 0;
        }
    }

    while (inc < in_iov + niov) {
        outc->data         = inc->data;
        outc->length       = inc->length;
        outc->private_data = inc->private_data;
        inc++;
        outc++;
    }

    return outc - out_iov;
} /* evpl_rpc2_iovec_skip */

static void
evpl_rpc2_dispatch_reply(struct evpl_rpc2_msg *msg)
{
    struct evpl_rpc2_thread *thread = msg->thread;
    struct evpl             *evpl   = thread->evpl;

    evpl_sendv(
        evpl,
        msg->bind,
        msg->reply_iov,
        msg->reply_niov,
        msg->reply_length);


    evpl_rpc2_msg_free(thread, msg);
} /* evpl_rpc2_dispatch_reply */

static void
evpl_rpc2_write_segment_callback(
    int   status,
    void *private_data)
{
    struct evpl_rpc2_msg *msg = private_data;

    evpl_rpc2_abort_if(status, "Failed to write rdma segment");

    msg->pending_writes--;

    if (msg->pending_writes == 0) {
        evpl_rpc2_dispatch_reply(msg);
    }
} /* evpl_rpc2_write_segment_callback */

static int
evpl_rpc2_send_reply(
    struct evpl          *evpl,
    struct evpl_rpc2_msg *msg,
    struct evpl_iovec    *msg_iov,
    int                   msg_niov,
    int                   length,
    int                   rpc2_stat)
{
    struct evpl_iovec        iov, reply_iov;
    int                      reply_len, reply_niov, offset, rpc_len;
    uint32_t                 hdr, segment_offset, write_left, left, chunk, reply_offset;
    struct rpc_msg           rpc_reply;
    struct rdma_msg          rdma_msg, *req_rdma_msg;
    struct xdr_write_list   *write_list;
    struct xdr_rdma_segment *target;
    struct evpl_iovec       *segment_iov, *reply_segment_iov;
    struct timespec          now;
    uint64_t                 elapsed;
    int                      i, reserve, reduce = 0, rdma = msg->rdma;
    struct  xdr_write_chunk *reply_chunk;

    reserve = msg->program ? msg->program->reserve : 0;

    rpc_reply.xid                               = msg->xid;
    rpc_reply.body.mtype                        = REPLY;
    rpc_reply.body.rbody.stat                   = 0;
    rpc_reply.body.rbody.areply.verf.flavor     = AUTH_NONE;
    rpc_reply.body.rbody.areply.verf.body.len   = 0;
    rpc_reply.body.rbody.areply.reply_data.stat = rpc2_stat;

    rpc_len = marshall_length_rpc_msg(&rpc_reply);

    if (rdma) {

        req_rdma_msg = msg->rdma_msg;

        rdma_msg.rdma_xid                       = msg->xid;
        rdma_msg.rdma_vers                      = 1;
        rdma_msg.rdma_credit                    = msg->rdma_credits;
        rdma_msg.rdma_body.proc                 = RDMA_MSG;
        rdma_msg.rdma_body.rdma_msg.rdma_reads  = NULL;
        rdma_msg.rdma_body.rdma_msg.rdma_writes = rpc2_stat ? NULL : req_rdma_msg->rdma_body.rdma_msg.rdma_writes;
        rdma_msg.rdma_body.rdma_msg.rdma_reply  = rpc2_stat ? NULL : req_rdma_msg->rdma_body.rdma_msg.rdma_reply;

        write_list     = rdma_msg.rdma_body.rdma_msg.rdma_writes;
        segment_offset = 0;
        write_left     = msg->write_chunk.length;

        segment_iov = msg->segment_iov;

        while (write_list) {


            for (i = 0; i < write_list->entry.num_target; i++) {
                target = &write_list->entry.target[i];

                if (write_left < target->length) {
                    target->length = write_left;
                    write_left     = 0;
                } else {
                    write_left -= target->length;
                }

                if (target->length) {
                    segment_iov->data         = msg->write_chunk.iov->data + segment_offset;
                    segment_iov->length       = target->length;
                    segment_iov->private_data = msg->write_chunk.iov->private_data;

                    evpl_rpc2_abort_if(msg->write_chunk.niov > 1, "write_chunk.niov > 1 unsupported atm");

                    /* XXX this logic is wrong if write_chunk contains many small IOV */
                    evpl_rdma_write(evpl, msg->bind,
                                    target->handle, target->offset,
                                    segment_iov, 1, evpl_rpc2_write_segment_callback, msg);

                    msg->pending_writes++;

                    segment_offset += target->length;

                    segment_iov++;
                }
            }

            write_list = write_list->next;
        }

        if (req_rdma_msg->rdma_body.rdma_msg.rdma_reply) {
            if (rpc_len + length > 512) {
                reduce = 1;

                rdma_msg.rdma_body.proc                   = RDMA_NOMSG;
                rdma_msg.rdma_body.rdma_nomsg.rdma_reads  = NULL;
                rdma_msg.rdma_body.rdma_nomsg.rdma_writes = req_rdma_msg->rdma_body.rdma_msg.rdma_writes;
                rdma_msg.rdma_body.rdma_nomsg.rdma_reply  = req_rdma_msg->rdma_body.rdma_msg.rdma_reply;

                left = rpc_len + length;

                for (i = 0; i < req_rdma_msg->rdma_body.rdma_nomsg.rdma_reply->num_target; i++) {

                    chunk = req_rdma_msg->rdma_body.rdma_nomsg.rdma_reply->target[i].length;

                    if (left < chunk) {
                        chunk = left;
                    }

                    req_rdma_msg->rdma_body.rdma_nomsg.rdma_reply->target[ i].length = chunk;

                    left -= chunk;
                }

            } else {

                for (i = 0; i < req_rdma_msg->rdma_body.rdma_nomsg.rdma_reply->num_target; i++) {
                    req_rdma_msg->rdma_body.rdma_nomsg.rdma_reply->target[ i].length = 0;
                }
            }
        }

        offset = marshall_length_rdma_msg(&rdma_msg);

        msg_iov[0].data   += reserve - (rpc_len + offset);
        msg_iov[0].length -= reserve - (rpc_len + offset);
        length            -= reserve - (rpc_len + offset);

        reply_niov = 1;
        iov        = msg_iov[0];
        offset     = marshall_rdma_msg(&rdma_msg, &iov, &reply_iov, &reply_niov, NULL, 0);

    } else {
        offset = 4;

        msg_iov[0].data   += reserve - (rpc_len + offset);
        msg_iov[0].length -= reserve - (rpc_len + offset);
        length            -= reserve - (rpc_len + offset);
    }

    iov = msg_iov[0];

    reply_niov = 1;
    reply_len  = marshall_rpc_msg(&rpc_reply, &iov, &reply_iov, &reply_niov, NULL, offset);

    evpl_rpc2_abort_if(reply_len != rpc_len + offset,
                       "marshalled reply length mismatch %d != %d", reply_len, rpc_len + offset);

    if (!rdma) {
        hdr = rpc2_hton32((length - 4) | 0x80000000);
        memcpy(msg_iov[0].data, &hdr, sizeof(hdr));
    }

    clock_gettime(CLOCK_MONOTONIC, &now);

    elapsed = evpl_ts_interval(&now, &msg->timestamp);

    prometheus_histogram_sample(msg->metric, elapsed);

    if (reduce) {

        reply_chunk = req_rdma_msg->rdma_body.rdma_nomsg.rdma_reply;

        xdr_dbuf_alloc_space(msg->reply_iov, sizeof(*msg->reply_iov), msg->dbuf);

        msg->reply_iov->data         = msg_iov[0].data;
        msg->reply_iov->length       = offset;
        msg->reply_iov->private_data = msg_iov[0].private_data;
        msg->reply_niov              = 1;
        msg->reply_length            = offset;

        msg_iov[0].data   += offset;
        msg_iov[0].length -= offset;

        reply_offset = 0;

        for (i = 0; i < reply_chunk->num_target; i++) {

            if (reply_chunk->target[i].length == 0) {
                continue;
            }

            reply_segment_iov = &msg->reply_segment_iov;

            reply_segment_iov->data         = msg_iov[0].data + reply_offset;
            reply_segment_iov->length       = reply_chunk->target[i].length;
            reply_segment_iov->private_data = msg_iov[0].private_data;

            evpl_rdma_write(evpl, msg->bind,
                            reply_chunk->target[i].handle,
                            reply_chunk->target[i].offset,
                            reply_segment_iov, 1, evpl_rpc2_write_segment_callback, msg);

            reply_offset += reply_chunk->target[i].length;

            msg->pending_writes++;
        }

    } else {
        msg->reply_iov    = msg_iov;
        msg->reply_niov   = msg_niov;
        msg->reply_length = length;
    }

    if (msg->pending_writes == 0) {
        evpl_rpc2_dispatch_reply(msg);
    }

    return 0;
} /* evpl_rpc2_send_reply */


static inline int
evpl_rpc2_send_reply_error(
    struct evpl          *evpl,
    struct evpl_rpc2_msg *msg,
    int                   rpc2_stat)
{
    struct evpl_iovec msg_iov;
    int               msg_niov = 1;

    msg_niov = evpl_iovec_alloc(evpl, 4096, 0, 1, &msg_iov);

    return evpl_rpc2_send_reply(evpl, msg, &msg_iov, msg_niov, 0, rpc2_stat);
} /* evpl_rpc2_send_reply_error */


static inline int
evpl_rpc2_send_reply_success(
    struct evpl          *evpl,
    struct evpl_rpc2_msg *msg,
    struct evpl_iovec    *msg_iov,
    int                   msg_niov,
    int                   length)
{
    return evpl_rpc2_send_reply(evpl, msg, msg_iov, msg_niov, length, SUCCESS);
} /* evpl_rpc2_send_reply_success */


static void
evpl_rpc2_handle_msg(struct evpl_rpc2_msg *msg)
{
    struct evpl_rpc2_conn    *conn    = msg->conn;
    struct evpl_rpc2_thread  *thread  = msg->thread;
    struct evpl              *evpl    = thread->evpl;
    struct evpl_rpc2_server  *server  = thread->server;
    struct rpc_msg           *rpc_msg = msg->rpc_msg;
    struct evpl_rpc2_program *program;
    int                       i;
    int                       error;

    msg->xid  = rpc_msg->xid;
    msg->proc = rpc_msg->body.cbody.proc;

    switch (rpc_msg->body.mtype) {
        case CALL:

            msg->program = NULL;

            for (i  = 0; i < server->nprograms; i++) {
                program = server->programs[i];

                if (program->program == rpc_msg->body.cbody.prog &&
                    program->version == rpc_msg->body.cbody.vers) {

                    msg->program = program;
                    msg->metric  = thread->metrics[i][msg->proc];
                    break;
                }
            }

            if (unlikely(!msg->program)) {
                evpl_rpc2_debug(
                    "rpc2 received call for unknown program %u vers %u",
                    rpc_msg->body.cbody.prog,
                    rpc_msg->body.cbody.vers);

                evpl_rpc2_send_reply_error(evpl, msg, PROG_MISMATCH);
                return;
            }

            error = program->call_dispatch(evpl, conn, msg, msg->req_iov, msg->req_niov, msg->request_length,
                                           thread->private_data);

            if (unlikely(error)) {
                abort();
            }

            break;
        case REPLY:
            break;
    } /* switch */
} /* evpl_rpc2_handle_msg */

static void
evpl_rpc2_read_segment_callback(
    int   status,
    void *private_data)
{
    struct evpl_rpc2_msg *msg = private_data;

    evpl_rpc2_abort_if(status, "Failed to read rdma segment");

    msg->pending_reads--;

    if (msg->pending_reads == 0) {
        evpl_rpc2_handle_msg(msg);
    }
} /* evpl_rpc2_read_segment_callback */

static void
evpl_rpc2_event(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct evpl_rpc2_conn   *rpc2_conn = private_data;
    struct evpl_rpc2_thread *thread    = rpc2_conn->thread;
    struct rpc_msg          *rpc_msg;
    struct rdma_msg         *rdma_msg;
    struct evpl_rpc2_msg    *msg;
    struct xdr_read_list    *read_list;
    struct xdr_write_list   *write_list;

    uint32_t                 hdr;
    struct evpl_iovec       *hdr_iov;
    int                      hdr_niov;
    int                      i, rc, rdma, offset, segment_offset;
    struct evpl_iovec       *segment_iov;
    char                     addr_str[80], addr_str_local[80];

    rdma = (rpc2_conn->protocol == EVPL_DATAGRAM_RDMACM_RC);

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            evpl_bind_get_local_address(bind, addr_str_local, sizeof(addr_str_local));
            evpl_bind_get_remote_address(bind, addr_str, sizeof(addr_str));
            evpl_rpc2_debug("Connection established from %s to %s", addr_str, addr_str_local);
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            evpl_bind_get_local_address(bind, addr_str_local, sizeof(addr_str_local));
            evpl_bind_get_remote_address(bind, addr_str, sizeof(addr_str));
            evpl_rpc2_debug("Connection terminated from %s to %s", addr_str, addr_str_local);
            free(rpc2_conn);
            break;
        case EVPL_NOTIFY_RECV_MSG:

            msg = evpl_rpc2_msg_alloc(thread);

            clock_gettime(CLOCK_MONOTONIC, &msg->timestamp);

            xdr_dbuf_alloc_space(msg->rpc_msg, sizeof(*msg->rpc_msg), msg->dbuf);

            rpc_msg = msg->rpc_msg;

            msg->conn = rpc2_conn;
            msg->rdma = rdma;
            msg->bind = bind;

            if (rdma) {
                /* RPC2 on RDMA has no header since its message based,
                 * instead we should have an rdma_msg xdr structure
                 * which describes the rdma particulars of the message */

                xdr_dbuf_alloc_space(msg->rdma_msg, sizeof(*msg->rdma_msg), msg->dbuf);
                rdma_msg = msg->rdma_msg;

                offset = unmarshall_rdma_msg(rdma_msg,
                                             notify->recv_msg.iovec,
                                             notify->recv_msg.niov,
                                             NULL,
                                             msg->dbuf);

                //dump_rdma_msg("rdma_msg", &rdma_msg);

                msg->rdma_credits = rdma_msg->rdma_credit;

                if (rdma_msg->rdma_body.proc == RDMA_MSG) {

                    read_list = rdma_msg->rdma_body.rdma_msg.rdma_reads;

                    if (read_list) {
                        msg->read_chunk.xdr_position = read_list->entry.position;
                    }

                    while (read_list) {
                        evpl_rpc2_abort_if(msg->read_chunk.xdr_position != read_list->entry.position,
                                           "read segment position mismatch");

                        msg->read_chunk.length += read_list->entry.target.length;

                        read_list = read_list->next;
                    }

                    xdr_dbuf_alloc_space(msg->read_chunk.iov, sizeof(*msg->read_chunk.iov), msg->dbuf);

                    msg->read_chunk.niov = evpl_iovec_alloc(evpl, msg->read_chunk.length, 4096, 1, msg->read_chunk.iov);

                    read_list = rdma_msg->rdma_body.rdma_msg.rdma_reads;

                    segment_offset = 0;

                    segment_iov = msg->segment_iov;

                    while (read_list) {

                        segment_iov->data         = msg->read_chunk.iov->data + segment_offset;
                        segment_iov->length       = read_list->entry.target.length;
                        segment_iov->private_data = msg->read_chunk.iov->private_data;

                        evpl_rdma_read(evpl, msg->bind,
                                       read_list->entry.target.handle, read_list->entry.target.offset,
                                       segment_iov, 1, evpl_rpc2_read_segment_callback, msg);

                        msg->pending_reads++;

                        segment_offset += read_list->entry.target.length;

                        segment_iov++;

                        read_list = read_list->next;
                    }

                    write_list = rdma_msg->rdma_body.rdma_msg.rdma_writes;

                    while (write_list) {

                        for (i = 0; i < write_list->entry.num_target; i++) {
                            msg->write_chunk.max_length += write_list->entry.target[i].length;
                        }

                        write_list = write_list->next;
                    }
                } else {
                    evpl_rpc2_error("rpc2 received rdma msg with unhandled proc %d", rdma_msg->rdma_body.proc);
                }

            } else {
                /* We expect RPC2 on TCP to start with a 4 byte header */

                offset = 4;
                hdr    = *(uint32_t *) notify->recv_msg.iovec->data;
                hdr    = rpc2_ntoh32(hdr);

                evpl_rpc2_abort_if((hdr & 0x7FFFFFFF) + 4 != notify->recv_msg.length
                                   ,
                                   "RPC message length mismatch %d != %d",
                                   (hdr & 0x7FFFFFFF) + 4, notify->recv_msg.length);
            }

            xdr_dbuf_alloc_space(hdr_iov, sizeof(*hdr_iov) * notify->recv_msg.niov, msg->dbuf);
            hdr_niov = evpl_rpc2_iovec_skip(hdr_iov, notify->recv_msg.iovec, notify->recv_msg.niov, offset);

            rc = unmarshall_rpc_msg(rpc_msg, hdr_iov, hdr_niov, NULL, msg->dbuf);

            //dump_rpc_msg("rpc_msg", &rpc_msg);

            if (rdma) {
                /* Adjust xdr positions for the rpc header */
                msg->read_chunk.xdr_position -= rc;
            }

            xdr_dbuf_alloc_space(msg->req_iov, sizeof(*msg->req_iov) * hdr_niov, msg->dbuf);
            msg->req_niov = evpl_rpc2_iovec_skip(msg->req_iov, hdr_iov, hdr_niov, rc);

            for (i = 0; i < msg->req_niov; ++i) {
                evpl_iovec_addref(&msg->req_iov[i]);
            }

            msg->request_length = notify->recv_msg.length - (rc + offset);

            if (msg->pending_reads == 0) {
                evpl_rpc2_handle_msg(msg);
            }

            break;
        default:
            evpl_rpc2_error("rpc2 unhandled event");
            abort();
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
    struct evpl_rpc2_thread *thread = private_data;
    struct evpl_rpc2_conn   *rpc2_conn;

    rpc2_conn           = evpl_zalloc(sizeof(*rpc2_conn));
    rpc2_conn->thread   = thread;
    rpc2_conn->server   = thread->server;
    rpc2_conn->protocol = evpl_bind_get_protocol(bind);

    *notify_callback   = evpl_rpc2_event;
    *segment_callback  = rpc2_segment_callback;
    *conn_private_data = rpc2_conn;

} /* evpl_rpc2_accept */

SYMBOL_EXPORT struct evpl_rpc2_server *
evpl_rpc2_init(
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
        server->programs[i]->reply_dispatch = evpl_rpc2_send_reply_success;
    }

    return server;
} /* evpl_rpc2_listen */

SYMBOL_EXPORT void
evpl_rpc2_start(
    struct evpl_rpc2_server *server,
    int                      protocol,
    struct evpl_endpoint    *endpoint)
{
    evpl_listen(
        server->listener,
        protocol,
        endpoint);
} /* evpl_rpc2_start */

SYMBOL_EXPORT struct evpl_rpc2_thread *
evpl_rpc2_attach(
    struct evpl             *evpl,
    struct evpl_rpc2_server *server,
    void                    *private_data)
{
    struct evpl_rpc2_thread  *thread;
    struct evpl_rpc2_program *program;
    int                       i, j;

    thread = evpl_zalloc(sizeof(*thread));

    thread->evpl         = evpl;
    thread->server       = server;
    thread->private_data = private_data;
    thread->metrics      = evpl_zalloc(server->nprograms * sizeof(*thread->metrics));

    for (i = 0; i < server->nprograms; i++) {

        program = server->programs[i];

        thread->metrics[i] = evpl_zalloc(
            (program->maxproc + 1) * sizeof(struct prometheus_histogram_instance *)
            );

        for (j = 0; j <= program->maxproc; j++) {
            if (program->metrics[j]) {
                thread->metrics[i][j] = prometheus_histogram_series_create_instance(program->metrics[j]);
            }
        }
    }

    thread->binding = evpl_listener_attach(
        thread->evpl,
        server->listener,
        evpl_rpc2_accept,
        thread);

    return thread;

} /* evpl_rpc2_attach */

SYMBOL_EXPORT void
evpl_rpc2_detach(struct evpl_rpc2_thread *thread)
{
    int                       i, j;
    struct evpl_rpc2_server  *server = thread->server;
    struct evpl_rpc2_program *program;
    struct evpl_rpc2_msg     *msg;

    evpl_listener_detach(thread->evpl, thread->binding);

    for (i = 0; i < server->nprograms; i++) {
        program = server->programs[i];
        for (j = 0; j <= program->maxproc; j++) {
            if (thread->metrics[i][j]) {
                prometheus_histogram_series_destroy_instance(program->metrics[j], thread->metrics[i][j]);
            }
        }
    }

    for (i = 0; i < server->nprograms; i++) {
        evpl_free(thread->metrics[i]);
    }

    while (thread->free_msg) {
        msg = thread->free_msg;
        LL_DELETE(thread->free_msg, msg);
        xdr_dbuf_free(msg->dbuf);
        evpl_free(msg);
    }

    evpl_free(thread->metrics);
    evpl_free(thread);

} /* evpl_rpc2_detach */

SYMBOL_EXPORT void
evpl_rpc2_stop(struct evpl_rpc2_server *server)
{
    evpl_listener_destroy(server->listener);
    server->listener = NULL;
} /* evpl_rpc2_stop */

SYMBOL_EXPORT void
evpl_rpc2_destroy(struct evpl_rpc2_server *server)
{
    if (server->listener) {
        evpl_listener_destroy(server->listener);
    }

    evpl_free(server->programs);
    evpl_free(server);
} /* evpl_rpc2_server_destroy */
