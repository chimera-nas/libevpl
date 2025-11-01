// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#define _GNU_SOURCE
#include <time.h>
#include <utlist.h>
#include <uthash.h>

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
    xdr_dbuf                        *dbuf;
    struct evpl_rpc2_msg            *free_msg;
    struct evpl_rpc2_server_binding *servers;
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
    struct rdma_msg          rdma_msg;
    struct xdr_write_chunk   reply_chunk;
    struct xdr_write_list    write_list;
    struct xdr_rdma_segment *target;
    struct evpl_iovec       *segment_iov, *reply_segment_iov;
    struct timespec          now;
    uint64_t                 elapsed;
    int                      i, reserve, reduce = 0, rdma = msg->rdma;

    reserve = msg->program ? msg->program->reserve : 0;

    rpc_reply.xid                               = msg->xid;
    rpc_reply.body.mtype                        = REPLY;
    rpc_reply.body.rbody.stat                   = 0;
    rpc_reply.body.rbody.areply.verf.flavor     = AUTH_NONE;
    rpc_reply.body.rbody.areply.verf.body.len   = 0;
    rpc_reply.body.rbody.areply.reply_data.stat = rpc2_stat;

    rpc_len = marshall_length_rpc_msg(&rpc_reply);

    if (rdma) {

        rdma_msg.rdma_xid                      = msg->xid;
        rdma_msg.rdma_vers                     = 1;
        rdma_msg.rdma_credit                   = msg->rdma_credits;
        rdma_msg.rdma_body.proc                = RDMA_MSG;
        rdma_msg.rdma_body.rdma_msg.rdma_reads = NULL;

        if (msg->write_segments.num_segments > 0) {
            write_list.entry.num_target = msg->write_segments.num_segments;
            write_list.entry.target     = (struct xdr_rdma_segment *) msg->write_segments.segments;
            write_list.next             = NULL;

            rdma_msg.rdma_body.rdma_msg.rdma_writes = &write_list;
        }

        if (msg->reply_segments.num_segments > 0) {
            reply_chunk.num_target                 = msg->reply_segments.num_segments;
            reply_chunk.target                     = (struct xdr_rdma_segment *) msg->reply_segments.segments;
            rdma_msg.rdma_body.rdma_msg.rdma_reply = &reply_chunk;
        }

        segment_offset = 0;
        write_left     = msg->write_chunk.length;

        segment_iov = msg->segment_iov;

        if (msg->write_segments.num_segments > 0) {

            for (i = 0; i < write_list.entry.num_target; i++) {
                target = &write_list.entry.target[i];

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
        }

        if (msg->reply_segments.num_segments > 0) {

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

    if (msg->metric) {
        prometheus_histogram_sample(msg->metric, elapsed);
    }

    if (reduce) {

        xdr_dbuf_alloc_space(msg->reply_iov, sizeof(*msg->reply_iov), msg->dbuf);

        msg->reply_iov->data         = msg_iov[0].data;
        msg->reply_iov->length       = offset;
        msg->reply_iov->private_data = msg_iov[0].private_data;
        msg->reply_niov              = 1;
        msg->reply_length            = offset;

        msg_iov[0].data   += offset;
        msg_iov[0].length -= offset;

        reply_offset = 0;

        for (i = 0; i < reply_chunk.num_target; i++) {

            if (reply_chunk.target[i].length == 0) {
                continue;
            }

            reply_segment_iov = &msg->reply_segment_iov;

            reply_segment_iov->data         = msg_iov[0].data + reply_offset;
            reply_segment_iov->length       = reply_chunk.target[i].length;
            reply_segment_iov->private_data = msg_iov[0].private_data;

            evpl_rdma_write(evpl, msg->bind,
                            reply_chunk.target[i].handle,
                            reply_chunk.target[i].offset,
                            reply_segment_iov, 1, evpl_rpc2_write_segment_callback, msg);

            reply_offset += reply_chunk.target[i].length;

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
evpl_rpc2_server_handle_msg(struct evpl_rpc2_msg *msg)
{
    struct evpl_rpc2_conn           *conn           = msg->conn;
    struct evpl_rpc2_thread         *thread         = msg->thread;
    struct evpl                     *evpl           = thread->evpl;
    struct evpl_rpc2_server_binding *server_binding = conn->server_binding;
    int                              error;

    error = msg->program->recv_call_dispatch(evpl, conn, msg, msg->req_iov, msg->req_niov, msg->request_length,
                                             server_binding->private_data);

    if (unlikely(error)) {
        abort();
    }

} /* evpl_rpc2_server_handle_msg */



static void
evpl_rpc2_read_segment_callback(
    int   status,
    void *private_data)
{
    struct evpl_rpc2_msg *msg = private_data;

    evpl_rpc2_abort_if(status, "Failed to read rdma segment");

    msg->pending_reads--;

    if (msg->pending_reads == 0) {
        evpl_rpc2_server_handle_msg(msg);
    }
} /* evpl_rpc2_read_segment_callback */

static void
evpl_rpc2_client_handle_msg(struct evpl_rpc2_msg *msg)
{
    struct evpl_rpc2_thread *thread = msg->thread;
    struct evpl_rpc2_conn   *conn   = msg->conn;
    int                      error, i;
    struct evpl             *evpl = thread->evpl;

    error = msg->program->recv_reply_dispatch(evpl, conn, msg, msg->reply_iov, msg->reply_niov, msg->reply_length,
                                              msg->callback,
                                              msg->callback_arg);

    if (unlikely(error)) {
        abort();
    }

    for (i = 0; i < msg->reply_niov; i++) {
        evpl_iovec_release(&msg->reply_iov[i]);
    }

    evpl_rpc2_msg_free(thread, msg);
} /* evpl_rpc2_client_handle_msg */

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
    struct evpl_rpc2_server_binding *server_binding = rpc2_conn->server_binding;
    struct evpl_rpc2_server         *server         = server_binding ? server_binding->server : NULL;
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

    xdr_dbuf_reset(thread->dbuf);

    rdma = (rpc2_conn->protocol == EVPL_DATAGRAM_RDMACM_RC);

    clock_gettime(CLOCK_MONOTONIC, &now);

    if (rdma) {
        /* RPC2 on RDMA has no header since its message based,
         * instead we should have an rdma_msg xdr structure
         * which describes the rdma particulars of the message */

        offset = unmarshall_rdma_msg(&rdma_msg,
                                     iovec,
                                     niov,
                                     NULL,
                                     thread->dbuf);

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

    xdr_dbuf_alloc_space(hdr_iov, sizeof(*hdr_iov) * niov, thread->dbuf);
    hdr_niov = evpl_rpc2_iovec_skip(hdr_iov, iovec, niov, offset);

    rc = unmarshall_rpc_msg(&rpc_msg, hdr_iov, hdr_niov, NULL, thread->dbuf);

    switch (rpc_msg.body.mtype) {
        case CALL:
            msg = evpl_rpc2_msg_alloc(thread);
            break;
        case REPLY:
            HASH_FIND(hh, rpc2_conn->pending_calls, &rpc_msg.xid, sizeof(rpc_msg.xid), msg);

            if (unlikely(!msg)) {
                evpl_rpc2_error("rpc2 received reply for unknown call %u", rpc_msg.xid);
                evpl_close(evpl, bind);
                return;
            }

            HASH_DELETE(hh, rpc2_conn->pending_calls, msg);
            break;
    } /* switch */

    xdr_dbuf_alloc_space(req_iov, sizeof(*req_iov) * hdr_niov, msg->dbuf);
    req_niov = evpl_rpc2_iovec_skip(req_iov, hdr_iov, hdr_niov, rc);

    for (i = 0; i < req_niov; ++i) {
        evpl_iovec_addref(&req_iov[i]);
    }

    request_length = length - (rc + offset);

    switch (rpc_msg.body.mtype) {
        case CALL:
            msg->conn           = rpc2_conn;
            msg->bind           = bind;
            msg->rdma           = rdma;
            msg->xid            = rpc_msg.xid;
            msg->proc           = rpc_msg.body.cbody.proc;
            msg->timestamp      = now;
            msg->pending_reads  = 0;
            msg->pending_writes = 0;
            msg->request_length = request_length;
            msg->req_iov        = req_iov;
            msg->req_niov       = req_niov;

            if (msg->rdma) {
                if (rdma_msg.rdma_body.proc == RDMA_MSG) {

                    read_list = rdma_msg.rdma_body.rdma_msg.rdma_reads;

                    if (read_list) {
                        msg->read_chunk.xdr_position = read_list->entry.position - rc;
                    }

                    while (read_list) {
                        evpl_rpc2_abort_if(msg->read_chunk.xdr_position != read_list->entry.position,
                                           "read segment position mismatch");

                        msg->read_chunk.length += read_list->entry.target.length;

                        read_list = read_list->next;
                    }

                    xdr_dbuf_alloc_space(msg->read_chunk.iov, sizeof(*msg->read_chunk.iov), msg->dbuf);

                    msg->read_chunk.niov = evpl_iovec_alloc(evpl, msg->read_chunk.length, 4096, 1, msg->read_chunk.iov);

                    read_list = rdma_msg.rdma_body.rdma_msg.rdma_reads;

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

                    write_list = rdma_msg.rdma_body.rdma_msg.rdma_writes;

                    while (write_list) {

                        for (i = 0; i < write_list->entry.num_target; i++) {
                            msg->write_chunk.max_length += write_list->entry.target[i].length;
                        }

                        write_list = write_list->next;
                    }
                } else {
                    evpl_rpc2_error("rpc2 received rdma msg with unhandled proc %d", rdma_msg.rdma_body.proc);
                }
            }

            msg->program = NULL;

            for (i  = 0; i < server->nprograms; i++) {
                program = server->programs[i];

                if (program->program == rpc_msg.body.cbody.prog &&
                    program->version == rpc_msg.body.cbody.vers) {

                    msg->program = program;
                    msg->metric  = server_binding->metrics[i][msg->proc];
                    break;
                }
            }

            if (unlikely(!msg->program)) {
                evpl_rpc2_debug(
                    "rpc2 received call for unknown program %u vers %u",
                    rpc_msg.body.cbody.prog,
                    rpc_msg.body.cbody.vers);

                evpl_rpc2_send_reply_error(evpl, msg, PROG_MISMATCH);
                return;
            }

            if (msg->pending_reads == 0) {
                evpl_rpc2_server_handle_msg(msg);
            }
            break;
        case REPLY:
            msg->reply_iov    = req_iov;
            msg->reply_niov   = req_niov;
            msg->reply_length = request_length;
            evpl_rpc2_client_handle_msg(msg);
            break;
        default:
            evpl_rpc2_error("rpc2 received unexpected message type %d", rpc_msg.body.mtype);
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
    struct evpl_rpc2_conn *rpc2_conn = private_data;
    char                   addr_str[80], addr_str_local[80];

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

    rpc2_conn                 = evpl_zalloc(sizeof(*rpc2_conn));
    rpc2_conn->thread_dbuf    = (struct xdr_dbuf *) server_binding->thread->dbuf;
    rpc2_conn->server_binding = server_binding;
    rpc2_conn->thread         = server_binding->thread;
    rpc2_conn->bind           = bind;
    rpc2_conn->protocol       = evpl_bind_get_protocol(bind);

    *notify_callback   = evpl_rpc2_event;
    *segment_callback  = rpc2_segment_callback;
    *conn_private_data = rpc2_conn;

} /* evpl_rpc2_accept */

SYMBOL_EXPORT struct evpl_rpc2_thread *
evpl_rpc2_thread_init(
    struct evpl               *evpl,
    struct evpl_rpc2_program **programs,
    int                        nprograms)
{
    struct evpl_rpc2_thread *thread;

    thread = evpl_zalloc(sizeof(*thread));

    thread->evpl      = evpl;
    thread->nprograms = nprograms;

    thread->dbuf = xdr_dbuf_alloc(128 * 1024);

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
    struct evpl_rpc2_msg *msg;

    xdr_dbuf_free(thread->dbuf);

    while (thread->free_msg) {
        msg = thread->free_msg;
        LL_DELETE(thread->free_msg, msg);
        xdr_dbuf_free(msg->dbuf);
        evpl_free(msg);
    }

    if (thread->programs) {
        evpl_free(thread->programs);
    }

    evpl_free(thread);
} /* evpl_rpc2_thread_destroy */



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
    struct evpl_rpc2_thread *thread,
    int                      protocol,
    struct evpl_endpoint    *endpoint)
{
    struct evpl_rpc2_conn *conn;

    conn = evpl_zalloc(sizeof(*conn));

    conn->thread         = thread;
    conn->thread_dbuf    = (struct xdr_dbuf *) thread->dbuf;
    conn->protocol       = protocol;
    conn->server_binding = NULL;
    conn->next_xid       = 1;

    conn->bind = evpl_connect(
        thread->evpl,
        protocol,
        NULL,  /* local_endpoint - let system choose */
        endpoint,  /* remote_endpoint */
        evpl_rpc2_event,
        rpc2_segment_callback,
        conn);

    if (!conn->bind) {
        evpl_free(conn);
        return NULL;
    }

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
    struct evpl              *evpl,
    struct evpl_rpc2_program *program,
    struct evpl_rpc2_conn    *conn,
    uint32_t                  procedure,
    struct evpl_iovec        *req_iov,
    int                       req_niov,
    int                       req_length,
    void                     *callback,
    void                     *private_data)
{
    struct evpl_rpc2_thread *thread = conn->thread;
    struct evpl_rpc2_msg    *msg;
    struct rpc_msg           rpc_msg;
    struct evpl_iovec        hdr_iov, hdr_out_iov;
    int                      rpc_len;
    int                      out_niov   = 1;
    int                      reserve    = 256;  /* Must match the reserve value in generated code */
    int                      offset     = 4;    /* TCP record header offset */
    int                      pay_length = req_length - reserve;
    int                      total_length;

    msg = evpl_rpc2_msg_alloc(thread);

    xdr_dbuf_alloc_space(msg->req_iov, sizeof(*msg->req_iov) * req_niov, msg->dbuf);
    memcpy(msg->req_iov, req_iov, req_niov * sizeof(*msg->req_iov));

    msg->conn         = conn;
    msg->program      = program;
    msg->req_niov     = req_niov;
    msg->xid          = conn->next_xid++;
    msg->proc         = procedure;
    msg->callback     = callback;
    msg->callback_arg = private_data;

    HASH_ADD(hh, conn->pending_calls, xid, sizeof(msg->xid), msg);

    rpc_msg.xid                      = msg->xid;
    rpc_msg.body.mtype               = CALL;
    rpc_msg.body.cbody.rpcvers       = 2;
    rpc_msg.body.cbody.prog          = program->program;
    rpc_msg.body.cbody.vers          = program->version;
    rpc_msg.body.cbody.proc          = procedure;
    rpc_msg.body.cbody.cred.flavor   = AUTH_NONE;
    rpc_msg.body.cbody.cred.body.len = 0;
    rpc_msg.body.cbody.verf.flavor   = AUTH_NONE;
    rpc_msg.body.cbody.verf.body.len = 0;

    /* Calculate exact RPC header length first */
    rpc_len = marshall_length_rpc_msg(&rpc_msg);

    total_length = offset + rpc_len + pay_length;

    /* Adjust iovec to point to where payload data starts, following server pattern */
    req_iov[0].data   = (char *) req_iov[0].data + (reserve - (rpc_len + offset));
    req_iov[0].length = req_iov[0].length - (reserve - (rpc_len + offset));

    hdr_iov = req_iov[0];

    rpc_len = marshall_rpc_msg(&rpc_msg, &hdr_iov, &hdr_out_iov, &out_niov, NULL, offset);

    /* Add 4-byte record marking header for TCP at the start of the output buffer */
    *(uint32_t *) req_iov[0].data = rpc2_hton32((req_iov[0].length - 4) | 0x80000000);

    /* Send the request - use out_iov which contains the marshalled header + payload */
    evpl_sendv(evpl, conn->bind, req_iov, req_niov, total_length);

    return 0;
} /* evpl_rpc2_call */