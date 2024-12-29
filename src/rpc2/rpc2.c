#define _GNU_SOURCE
#include <time.h>

#include "rpc2/rpc2.h"
#include "core/internal.h"

#include "utlist.h"

#include "rpc2/common.h"
#include "rpc2_xdr.h"
#include "rpcrdma1_xdr.h"
#include "rpc2/rpc2_program.h"
#include "core/evpl.h"

struct evpl_rpc2_server {
    int                        protocol;
    struct evpl_rpc2_agent    *agent;
    struct evpl_bind          *bind;
    struct evpl_rpc2_program **programs;
    struct evpl_rpc2_metric  **metrics;
    int                        nprograms;
    void                      *private_data;
};

struct evpl_rpc2_agent {
    struct evpl          *evpl;
    struct evpl_rpc2_msg *free_msg;
};

static struct evpl_rpc2_msg *
evpl_rpc2_msg_alloc(struct evpl_rpc2_agent *agent)
{
    struct evpl_rpc2_msg *msg;

    if (agent->free_msg) {
        msg = agent->free_msg;
        LL_DELETE(agent->free_msg, msg);
    } else {
        msg        = evpl_zalloc(sizeof(*msg));
        msg->dbuf  = xdr_dbuf_alloc();
        msg->agent = agent;
    }

    xdr_dbuf_reset(msg->dbuf);

    msg->pending_reads      = 0;
    msg->pending_writes     = 0;
    msg->read_chunk.niov    = 0;
    msg->read_chunk.length  = 0;
    msg->write_chunk.niov   = 0;
    msg->write_chunk.length = 0;

    return msg;
} /* evpl_rpc2_msg_alloc */

static inline void
evpl_rpc2_msg_free(
    struct evpl_rpc2_agent *agent,
    struct evpl_rpc2_msg   *msg)
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

    LL_PREPEND(agent->free_msg, msg);
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

struct evpl_rpc2_agent *
evpl_rpc2_init(struct evpl *evpl)
{
    struct evpl_rpc2_agent *agent;

    agent = evpl_zalloc(sizeof(*agent));

    agent->evpl = evpl;

    return agent;
} /* evpl_rpc2_agent_init */

void
evpl_rpc2_destroy(struct evpl_rpc2_agent *agent)
{
    struct evpl_rpc2_msg *msg;

    while (agent->free_msg) {
        msg = agent->free_msg;
        LL_DELETE(agent->free_msg, msg);
        xdr_dbuf_free(msg->dbuf);
        evpl_free(msg);
    }
    evpl_free(agent);
} /* evpl_rpc2_agent_destroy */

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
            outc->data   = inc->data + left;
            outc->length = inc->length - left;
            outc->buffer = inc->buffer;
            inc++;
            outc++;
            left = 0;
        }
    }

    while (inc < in_iov + niov) {
        outc->data   = inc->data;
        outc->length = inc->length;
        outc->buffer = inc->buffer;
        inc++;
        outc++;
    }

    return outc - out_iov;
} /* evpl_rpc2_iovec_skip */

static int
evpl_rpc2_send_reply_error(
    struct evpl          *evpl,
    struct evpl_rpc2_msg *msg)
{
    struct evpl_iovec iov, reply_iov;
    int               reply_len, reply_niov, niov;
    uint32_t          hdr;
    struct rpc_msg    rpc_reply;

    niov = evpl_iovec_reserve(evpl, 4096, 0, 1, &iov);

    evpl_rpc2_abort_if(niov != 1, "Failed to allocate iov for rpc header");

    rpc_reply.xid                               = msg->xid;
    rpc_reply.body.mtype                        = REPLY;
    rpc_reply.body.rbody.stat                   = 0;
    rpc_reply.body.rbody.areply.verf.flavor     = AUTH_NONE;
    rpc_reply.body.rbody.areply.verf.body.len   = 0;
    rpc_reply.body.rbody.areply.reply_data.stat = PROG_MISMATCH;

    reply_niov = 1;
    reply_len  = marshall_rpc_msg(&rpc_reply, &iov, &reply_iov, &reply_niov, NULL, 4);

    hdr = rpc2_hton32((reply_len - 4) | 0x80000000);

    memcpy(reply_iov.data, &hdr, sizeof(hdr));

    evpl_iovec_commit(evpl, 0, &iov, 1);

    evpl_sendv(evpl, msg->bind, &reply_iov, 1, reply_len);

    evpl_rpc2_msg_free(msg->agent, msg);

    return 0;
} /* evpl_rpc2_send_reply_error */

static void
evpl_rpc2_handle_msg(struct evpl_rpc2_msg *msg)
{
    struct evpl_rpc2_conn    *conn    = msg->conn;
    struct evpl_rpc2_agent   *agent   = msg->agent;
    struct evpl              *evpl    = agent->evpl;
    struct evpl_rpc2_server  *server  = conn->server;
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
                    msg->metric  = &server->metrics[i][msg->proc];
                    break;
                }
            }

            if (unlikely(!msg->program)) {
                evpl_rpc2_debug(
                    "rpc2 received call for unknown program %u vers %u",
                    rpc_msg->body.cbody.prog,
                    rpc_msg->body.cbody.vers);

                evpl_rpc2_send_reply_error(evpl, msg);
                return;
            }

            error = program->call_dispatch(evpl, conn, msg, msg->req_iov, msg->req_niov, msg->request_length,
                                           server->private_data);

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
    struct evpl_rpc2_server *server    = rpc2_conn->server;
    struct evpl_rpc2_agent  *agent     = server->agent;
    struct rpc_msg          *rpc_msg;
    struct rdma_msg         *rdma_msg;
    struct evpl_rpc2_msg    *msg;
    struct xdr_read_list    *read_list;
    struct xdr_write_list   *write_list;

    uint32_t                 hdr;
    struct evpl_iovec       *hdr_iov;
    int                      hdr_niov;
    int                      i, rc, rdma, offset, segment_offset;
    struct evpl_iovec        segment_iov;

    rdma = (server->protocol == EVPL_DATAGRAM_RDMACM_RC);

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            free(rpc2_conn);
            break;
        case EVPL_NOTIFY_RECV_MSG:

            msg = evpl_rpc2_msg_alloc(agent);

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

                    while (read_list) {

                        segment_iov.data   = msg->read_chunk.iov->data + segment_offset;
                        segment_iov.length = read_list->entry.target.length;
                        segment_iov.buffer = msg->read_chunk.iov->buffer;

                        evpl_rdma_read(evpl, msg->bind,
                                       read_list->entry.target.handle, read_list->entry.target.offset,
                                       &segment_iov, 1, evpl_rpc2_read_segment_callback, msg);

                        msg->pending_reads++;

                        segment_offset += read_list->entry.target.length;

                        read_list = read_list->next;
                    }

                    write_list = rdma_msg->rdma_body.rdma_msg.rdma_writes;

                    while (write_list) {

                        for (i = 0; i < write_list->entry.num_target; i++) {
                            msg->write_chunk.length += write_list->entry.target[i].length;
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
    struct evpl_bind        *listen_bind,
    struct evpl_bind        *accepted_bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    struct evpl_rpc2_server *server = private_data;
    struct evpl_rpc2_conn   *rpc2_conn;

    rpc2_conn            = evpl_zalloc(sizeof(*rpc2_conn));
    rpc2_conn->server    = server;
    rpc2_conn->is_server = 1;
    rpc2_conn->agent     = server->agent;

    *notify_callback   = evpl_rpc2_event;
    *segment_callback  = rpc2_segment_callback;
    *conn_private_data = rpc2_conn;

} /* evpl_rpc2_accept */

static void
evpl_rpc2_dispatch_reply(struct evpl_rpc2_msg *msg)
{
    struct evpl_rpc2_agent *agent = msg->agent;
    struct evpl            *evpl  = agent->evpl;

    evpl_sendv(
        evpl,
        msg->bind,
        msg->reply_iov,
        msg->reply_niov,
        msg->reply_length);


    evpl_rpc2_msg_free(agent, msg);
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
    int                   length)
{
    struct evpl_rpc2_metric *metric = msg->metric;
    struct evpl_iovec        iov, reply_iov;
    int                      reply_len, reply_niov, offset, rpc_len;
    uint32_t                 hdr, segment_offset, write_left;
    struct rpc_msg           rpc_reply;
    struct rdma_msg          rdma_msg, *req_rdma_msg;
    struct xdr_write_list   *write_list;
    struct xdr_rdma_segment *target;
    struct evpl_iovec        segment_iov;
    struct timespec          now;
    uint64_t                 elapsed;
    int                      i, reduce = 0, rdma = msg->rdma;

    rpc_reply.xid                               = msg->xid;
    rpc_reply.body.mtype                        = REPLY;
    rpc_reply.body.rbody.stat                   = 0;
    rpc_reply.body.rbody.areply.verf.flavor     = AUTH_NONE;
    rpc_reply.body.rbody.areply.verf.body.len   = 0;
    rpc_reply.body.rbody.areply.reply_data.stat = SUCCESS;

    rpc_len = marshall_length_rpc_msg(&rpc_reply);

    if (rdma) {

        req_rdma_msg = msg->rdma_msg;

        rdma_msg.rdma_xid                       = msg->xid;
        rdma_msg.rdma_vers                      = 1;
        rdma_msg.rdma_credit                    = msg->rdma_credits;
        rdma_msg.rdma_body.proc                 = RDMA_MSG;
        rdma_msg.rdma_body.rdma_msg.rdma_reads  = NULL;
        rdma_msg.rdma_body.rdma_msg.rdma_writes = req_rdma_msg->rdma_body.rdma_msg.rdma_writes;
        rdma_msg.rdma_body.rdma_msg.rdma_reply  = req_rdma_msg->rdma_body.rdma_msg.rdma_reply;

        write_list     = rdma_msg.rdma_body.rdma_msg.rdma_writes;
        segment_offset = 0;
        write_left     = msg->write_chunk.length;

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
                    segment_iov.data   = msg->write_chunk.iov->data + segment_offset;
                    segment_iov.length = target->length;
                    segment_iov.buffer = msg->write_chunk.iov->buffer;

                    /* XXX this logic is wrong if write_chunk contains many small IOV */
                    evpl_rdma_write(evpl, msg->bind,
                                    target->handle, target->offset,
                                    &segment_iov, 1, evpl_rpc2_write_segment_callback, msg);

                    msg->pending_writes++;

                    segment_offset += target->length;
                }
            }

            write_list = write_list->next;
        }

        if (req_rdma_msg->rdma_body.rdma_msg.rdma_reply) {

            evpl_rpc2_abort_if(req_rdma_msg->rdma_body.rdma_msg.rdma_reply->num_target != 1,
                               "got reply segment with multiple targets");

            reduce = 1;

            rdma_msg.rdma_body.proc                   = RDMA_NOMSG;
            rdma_msg.rdma_body.rdma_nomsg.rdma_reads  = NULL;
            rdma_msg.rdma_body.rdma_nomsg.rdma_writes = req_rdma_msg->rdma_body.rdma_msg.rdma_writes;
            rdma_msg.rdma_body.rdma_nomsg.rdma_reply  = req_rdma_msg->rdma_body.rdma_msg.rdma_reply;

            rdma_msg.rdma_body.rdma_nomsg.rdma_reply->target->length = rpc_len + length;

        }

        offset = marshall_length_rdma_msg(&rdma_msg);

        msg_iov[0].data   += msg->program->reserve - (rpc_len + offset);
        msg_iov[0].length -= msg->program->reserve - (rpc_len + offset);
        length            -= msg->program->reserve - (rpc_len + offset);

        reply_niov = 1;
        iov        = msg_iov[0];
        offset     = marshall_rdma_msg(&rdma_msg, &iov, &reply_iov, &reply_niov, NULL, 0);

    } else {
        offset = 4;

        msg_iov[0].data   += msg->program->reserve - (rpc_len + offset);
        msg_iov[0].length -= msg->program->reserve - (rpc_len + offset);
        length            -= msg->program->reserve - (rpc_len + offset);
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

    metric->total_latency += elapsed;
    metric->total_calls++;

    if (elapsed < metric->min_latency || metric->min_latency == 0) {
        metric->min_latency = elapsed;
    }

    if (elapsed > metric->max_latency) {
        metric->max_latency = elapsed;
    }

    if (reduce) {
        xdr_dbuf_alloc_space(msg->reply_iov, sizeof(*msg->reply_iov), msg->dbuf);
        msg->reply_iov->data   = msg_iov[0].data;
        msg->reply_iov->length = offset;
        msg->reply_iov->buffer = msg_iov[0].buffer;
        msg->reply_niov        = 1;
        msg->reply_length      = offset;

        msg_iov[0].data   += offset;
        msg_iov[0].length -= offset;

        evpl_rdma_write(evpl, msg->bind,
                        rdma_msg.rdma_body.rdma_nomsg.rdma_reply->target->handle,
                        rdma_msg.rdma_body.rdma_nomsg.rdma_reply->target->offset,
                        msg_iov, msg_niov, evpl_rpc2_write_segment_callback, msg);

        msg->pending_writes++;

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

struct evpl_rpc2_server *
evpl_rpc2_listen(
    struct evpl_rpc2_agent    *agent,
    int                        protocol,
    struct evpl_endpoint      *endpoint,
    struct evpl_rpc2_program **programs,
    int                        nprograms,
    void                      *private_data)
{
    struct evpl_rpc2_server *server;

    server = evpl_zalloc(sizeof(*server));

    server->agent        = agent;
    server->protocol     = protocol;
    server->private_data = private_data;
    server->programs     = evpl_zalloc(nprograms * sizeof(*programs));
    server->nprograms    = nprograms;
    memcpy(server->programs, programs, nprograms * sizeof(*programs));

    server->metrics = evpl_zalloc(nprograms * sizeof(*server->metrics));

    for (int i = 0; i < nprograms; i++) {
        server->programs[i]->reply_dispatch = evpl_rpc2_send_reply;

        server->metrics[i] = evpl_zalloc(
            (server->programs[i]->maxproc + 1) * sizeof(struct evpl_rpc2_metric)
            );
    }

    server->bind = evpl_listen(
        agent->evpl,
        protocol,
        endpoint,
        evpl_rpc2_accept,
        server);

    return server;
} /* evpl_rpc2_listen */

void
evpl_rpc2_server_destroy(
    struct evpl_rpc2_agent  *agent,
    struct evpl_rpc2_server *server)
{
    int                       i, j;
    struct evpl_rpc2_program *program;
    struct evpl_rpc2_metric  *shared_metric, *thread_metric;

    for (i = 0; i < server->nprograms; i++) {

        program = server->programs[i];

        pthread_mutex_lock(&program->metrics_lock);

        for (j = 0; j < program->maxproc; j++) {

            shared_metric = &program->metrics[j];
            thread_metric = &server->metrics[i][j];

            if (thread_metric->total_calls == 0) {
                continue;
            }

            shared_metric->total_latency += thread_metric->total_latency;
            shared_metric->total_calls   += thread_metric->total_calls;

            if (thread_metric->min_latency < shared_metric->min_latency ||
                shared_metric->min_latency == 0) {
                shared_metric->min_latency = thread_metric->min_latency;
            }

            if (thread_metric->max_latency > shared_metric->max_latency) {
                shared_metric->max_latency = thread_metric->max_latency;
            }
        }

        pthread_mutex_unlock(&program->metrics_lock);
    }

    for (i = 0; i < server->nprograms; i++) {
        evpl_free(server->metrics[i]);
    }

    evpl_free(server->metrics);
    evpl_free(server->programs);
    evpl_free(server);
} /* evpl_rpc2_server_destroy */

struct evpl_bind *
evpl_rpc2_connect(
    struct evpl_rpc2_agent       *agent,
    int                           protocol,
    struct evpl_endpoint         *endpoint,
    evpl_rpc2_dispatch_callback_t dispatch_callback,
    void                         *private_data)
{
    struct evpl_rpc2_conn *conn;

    conn = evpl_zalloc(sizeof(*conn));

    conn->is_server = 0;
    conn->agent     = agent;

    return evpl_connect(agent->evpl, protocol, endpoint,
                        evpl_rpc2_event,
                        rpc2_segment_callback,
                        conn);

} /* evpl_rpc2_connect */