#include "rpc2/rpc2.h"
#include "core/internal.h"

#include "utlist.h"

#include "rpc2/common.h"
#include "rpc2_xdr.h"
#include "rpc2/rpc2_program.h"
#include "core/evpl.h"

struct evpl_rpc2_conn {
    int                      is_server;
    struct evpl_rpc2_server *server;
    struct evpl_rpc2_agent  *agent;
    struct evpl_rpc2_msg    *recv_msg;
    uint32_t                 next_xid;
};

struct evpl_rpc2_server {
    struct evpl_rpc2_agent    *agent;
    struct evpl_bind          *bind;
    struct evpl_rpc2_program **programs;
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
        msg             = agent->free_msg;
        agent->free_msg = msg->next;
    } else {
        msg             = evpl_zalloc(sizeof(*msg));
        msg->dbuf       = xdr_dbuf_alloc();
        msg->msg_buffer = evpl_zalloc(4096);
    }

    xdr_dbuf_reset(msg->dbuf);

    return msg;
} /* evpl_rpc2_msg_alloc */

static inline void
evpl_rpc2_msg_free(
    struct evpl_rpc2_agent *agent,
    struct evpl_rpc2_msg   *msg)
{
    DL_PREPEND(agent->free_msg, msg);
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
    evpl_free(agent);
} /* evpl_rpc2_agent_destroy */

static inline void
evpl_rpc2_iovec_skip(
    struct evpl_iovec **out_iov,
    int                *out_niov,
    struct evpl_iovec  *in_iov,
    int                 in_niov,
    int                 offset)
{
    struct evpl_iovec *cur  = in_iov;
    int                left = offset;
    int                niov = in_niov;

    while (left) {
        if (cur->length > left) {
            cur->data   += left;
            cur->length -= left;
            --niov;
            break;
        }
        left -= cur->length;
        cur++;
    }

    *out_iov  = cur;
    *out_niov = niov;
} /* evpl_rpc2_iovec_skip */
static void
evpl_rpc2_handle_msg(
    struct evpl           *evpl,
    struct evpl_rpc2_conn *conn,
    struct evpl_rpc2_msg  *msg,
    struct rpc_msg        *rpc_msg,
    struct evpl_iovec     *iov,
    int                    niov)
{
    struct evpl_rpc2_server  *server = conn->server;
    struct evpl_rpc2_program *program;
    int                       i;
    int                       error;

    evpl_rpc2_debug("rpc2 received xid %u mtype %u", rpc_msg->xid,
                    rpc_msg->body.mtype);

    msg->xid  = rpc_msg->xid;
    msg->proc = rpc_msg->body.cbody.proc;

    switch (rpc_msg->body.mtype) {
        case CALL:
            evpl_rpc2_debug(
                "rpc2 received call rpcvers %u prog %u vers %u proc %u",
                rpc_msg->body.cbody.rpcvers,
                rpc_msg->body.cbody.prog,
                rpc_msg->body.cbody.vers,
                rpc_msg->body.cbody.proc);

            msg->program = NULL;

            for (i  = 0; i < server->nprograms; i++) {
                program = server->programs[i];

                if (program->program == rpc_msg->body.cbody.prog &&
                    program->version == rpc_msg->body.cbody.vers) {

                    msg->program = program;
                    break;
                }
            }

            if (unlikely(!msg->program)) {
                evpl_rpc2_debug(
                    "rpc2 received call for unknown program %u vers %u",
                    rpc_msg->body.cbody.prog,
                    rpc_msg->body.cbody.vers);
            }


            error = program->call_dispatch(evpl, msg, iov, niov, server->
                                           private_data);

            evpl_rpc2_debug("rpc2 call dispatch returned %d", error);

            break;
        case REPLY:
            break;
    } /* switch */
} /* evpl_rpc2_handle_msg */

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
    struct rpc_msg           rpc_msg;
    struct evpl_rpc2_msg    *msg;
    struct evpl_iovec       *hdr_iov, *msg_iov;
    int                      hdr_niov, msg_niov;
    int                      rc;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            evpl_rpc2_info("rpc2 conn connected");
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            evpl_rpc2_info("rpc2 conn disconnected");
            break;
        case EVPL_NOTIFY_RECV_MSG:
            evpl_rpc2_info("rpc2 received msg length %d", notify->recv_msg.
                           length);

            msg = evpl_rpc2_msg_alloc(agent);

            msg->bind = bind;
            evpl_rpc2_iovec_skip(&hdr_iov, &hdr_niov, notify->recv_msg.iovec,
                                 notify->recv_msg.niov, sizeof(uint32_t));

            rc = unmarshall_rpc_msg(&rpc_msg, 1,
                                    hdr_iov, hdr_niov,
                                    msg->dbuf);

            evpl_rpc2_debug("unmarshalled rpc msg len %d of %d", rc, notify->
                            recv_msg.length);

            evpl_rpc2_iovec_skip(&msg_iov, &msg_niov, hdr_iov, hdr_niov, rc);

            evpl_rpc2_handle_msg(evpl, rpc2_conn, msg, &rpc_msg, msg_iov,
                                 msg_niov);
            break;
        default:
            evpl_rpc2_info("rpc2 unhandled event");
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

static int
evpl_rpc2_send_reply(
    struct evpl          *evpl,
    struct evpl_rpc2_msg *msg,
    struct evpl_iovec    *msg_iov,
    int                   msg_niov,
    int                   length)
{
    struct evpl_iovec iov[8], reply_iov[8];
    int               reply_len, niov, reply_niov;
    uint32_t          hdr;
    struct rpc_msg    rpc_reply;

    evpl_rpc2_debug("rpc2 send reply xid %u proc %u", msg->xid, msg->proc);

    niov = evpl_iovec_reserve(evpl, 4096, 0, 8, iov);

    evpl_rpc2_debug("reserved space into %d iovs", niov);

    rpc_reply.xid                                         = msg->xid;
    rpc_reply.body.mtype                                  = REPLY;
    rpc_reply.body.rbody.stat                             = 0;
    rpc_reply.body.rbody.areply.verf.flavor               = AUTH_NONE;
    rpc_reply.body.rbody.areply.reply_data.stat           = AUTH_OK;
    rpc_reply.body.rbody.areply.reply_data.results.length = 0;

    reply_len = marshall_rpc_msg(&rpc_reply, 1, iov, niov, reply_iov, &
                                 reply_niov, 4);

    hdr = rpc2_hton32(((reply_len - 4) + length) | 0x80000000);

    memcpy(reply_iov[0].data, &hdr, sizeof(hdr));

    evpl_iovec_commit(evpl, 0, reply_iov, reply_niov);

    evpl_rpc2_debug("marshalled reply rc %d into %d iovs", reply_len, reply_niov
                    );

    evpl_sendv(evpl, msg->bind, reply_iov, reply_niov, reply_len);
    evpl_sendv(evpl, msg->bind, msg_iov, msg_niov, length);

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
    server->private_data = private_data;
    server->programs     = evpl_zalloc(nprograms * sizeof(*programs));
    server->nprograms    = nprograms;
    memcpy(server->programs, programs, nprograms * sizeof(*programs));

    for (int i = 0; i < nprograms; i++) {
        server->programs[i]->reply_dispatch = evpl_rpc2_send_reply;
    }

    server->bind = evpl_listen(
        agent->evpl,
        protocol,
        endpoint,
        evpl_rpc2_accept,
        server);

    return server;
} /* evpl_rpc2_listen */

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