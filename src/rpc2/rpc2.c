#include "rpc2/rpc2.h"
#include "core/internal.h"

#include "utlist.h"

#include "rpc2/common.h"
#include "rpc2_xdr.h"
#include "core/evpl.h"

#define RPC2_MAX_BVEC 16

struct evpl_rpc2_msg {
    uint32_t              hdr;
    int                   nbvec;
    struct evpl_bvec      bvec[RPC2_MAX_BVEC];
    struct rpc_msg        msg;
    xdr_dbuf             *dbuf;
    struct evpl_rpc2_msg *prev;
    struct evpl_rpc2_msg *next;
};

struct evpl_rpc2_conn {
    struct evpl_rpc2_agent *agent;
    struct evpl_rpc2_msg   *recv_msg;
    uint32_t                next_xid;
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
        msg = evpl_zalloc(sizeof(*msg));
    }

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
evpl_rpc2_bvec_skip(
    struct evpl_bvec **out_iov,
    int               *out_niov,
    struct evpl_bvec  *in_iov,
    int                in_niov,
    int                offset)
{
    struct evpl_bvec *cur  = in_iov;
    int               left = offset;
    int               niov = in_niov;

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
} /* evpl_rpc2_bvec_skip */
static void
evpl_rpc2_handle_msg(
    struct evpl_rpc2_agent *agent,
    struct evpl_rpc2_msg   *msg)
{
    evpl_rpc2_debug("rpc2 received xid %u mtype %u", msg->msg.xid,
                    msg->msg.body.mtype);

    switch (msg->msg.body.mtype) {
        case CALL:
            evpl_rpc2_debug(
                "rpc2 received call rpcvers %u prog %u vers %u proc %u",
                msg->msg.body.cbody.rpcvers,
                msg->msg.body.cbody.prog,
                msg->msg.body.cbody.vers,
                msg->msg.body.cbody.proc);
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
    struct evpl_rpc2_conn  *rpc2_conn = private_data;
    struct evpl_rpc2_agent *agent     = rpc2_conn->agent;
    struct evpl_rpc2_msg   *msg;
    struct evpl_bvec       *msg_iov;
    int                     msg_niov;
    int                     rc;

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

            evpl_rpc2_bvec_skip(&msg_iov, &msg_niov, notify->recv_msg.bvec,
                                notify->recv_msg.nbvec, sizeof(uint32_t));

            rc = unmarshall_rpc_msg(&msg->msg, 1,
                                    msg_iov, msg_niov,
                                    msg->dbuf);

            /* XXX this should not be a crash */
            evpl_rpc2_abort_if(rc + sizeof(uint32_t) != notify->recv_msg.length,
                               "Unmarshall of RPC message ended short");

            evpl_rpc2_handle_msg(agent, msg);
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
    struct evpl_rpc2_conn *rpc2_conn;

    rpc2_conn        = evpl_zalloc(sizeof(*rpc2_conn));
    rpc2_conn->agent = private_data;

    *notify_callback   = evpl_rpc2_event;
    *segment_callback  = rpc2_segment_callback;
    *conn_private_data = rpc2_conn;

} /* evpl_rpc2_accept */

struct evpl_bind *
evpl_rpc2_listen(
    struct evpl_rpc2_agent       *agent,
    int                           protocol,
    struct evpl_endpoint         *endpoint,
    evpl_rpc2_dispatch_callback_t dispatch_callback,
    void                         *private_data)
{
    return evpl_listen(
        agent->evpl,
        protocol,
        endpoint,
        evpl_rpc2_accept,
        agent);
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

    conn->agent = agent;

    return evpl_connect(agent->evpl, protocol, endpoint,
                        evpl_rpc2_event,
                        rpc2_segment_callback,
                        conn);

} /* evpl_rpc2_connect */
#if 0
void
evpl_rpc2_call(
    struct evpl_rpc2_agent *agent,
    struct evpl_conn       *conn,
    unsigned int            program,
    unsigned int            version,
    unsigned int            procedure)
{
    struct evpl_rpc2_conn *rpc2_conn = conn->private_data;
    struct evpl_rpc2_msg  *msg;
    struct evpl_bvec       space[RPC2_MAX_BVEC];
    int                    nspace, rc;

    msg = evpl_zalloc(sizeof(*msg));

    evpl_info("sending rpc2 call");

    msg->msg.xid                         = rpc2_conn->next_xid++;
    msg->msg.body.mtype                  = CALL;
    msg->msg.body.cbody.rpcvers          = 2;
    msg->msg.body.cbody.prog             = program;
    msg->msg.body.cbody.vers             = version;
    msg->msg.body.cbody.proc             = procedure;
    msg->msg.body.cbody.cred.flavor      = AUTH_NONE;
    msg->msg.body.cbody.cred.body.length = 0;
    msg->msg.body.cbody.verf.flavor      = AUTH_NONE;
    msg->msg.body.cbody.verf.body.length = 0;

    nspace = evpl_bvec_reserve(agent->evpl, 2 * 1024 * 1024, 8, RPC2_MAX_BVEC,
                               space);

    if (unlikely(nspace < 0)) {
        evpl_fatal("Failed to reserve space for RPC2 call");
    }

    msg->nbvec = RPC2_MAX_BVEC;

    rc = marshall_rpc_msg(&msg->msg, 1, space, nspace, msg->bvec, &msg->nbvec,
                          sizeof(uint32_t));

    if (unlikely(rc < 0)) {
        evpl_fatal("Failed to marshall RPC2 call headeR");
    }

    evpl_bvec_commit(agent->evpl, msg->bvec, msg->nbvec);

    *(uint32_t *) msg->bvec[0].data = rpc2_hton32(rc);

    evpl_send(agent->evpl, conn, msg->bvec, msg->nbvec);

} /* evpl_rpc2_call */
#endif /* if 0 */