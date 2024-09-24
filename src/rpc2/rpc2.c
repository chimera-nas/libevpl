#include "rpc2/rpc2.h"
#include "core/internal.h"

#include "rpc2_xdr.h"
#include "core/buffer.h"
#include "core/event.h"
#include "core/conn.h"

#define RPC2_MAX_BVEC 16

struct evpl_rpc2_msg {
    uint32_t            hdr;
    int                 nbvec;
    struct evpl_bvec    bvec[RPC2_MAX_BVEC];
    struct rpc_msg      msg;
    xdr_dbuf           *dbuf;
};


struct evpl_rpc2_conn {
    struct evpl_rpc2_agent *agent;
    struct evpl_rpc2_msg *recv_msg;
    uint32_t                next_xid;
};

struct evpl_rpc2_agent {
    struct evpl    *evpl;
};

static FORCE_INLINE uint32_t
rpc2_hton32(uint32_t value)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return __builtin_bswap32(value);
#else
    return value;
#endif
}

static FORCE_INLINE uint32_t
rpc2_ntoh32(uint32_t value)
{
#if __BYTE_ORDER == __LITTLE_ENDIAN
    return __builtin_bswap32(value);
#else
    return value;
#endif
}


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

static int
evpl_rpc2_recv(
    struct evpl_rpc2_agent *agent,
    struct evpl_rpc2_conn *rpc2_conn,
    struct evpl_conn *conn)
{
    struct evpl_rpc2_msg *msg;
    int         length;
    int         rc;

    if (!rpc2_conn->recv_msg) {
        rpc2_conn->recv_msg = evpl_zalloc(sizeof(*rpc2_conn->recv_msg));
    }

    msg = rpc2_conn->recv_msg;

    evpl_info("rpc2 conn received data");

    if (msg->hdr == 0) {
        length = evpl_read(agent->evpl, conn, &msg->hdr, sizeof(msg->hdr));

        evpl_info("peeked %d bytes", length);

        if (length < sizeof(msg->hdr)) {
            msg->hdr = 0;
            return 0;
        }

        msg->hdr = rpc2_ntoh32(msg->hdr);
        evpl_info("got header %u\n", msg->hdr);
    }

    evpl_info("rpc2 reading msg");

    msg->nbvec = evpl_readv(agent->evpl, conn, msg->bvec, RPC2_MAX_BVEC, msg->hdr);

    if (msg->nbvec < 0) {
        return 0;
    }

    evpl_info("got %d nbvecs", msg->nbvec);

    rc = unmarshall_rpc_msg(&msg->msg, 1, msg->bvec, msg->nbvec, msg->dbuf);

    evpl_info("unmarshalled rpc msg used %d bytes", rc);

    if (unlikely(rc < 0)) return rc;

    return 0;
}

static int
evpl_rpc2_event(
    struct evpl *evpl,
    struct evpl_conn *conn,
    unsigned int event_type,
    unsigned int event_code,
    void *private_data)
{
    struct evpl_rpc2_conn *rpc2_conn = private_data;
    struct evpl_rpc2_agent *agent = rpc2_conn->agent;

    evpl_info("rpc2 event conn %p type %u", conn, event_type);

    switch (event_type) {
    case EVPL_EVENT_CONNECTED:
        evpl_info("rpc2 conn connected");
        break;
    case EVPL_EVENT_DISCONNECTED:
        evpl_info("rpc2 conn disconnected");
        break;
    case EVPL_EVENT_RECEIVED:
        evpl_rpc2_recv(agent, rpc2_conn, conn);
        break;
    default:
        evpl_info("rpc2 unhandled event");
    }


    return 0;
}

static void
evpl_rpc2_accept(
    struct evpl_conn      *conn,
    evpl_event_callback_t *callback,
    void                 **conn_private_data,
    void                  *private_data)
{
    struct evpl_rpc2_conn *rpc2_conn;

    evpl_info("Received RPC2 connection from %s:%d",
        evpl_conn_address(conn),
        evpl_conn_port(conn));

    rpc2_conn = evpl_zalloc(sizeof(*rpc2_conn));
    rpc2_conn->agent = private_data;

    *callback = evpl_rpc2_event;
    *conn_private_data = rpc2_conn;

} /* evpl_rpc2_accept */

int
evpl_rpc2_listen(
    struct evpl_rpc2_agent       *agent,
    int                           protocol,
    const char                   *address,
    int                           port,
    evpl_rpc2_dispatch_callback_t dispatch_callback,
    void                         *private_data)
{
    int error;

    error = evpl_listen(
        agent->evpl,
        protocol,
        address,
        port,
        evpl_rpc2_accept,
        agent);

    return error;
} /* evpl_rpc2_listen */

struct evpl_conn *
evpl_rpc2_connect(
    struct evpl_rpc2_agent       *agent,
    int                           protocol,
    const char                   *address,
    int                           port,
    evpl_rpc2_dispatch_callback_t dispatch_callback,
    void                         *private_data)
{
    struct evpl_rpc2_conn *conn;

    conn = evpl_zalloc(sizeof(*conn));

    conn->agent = agent;

    return evpl_connect(agent->evpl, protocol, address, port,
        evpl_rpc2_event, conn);

} /* evpl_rpc2_connect */

void
evpl_rpc2_call(
    struct evpl_rpc2_agent       *agent,
    struct evpl_conn             *conn,
    unsigned int                  program,
    unsigned int                  version,
    unsigned int                  procedure)
{
    struct evpl_rpc2_conn *rpc2_conn = conn->private_data;
    struct evpl_rpc2_msg *msg;
    struct evpl_bvec space[RPC2_MAX_BVEC];
    int nspace, rc;

    msg = evpl_zalloc(sizeof(*msg));

    evpl_info("sending rpc2 call");

    msg->msg.xid = rpc2_conn->next_xid++;
    msg->msg.body.mtype = CALL;
    msg->msg.body.cbody.rpcvers = 2;
    msg->msg.body.cbody.prog = program;
    msg->msg.body.cbody.vers = version;
    msg->msg.body.cbody.proc = procedure;
    msg->msg.body.cbody.cred.flavor = AUTH_NONE;
    msg->msg.body.cbody.cred.body.length = 0;
    msg->msg.body.cbody.verf.flavor = AUTH_NONE;
    msg->msg.body.cbody.verf.body.length = 0;

    nspace = evpl_bvec_reserve(agent->evpl, 2*1024*1024, 8, RPC2_MAX_BVEC, space);

    if (unlikely(nspace < 0)) {
        evpl_fatal("Failed to reserve space for RPC2 call");
    }

    msg->nbvec = RPC2_MAX_BVEC;

    rc = marshall_rpc_msg(&msg->msg, 1, space, nspace, msg->bvec, &msg->nbvec, sizeof(uint32_t));

    if (unlikely(rc < 0)) {
        evpl_fatal("Failed to marshall RPC2 call headeR");
    }

    evpl_bvec_commit(agent->evpl, msg->bvec, msg->nbvec);

    *(uint32_t*)msg->bvec[0].data = rpc2_hton32(rc);

    evpl_send(agent->evpl, conn, msg->bvec, msg->nbvec);

}

