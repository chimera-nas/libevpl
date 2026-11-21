// SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
/*
 * Connection inspection: evpl_rpc2_visit_connections,
 * evpl_rpc2_server_connection_count and the application tag.
 *
 * Client and server share one thread, so the thread's connection list holds
 * both ends of every connection, and the visitor has to show only the accepted
 * ones.  The per-connection counters are read in the middle of a call, from
 * inside the handler where the request is in flight, and again once the call
 * has been answered.  The limit and the early stop are checked with two
 * connections open.  Last, the server is detached while a connection it
 * accepted is still open: the connection must no longer be visited, and
 * closing it afterwards must not touch the freed binding (the test is built
 * with AddressSanitizer in the debug build).
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef _WIN32
#include "tests/test_options.h"
#else  /* ifdef _WIN32 */
#include <getopt.h>
#endif /* ifdef _WIN32 */

#include "evpl/evpl.h"
#include "evpl/evpl_rpc2.h"

#include "core/test_log.h"
#include "test_common.h"

#include "server_inspect_xdr.h"

#define TAG         0xfeedULL
#define MAX_COLLECT 4

static enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
static int                   port  = 8110;

struct collect {
    unsigned int                     n;
    unsigned int                     stop_after; /* return 0 on this visit; 0 = never */
    struct evpl_rpc2_connection_info info[MAX_COLLECT];
};

struct test_state {
    struct HELLO_V1         *prog;
    struct evpl_rpc2_thread *thread;
    struct evpl_rpc2_server *server;
    struct collect           mid;               /* taken inside the handler of call 2 */
    int                      server_disconnects;
    int                      disconnects;
};

static struct test_state state;

struct call_ctx {
    int done;
    int status;
};

static int
collect_visit(
    const struct evpl_rpc2_connection_info *info,
    void                                   *private_data)
{
    struct collect *c = private_data;

    if (c->n < MAX_COLLECT) {
        c->info[c->n] = *info;
    }

    c->n++;

    return !(c->stop_after && c->n >= c->stop_after);
} /* collect_visit */

static unsigned int
visit(
    unsigned int    limit,
    unsigned int    stop_after,
    struct collect *c,
    int            *truncated)
{
    memset(c, 0, sizeof(*c));
    c->stop_after = stop_after;

    return evpl_rpc2_visit_connections(state.thread, limit, collect_visit, c,
                                       truncated);
} /* visit */

static void
server_recv_greet(
    struct evpl               *evpl,
    struct evpl_rpc2_conn     *conn,
    struct evpl_rpc2_cred     *cred,
    struct Hello              *call,
    struct evpl_rpc2_encoding *encoding,
    void                      *private_data)
{
    struct Hello reply;
    int          truncated, rc;

    if (call->id == 1) {
        evpl_test_abort_if(evpl_rpc2_conn_get_application_tag(conn) != 0,
                           "a new connection has a tag");
        evpl_rpc2_conn_set_application_tag(conn, TAG);
    }

    if (call->id == 2) {
        visit(16, 0, &state.mid, &truncated);
    }

    reply.id = call->id;
    xdr_set_str_static(&reply, greeting, "ack", 3);
    rc = state.prog->send_reply_GREET(evpl, NULL, &reply, encoding);
    evpl_test_abort_if(rc, "send_reply_GREET failed");
} /* server_recv_greet */

static void
notify(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_conn   *conn,
    struct evpl_rpc2_notify *notify,
    void                    *private_data)
{
    if (notify->notify_type != EVPL_RPC2_NOTIFY_DISCONNECTED) {
        return;
    }

    state.disconnects++;

    if (conn->server_binding) {
        state.server_disconnects++;
    }
} /* notify */

static void
client_recv_reply_greet(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct Hello                *reply,
    int                          status,
    void                        *callback_private_data)
{
    struct call_ctx *ctx = callback_private_data;

    ctx->done   = 1;
    ctx->status = status;
} /* client_recv_reply_greet */

static void
greet(
    struct evpl           *evpl,
    struct evpl_rpc2_conn *conn,
    uint32_t               id)
{
    struct call_ctx ctx = { 0 };
    struct Hello    request;

    request.id = id;
    xdr_set_str_static(&request, greeting, "hi", 2);
    state.prog->send_call_GREET(&state.prog->rpc2, evpl, conn, NULL, &request,
                                0, 0, NULL, 0, 0, client_recv_reply_greet, &ctx);

    while (!ctx.done) {
        evpl_continue(evpl);
    }

    evpl_test_abort_if(ctx.status != 0, "call %u failed: %d", id, ctx.status);
} /* greet */

static void
check_counters(
    const char                             *when,
    const struct evpl_rpc2_connection_info *info,
    uint64_t                                rx,
    uint64_t                                tx,
    uint64_t                                done,
    uint64_t                                inflight)
{
    evpl_test_abort_if(info->rx_msgs != rx, "%s: rx_msgs %lu, expected %lu",
                       when, (unsigned long) info->rx_msgs, (unsigned long) rx);
    evpl_test_abort_if(info->tx_msgs != tx, "%s: tx_msgs %lu, expected %lu",
                       when, (unsigned long) info->tx_msgs, (unsigned long) tx);
    evpl_test_abort_if(info->requests_done != done,
                       "%s: requests_done %lu, expected %lu",
                       when, (unsigned long) info->requests_done,
                       (unsigned long) done);
    evpl_test_abort_if(info->inflight != inflight,
                       "%s: inflight %lu, expected %lu",
                       when, (unsigned long) info->inflight,
                       (unsigned long) inflight);
    evpl_test_abort_if(!info->rx_bytes, "%s: rx_bytes is 0", when);
    evpl_test_abort_if(info->tx_msgs && !info->tx_bytes, "%s: tx_bytes is 0",
                       when);
} /* check_counters */

static void
usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s [-r protocol] [-p port]\n", prog_name);
    exit(1);
} /* usage */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl              *evpl;
    struct evpl_rpc2_conn    *conn1, *conn2, *conn3;
    struct evpl_endpoint     *endpoint;
    struct HELLO_V1           prog;
    struct evpl_rpc2_program *programs[1];
    struct collect            c;
    unsigned int              scanned;
    int                       opt, rc, truncated, tagged, i;

    test_evpl_config();

    while ((opt = getopt(argc, argv, "r:p:")) != -1) {
        switch (opt) {
            case 'r':
                rc = evpl_protocol_lookup(&proto, optarg);
                if (rc) {
                    fprintf(stderr, "Invalid protocol '%s'\n", optarg);
                    return 1;
                }
                break;
            case 'p':
                port = atoi(optarg);
                break;
            default:
                usage(argv[0]);
        } /* switch */
    }

    evpl = evpl_create(NULL);

    HELLO_V1_init(&prog);
    prog.recv_call_GREET = server_recv_greet;
    state.prog           = &prog;
    programs[0]          = &prog.rpc2;

    state.server = evpl_rpc2_server_init(programs, 1);
    endpoint     = evpl_endpoint_create(test_address(proto, "127.0.0.1", argv[0]), port);
    evpl_rpc2_server_start(state.server, proto, endpoint);

    state.thread = evpl_rpc2_thread_init(evpl, programs, 1, notify, &state);
    evpl_rpc2_server_attach(state.thread, state.server, &state);

    /* One connection, three calls.  The handler of call 2 took the snapshot
     * while that call was in flight: two calls received, one answered. */
    conn1 = evpl_rpc2_client_connect(state.thread, proto, endpoint, NULL, 0, NULL);
    evpl_test_abort_if(!conn1, "Failed to create RPC2 client");

    greet(evpl, conn1, 1);
    greet(evpl, conn1, 2);
    greet(evpl, conn1, 3);

    evpl_test_abort_if(state.mid.n != 1, "snapshot in the handler saw %u "
                       "connections, expected only the accepted one",
                       state.mid.n);
    check_counters("mid-call", &state.mid.info[0], 2, 1, 1, 1);

    scanned = visit(16, 0, &c, &truncated);
    evpl_test_abort_if(c.n != 1, "visited %u connections, expected 1", c.n);
    evpl_test_abort_if(scanned < c.n, "examined %u, visited %u", scanned, c.n);
    evpl_test_abort_if(truncated, "a complete walk reported truncation");
    check_counters("after calls", &c.info[0], 3, 3, 3, 0);

    evpl_test_abort_if(c.info[0].server != state.server, "wrong server identity");
    evpl_test_abort_if(c.info[0].application_tag != TAG, "tag %lx, expected %lx",
                       (unsigned long) c.info[0].application_tag,
                       (unsigned long) TAG);
    evpl_test_abort_if(c.info[0].nprograms != 1 ||
                       c.info[0].programs[0].program != prog.rpc2.program ||
                       c.info[0].programs[0].version != prog.rpc2.version,
                       "observed program not reported");
    evpl_test_abort_if(c.info[0].bind.protocol != proto, "wrong protocol");
    evpl_test_abort_if(!c.info[0].bind.serial ||
                       !c.info[0].bind.created_monotonic_ns,
                       "bind identity missing");
    evpl_test_abort_if(c.info[0].rdma_framing, "stream connection with RDMA framing");
    evpl_test_abort_if(evpl_rpc2_server_connection_count(state.thread,
                                                         state.server) != 1,
                       "connection count is not 1");

    /* A second connection: both are listed, with their own identities and
     * counters, and the walk can be cut short two ways. */
    conn2 = evpl_rpc2_client_connect(state.thread, proto, endpoint, NULL, 0, NULL);
    evpl_test_abort_if(!conn2, "Failed to create second RPC2 client");
    greet(evpl, conn2, 4);

    evpl_test_abort_if(evpl_rpc2_server_connection_count(state.thread,
                                                         state.server) != 2,
                       "connection count is not 2");

    scanned = visit(16, 0, &c, &truncated);
    evpl_test_abort_if(scanned < c.n, "examined %u, visited %u", scanned, c.n);
    evpl_test_abort_if(c.n != 2, "visited %u connections, expected 2", c.n);
    evpl_test_abort_if(truncated, "a complete walk reported truncation");
    evpl_test_abort_if(c.info[0].bind.serial == c.info[1].bind.serial &&
                       c.info[0].bind.remote.port == c.info[1].bind.remote.port,
                       "two connections share one identity");

    tagged = 0;
    for (i = 0; i < 2; i++) {
        if (c.info[i].application_tag == TAG) {
            tagged++;
            check_counters("first connection", &c.info[i], 3, 3, 3, 0);
        } else {
            evpl_test_abort_if(c.info[i].application_tag != 0,
                               "unexpected tag %lx",
                               (unsigned long) c.info[i].application_tag);
            check_counters("second connection", &c.info[i], 1, 1, 1, 0);
        }
    }
    evpl_test_abort_if(tagged != 1, "%d connections carry the tag, expected 1",
                       tagged);

    scanned = visit(1, 0, &c, &truncated);
    evpl_test_abort_if(scanned != 1, "limit 1 examined %u", scanned);
    evpl_test_abort_if(!truncated, "a walk cut by the limit did not say so");

    visit(16, 1, &c, &truncated);
    evpl_test_abort_if(c.n != 1, "a visitor that stops saw %u connections", c.n);
    evpl_test_abort_if(!truncated, "a walk the visitor stopped did not say so");

    /* Closing a connection removes it from the list and from the count. */
    evpl_rpc2_client_disconnect(state.thread, conn2);
    while (state.server_disconnects < 1) {
        evpl_continue(evpl);
    }

    evpl_test_abort_if(evpl_rpc2_server_connection_count(state.thread,
                                                         state.server) != 1,
                       "connection count is not 1 after a disconnect");
    visit(16, 0, &c, &truncated);
    evpl_test_abort_if(c.n != 1, "visited %u connections after a disconnect", c.n);
    evpl_test_abort_if(c.info[0].application_tag != TAG, "the wrong one is left");

    /* Detach the server with a connection still open.  The connection must
     * drop out of the walk, and closing it must not use the freed binding. */
    conn3 = evpl_rpc2_client_connect(state.thread, proto, endpoint, NULL, 0, NULL);
    evpl_test_abort_if(!conn3, "Failed to create third RPC2 client");
    greet(evpl, conn3, 5);

    evpl_rpc2_server_stop(state.server);
    evpl_rpc2_server_detach(state.thread, state.server);

    visit(16, 0, &c, &truncated);
    evpl_test_abort_if(c.n != 0, "visited %u connections of a detached server",
                       c.n);
    evpl_test_abort_if(evpl_rpc2_server_connection_count(state.thread,
                                                         state.server) != 0,
                       "a detached server still has connections");

    /* The connection keeps working without its binding: this call must not
     * read the freed binding's metric instances. */
    greet(evpl, conn3, 6);

    evpl_rpc2_client_disconnect(state.thread, conn3);
    evpl_rpc2_client_disconnect(state.thread, conn1);

    /* Each of the three connections reports its client end and its server
     * end. */
    while (state.disconnects < 6) {
        evpl_continue(evpl);
    }

    evpl_rpc2_thread_destroy(state.thread);
    evpl_rpc2_server_destroy(state.server);
    evpl_destroy(evpl);

    printf("Test PASSED\n");
    return 0;
} /* main */
