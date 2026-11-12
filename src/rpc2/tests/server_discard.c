// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
/*
 * evpl_rpc2_discard_request: a server can end a call without answering it.
 *
 * Asserted, on one connection:
 *
 *   1. A discarded call gets no reply.  The client's callback for it does not
 *      fire while the connection is up.
 *   2. The connection is unharmed: calls made after the discard are answered
 *      normally, so the discard released only its own request.
 *   3. The discarded call is completed by the client's own disconnect path
 *      (EVPL_RPC2_REPLY_CONN_LOST), which is what a client sees when a server
 *      drops a call and the connection later goes away.
 *
 * Run under AddressSanitizer this also checks that the discard returns the
 * request's memory exactly once: a double free, or a later touch of the dbuf
 * the decoded call lived in, fails the run.
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

#include "server_discard_xdr.h"

static enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
static int                   port  = 8000;

/* Calls carrying this id are discarded by the server; every other id is
 * answered. */
#define DISCARD_ID 7

struct test_state {
    struct HELLO_V1 *prog;
    int              server_calls;
    int              server_discards;
    int              replies;        /* answered calls the client received */
    int              lost;           /* calls completed by the disconnect */
};

struct call_ctx {
    struct test_state *state;
    uint32_t           id;
    int                done;
    int                status;
};

static void
server_recv_greet(
    struct evpl               *evpl,
    struct evpl_rpc2_conn     *conn,
    struct evpl_rpc2_cred     *cred,
    struct Hello              *call,
    struct evpl_rpc2_encoding *encoding,
    void                      *private_data)
{
    struct test_state *state = private_data;
    struct HELLO_V1   *prog  = state->prog;
    struct Hello       reply;
    int                rc;

    state->server_calls++;

    if (call->id == DISCARD_ID) {
        evpl_test_info("server discarding call id %u (xid %u)", call->id,
                       encoding->xid);
        state->server_discards++;
        evpl_rpc2_discard_request(evpl, encoding);
        return;
    }

    reply.id = call->id;
    xdr_set_str_static(&reply, greeting, "ack", 3);

    rc = prog->send_reply_GREET(evpl, NULL, &reply, encoding);
    evpl_test_abort_if(rc, "send_reply_GREET failed");
} /* server_recv_greet */

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

    if (status == 0) {
        evpl_test_abort_if(reply->id != ctx->id,
                           "reply carried id %u, expected %u", reply->id,
                           ctx->id);
        ctx->state->replies++;
    } else {
        ctx->state->lost++;
    }
} /* client_recv_reply_greet */

static void
send_greet(
    struct evpl           *evpl,
    struct HELLO_V1       *prog,
    struct evpl_rpc2_conn *conn,
    struct call_ctx       *ctx)
{
    struct Hello request;

    request.id = ctx->id;
    xdr_set_str_static(&request, greeting, "hi", 2);

    prog->send_call_GREET(&prog->rpc2, evpl, conn, NULL, &request, 0, 0, NULL,
                          0, 0, client_recv_reply_greet, ctx);
} /* send_greet */

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
    struct evpl_rpc2_server  *server;
    struct evpl_rpc2_conn    *conn;
    struct evpl_rpc2_thread  *thread;
    struct evpl_endpoint     *endpoint;
    struct HELLO_V1           prog;
    struct evpl_rpc2_program *programs[1];
    struct test_state         state = { 0 };
    struct call_ctx           dropped, after1, after2;
    int                       opt, rc;

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
    programs[0]          = &prog.rpc2;
    state.prog           = &prog;

    server   = evpl_rpc2_server_init(programs, 1);
    endpoint = evpl_endpoint_create(test_address(proto, "127.0.0.1", argv[0]), port);
    evpl_rpc2_server_start(server, proto, endpoint);

    thread = evpl_rpc2_thread_init(evpl, programs, 1, NULL, NULL);
    evpl_rpc2_server_attach(thread, server, &state);

    conn = evpl_rpc2_client_connect(thread, proto, endpoint, NULL, 0, NULL);

    if (!conn) {
        evpl_test_error("Failed to create RPC2 client");
        evpl_destroy(evpl);
        return -1;
    }

    memset(&dropped, 0, sizeof(dropped));
    memset(&after1, 0, sizeof(after1));
    memset(&after2, 0, sizeof(after2));
    dropped.state = after1.state = after2.state = &state;
    dropped.id    = DISCARD_ID;
    after1.id     = 1;
    after2.id     = 2;

    /* 1. The discarded call is handled by the server but never answered. */
    send_greet(evpl, &prog, conn, &dropped);

    while (state.server_discards < 1) {
        evpl_continue(evpl);
    }

    /* 2. The connection still works: two more calls, both answered.  Their
     *    replies arriving also gives the discarded call every chance to have
     *    been (wrongly) answered first -- replies on one connection are
     *    processed in order. */
    send_greet(evpl, &prog, conn, &after1);
    send_greet(evpl, &prog, conn, &after2);

    while (!after1.done || !after2.done) {
        evpl_continue(evpl);
    }

    evpl_test_abort_if(after1.status != 0 || after2.status != 0,
                       "calls after the discard failed: %d %d",
                       after1.status, after2.status);
    evpl_test_abort_if(dropped.done,
                       "the discarded call was answered (status %d)",
                       dropped.status);
    evpl_test_abort_if(state.server_calls != 3,
                       "server handled %d calls, expected 3",
                       state.server_calls);
    evpl_test_abort_if(state.replies != 2,
                       "client received %d replies, expected 2",
                       state.replies);

    /* 3. The client's disconnect completes the call nobody answered.  The
     *    completion runs when the loop processes the disconnect, so pump until
     *    it lands; the test's own timeout bounds a call that never completes. */
    evpl_rpc2_server_stop(server);
    evpl_rpc2_client_disconnect(thread, conn);

    while (!dropped.done) {
        evpl_continue(evpl);
    }

    evpl_test_abort_if(!dropped.done || dropped.status == 0,
                       "the discarded call was not completed by the "
                       "disconnect (done %d, status %d)",
                       dropped.done, dropped.status);
    evpl_test_abort_if(state.lost != 1, "%d calls lost, expected 1",
                       state.lost);

    evpl_rpc2_server_detach(thread, server);
    evpl_rpc2_thread_destroy(thread);
    evpl_rpc2_server_destroy(server);
    evpl_destroy(evpl);

    printf("Test PASSED\n");
    return 0;
} /* main */
