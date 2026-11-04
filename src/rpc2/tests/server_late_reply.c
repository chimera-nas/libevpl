// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
/*
 * A server replies to a call after the client that made it has disconnected.
 *
 * Servers execute calls asynchronously, so the peer can go away while one is
 * still running; the reply then comes back for a connection rpc2 has already
 * torn down.  Asserted:
 *
 *   1. The late reply is neither sent nor fatal.  Run under AddressSanitizer
 *      this is the substance of the test: the reply path used to read the
 *      connection after the disconnect had freed it.
 *   2. The reply-capture hook still sees the reply.  A duplicate-request cache
 *      depends on that: the client's retransmit, on its next connection, is
 *      owed exactly this answer.
 *   3. The server is unaffected: a new connection is served normally.
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

#include "server_late_reply_xdr.h"

static enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
static int                   port  = 8000;

/* Calls carrying this id are held by the server instead of answered. */
#define HOLD_ID 9

struct test_state {
    struct HELLO_V1           *prog;
    struct evpl_rpc2_encoding *held;              /* the call being held */
    int                        server_disconnects; /* server-side conns closed */
    int                        captured;          /* replies the hook saw */
};

struct call_ctx {
    uint32_t id;
    int      done;
    int      status;
};

static void
capture_reply(
    const struct evpl_iovec *iov,
    int                      niov,
    int                      total_length,
    uint32_t                 body_offset,
    void                    *private_data)
{
    struct test_state *state = private_data;

    (void) iov;
    (void) niov;
    (void) total_length;
    (void) body_offset;
    state->captured++;
} /* capture_reply */

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
    struct Hello       reply;
    int                rc;

    if (call->id == HOLD_ID) {
        evpl_test_info("server holding call id %u", call->id);
        encoding->reply_capture_cb      = capture_reply;
        encoding->reply_capture_private = state;
        state->held                     = encoding;
        return;
    }

    reply.id = call->id;
    xdr_set_str_static(&reply, greeting, "ack", 3);
    rc = state->prog->send_reply_GREET(evpl, NULL, &reply, encoding);
    evpl_test_abort_if(rc, "send_reply_GREET failed");
} /* server_recv_greet */

static void
notify(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_conn   *conn,
    struct evpl_rpc2_notify *notify,
    void                    *private_data)
{
    struct test_state *state = private_data;

    if (notify->notify_type == EVPL_RPC2_NOTIFY_DISCONNECTED &&
        conn->server_binding) {
        state->server_disconnects++;
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
    if (status == 0) {
        evpl_test_abort_if(reply->id != ctx->id,
                           "reply carried id %u, expected %u", reply->id,
                           ctx->id);
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
    struct call_ctx           held_call, after;
    struct Hello              reply;
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

    thread = evpl_rpc2_thread_init(evpl, programs, 1, notify, &state);
    evpl_rpc2_server_attach(thread, server, &state);

    conn = evpl_rpc2_client_connect(thread, proto, endpoint, NULL, 0, NULL);
    if (!conn) {
        evpl_test_error("Failed to create RPC2 client");
        evpl_destroy(evpl);
        return -1;
    }

    memset(&held_call, 0, sizeof(held_call));
    memset(&after, 0, sizeof(after));
    held_call.id = HOLD_ID;
    after.id     = 1;

    /* The server takes the call and holds it. */
    send_greet(evpl, &prog, conn, &held_call);
    while (!state.held) {
        evpl_continue(evpl);
    }

    /* The client goes away while the call is still executing. */
    evpl_rpc2_client_disconnect(thread, conn);
    while (!held_call.done || state.server_disconnects < 1) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if(held_call.status == 0,
                       "the client got a reply to a call nobody answered");

    /* 1 + 2. The server finishes and replies to a connection that is gone. */
    reply.id = HOLD_ID;
    xdr_set_str_static(&reply, greeting, "late", 4);
    rc = prog.send_reply_GREET(evpl, NULL, &reply, state.held);
    evpl_test_abort_if(rc, "late send_reply_GREET failed: %d", rc);
    state.held = NULL;

    evpl_test_abort_if(state.captured != 1,
                       "the late reply was captured %d times, expected once",
                       state.captured);

    /* 3. A new connection is served normally. */
    conn = evpl_rpc2_client_connect(thread, proto, endpoint, NULL, 0, NULL);
    evpl_test_abort_if(!conn, "reconnect failed");
    send_greet(evpl, &prog, conn, &after);
    while (!after.done) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if(after.status != 0, "call after the late reply failed: %d",
                       after.status);

    evpl_rpc2_server_stop(server);
    evpl_rpc2_client_disconnect(thread, conn);
    evpl_rpc2_server_detach(thread, server);
    evpl_rpc2_thread_destroy(thread);
    evpl_rpc2_server_destroy(server);
    evpl_destroy(evpl);

    printf("Test PASSED\n");
    return 0;
} /* main */
