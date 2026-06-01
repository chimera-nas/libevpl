// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Exercises the client-side disconnect path: when a connection is torn down
 * with calls still in flight, each pending call's reply callback must fire with
 * EVPL_RPC2_REPLY_TRANSPORT_ERROR (rather than being silently dropped, which
 * would hang the caller forever).  Also verifies that a caller may re-enter the
 * RPC layer from within that error callback -- connecting and issuing a fresh
 * call -- which models a proxy that lazily reconnects after dropping its cached
 * connection.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "evpl/evpl.h"
#include "evpl/evpl_rpc2.h"

#include "core/test_log.h"
#include "test_common.h"

#include "client_disconnect_xdr.h"

static enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
static int                   port  = 8000;

struct test_state {
    struct evpl             *evpl;
    struct evpl_rpc2_thread *thread;
    struct HELLO_V1         *prog;
    struct evpl_endpoint    *endpoint;        /* real, listening server */

    int                      transport_error_seen;    /* Test A: error callback fired */
    int                      reentrant_completed;      /* Test B/C: re-entrant call succeeded */
};

/* Server replies normally.  Only the re-entrant call ever reaches it. */
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

    reply.id = 100;
    xdr_set_str_static(&reply, greeting, "Hello from server!", strlen("Hello from server!"));
    rc = state->prog->send_reply_GREET(evpl, NULL, &reply, encoding);
    evpl_test_abort_if(rc, "failed to send GREET reply: %d", rc);
} /* server_recv_greet */

/* Reply callback for the re-entrant call issued from within the error callback. */
static void
client_recv_reply_reentrant(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct Hello                *reply,
    int                          status,
    void                        *callback_private_data)
{
    struct test_state *state = callback_private_data;

    evpl_test_abort_if(status != 0, "re-entrant call status %d", status);
    evpl_test_abort_if(!reply, "re-entrant call missing reply");
    evpl_test_abort_if(reply->id != 100, "re-entrant reply id mismatch");

    state->reentrant_completed = 1;
    evpl_test_info("Re-entrant call completed");
} /* client_recv_reply_reentrant */

/*
 * Reply callback for the first call.  This must fire with a transport error when
 * the connection is dropped.  From inside it we re-enter the RPC layer: open a
 * fresh connection and issue a new call, proving the disconnect teardown is safe
 * against re-entrant connect/send.
 */
static void
client_recv_reply_first(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct Hello                *reply,
    int                          status,
    void                        *callback_private_data)
{
    struct test_state     *state = callback_private_data;
    struct evpl_rpc2_conn *conn2;
    struct Hello           request;

    evpl_test_info("First call completed with status=%d", status);

    evpl_test_abort_if(status != EVPL_RPC2_REPLY_TRANSPORT_ERROR,
                       "expected transport error (-2), got %d", status);
    evpl_test_abort_if(reply != NULL, "transport error must carry a NULL reply");

    state->transport_error_seen = 1;

    /* Re-entrant reconnect + send to the real server, from within the
     * disconnect-driven callback -- models a proxy lazily reconnecting after
     * dropping its cached connection. */
    conn2 = evpl_rpc2_client_connect(state->thread, proto, state->endpoint, NULL, 0, NULL);
    evpl_test_abort_if(!conn2, "re-entrant connect failed");

    request.id = 42;
    xdr_set_str_static(&request, greeting, "Hello again!", strlen("Hello again!"));

    state->prog->send_call_GREET(&state->prog->rpc2, evpl, conn2, NULL, &request,
                                 0, 0, NULL, 0, 0, client_recv_reply_reentrant, state);
} /* client_recv_reply_first */

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
    struct Hello              request;
    struct evpl_rpc2_program *programs[1];
    struct test_state         state = { 0 };
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

    server   = evpl_rpc2_server_init(programs, 1);
    endpoint = evpl_endpoint_create("0.0.0.0", port);
    evpl_rpc2_server_start(server, proto, endpoint);

    thread = evpl_rpc2_thread_init(evpl, programs, 1, NULL, NULL);
    evpl_rpc2_server_attach(thread, server, &state);

    state.evpl     = evpl;
    state.thread   = thread;
    state.prog     = &prog;
    state.endpoint = endpoint;

    conn = evpl_rpc2_client_connect(thread, proto, endpoint, NULL, 0, NULL);
    if (!conn) {
        evpl_test_error("Failed to create RPC2 client");
        evpl_destroy(evpl);
        return -1;
    }

    /*
     * Queue a call, then immediately drop the connection -- before driving the
     * event loop, so the connect never completes and the call is never sent.
     * The call is in pending_calls, so the disconnect must error-complete it
     * rather than dropping it silently and hanging the caller forever.
     */
    request.id = 42;
    xdr_set_str_static(&request, greeting, "Hello from client!", strlen("Hello from client!"));
    prog.send_call_GREET(&prog.rpc2, evpl, conn, NULL, &request,
                         0, 0, NULL, 0, 0, client_recv_reply_first, &state);

    evpl_rpc2_client_disconnect(thread, conn);

    /* The pending call must be error-completed, and the re-entrant call issued
     * from inside that error callback must then complete against the real
     * (listening) server. */
    while (!state.reentrant_completed) {
        evpl_continue(evpl);
    }

    evpl_test_abort_if(!state.transport_error_seen, "transport error callback never fired");

    evpl_rpc2_server_stop(server);
    evpl_rpc2_server_detach(thread, server);
    evpl_rpc2_thread_destroy(thread);
    evpl_rpc2_server_destroy(server);
    evpl_destroy(evpl);

    printf("Test PASSED\n");
    return 0;
} /* main */
