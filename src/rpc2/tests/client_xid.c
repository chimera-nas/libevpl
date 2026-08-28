// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * evpl_rpc2_conn_{get,set}_next_xid: the caller can observe, and choose, the
 * XID a client connection puts on its next call.
 *
 * Three things are asserted, in one connection's lifetime:
 *
 *   1. The XID the server sees is the one get_next_xid reported, and the
 *      counter advances by exactly one per call.
 *   2. Rewinding the counter reproduces a call on the wire byte for byte --
 *      the server sees the same XID a second time.  This is what a retransmit
 *      is, and what a duplicate-request cache keys on; without it a caller
 *      cannot exercise (or implement) one.
 *   3. Restoring the saved counter afterwards leaves the connection where it
 *      was, so a rewound call is an interlude and not a reset.
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

#include "client_xid_xdr.h"

static enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
static int                   port  = 8000;

#define MAX_SEEN 8

struct test_state {
    struct HELLO_V1 *prog;
    uint32_t         seen[MAX_SEEN];   /* XIDs the server was handed, in order */
    int              nseen;
    int              replies;
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

    evpl_test_abort_if(state->nseen >= MAX_SEEN, "too many calls");
    state->seen[state->nseen++] = encoding->xid;

    evpl_test_info("server saw call %d with xid %u", state->nseen, encoding->xid);

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
    struct test_state *state = callback_private_data;

    evpl_test_abort_if(status != 0, "call failed with status %d", status);
    state->replies++;
} /* client_recv_reply_greet */

/* One call, driven to completion, so the next assertion sees a settled
 * connection rather than a race with the reply. */
static void
call_and_wait(
    struct evpl           *evpl,
    struct HELLO_V1       *prog,
    struct evpl_rpc2_conn *conn,
    struct test_state     *state,
    uint32_t               id)
{
    struct Hello request;
    int          want = state->replies + 1;

    request.id = id;
    xdr_set_str_static(&request, greeting, "hi", 2);

    prog->send_call_GREET(&prog->rpc2, evpl, conn, NULL, &request, 0, 0, NULL,
                          0, 0, client_recv_reply_greet, state);

    while (state->replies < want) {
        evpl_continue(evpl);
    }
} /* call_and_wait */

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
    uint32_t                  first, second, saved, resumed;
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
    endpoint = evpl_endpoint_create(test_address(proto, "0.0.0.0", argv[0]), port);
    evpl_rpc2_server_start(server, proto, endpoint);

    thread = evpl_rpc2_thread_init(evpl, programs, 1, NULL, NULL);
    evpl_rpc2_server_attach(thread, server, &state);

    conn = evpl_rpc2_client_connect(thread, proto, endpoint, NULL, 0, NULL);

    if (!conn) {
        evpl_test_error("Failed to create RPC2 client");
        evpl_destroy(evpl);
        return -1;
    }

    /* 1. The reported XID is the one that goes on the wire, and the counter
     *    advances by one per call. */
    first = evpl_rpc2_conn_get_next_xid(conn);
    call_and_wait(evpl, &prog, conn, &state, 1);

    second = evpl_rpc2_conn_get_next_xid(conn);
    evpl_test_abort_if(second != first + 1,
                       "counter advanced to %u, expected %u", second, first + 1);

    call_and_wait(evpl, &prog, conn, &state, 2);

    saved = evpl_rpc2_conn_get_next_xid(conn);
    evpl_test_abort_if(saved != first + 2,
                       "counter advanced to %u, expected %u", saved, first + 2);

    evpl_test_abort_if(state.nseen != 2, "server saw %d calls, expected 2",
                       state.nseen);
    evpl_test_abort_if(state.seen[0] != first,
                       "server saw xid %u for call 1, expected %u",
                       state.seen[0], first);
    evpl_test_abort_if(state.seen[1] != second,
                       "server saw xid %u for call 2, expected %u",
                       state.seen[1], second);

    /* 2. Rewind and re-issue: a retransmit of call 1, carrying its XID. */
    evpl_rpc2_conn_set_next_xid(conn, first);
    evpl_test_abort_if(evpl_rpc2_conn_get_next_xid(conn) != first,
                       "set_next_xid did not take effect");

    call_and_wait(evpl, &prog, conn, &state, 1);

    evpl_test_abort_if(state.nseen != 3, "server saw %d calls, expected 3",
                       state.nseen);
    evpl_test_abort_if(state.seen[2] != first,
                       "retransmit carried xid %u, expected %u",
                       state.seen[2], first);

    /* 3. Restoring the saved counter resumes where the connection left off. */
    evpl_rpc2_conn_set_next_xid(conn, saved);
    call_and_wait(evpl, &prog, conn, &state, 3);

    resumed = evpl_rpc2_conn_get_next_xid(conn);
    evpl_test_abort_if(state.seen[3] != saved,
                       "resumed call carried xid %u, expected %u",
                       state.seen[3], saved);
    evpl_test_abort_if(resumed != saved + 1,
                       "counter resumed to %u, expected %u", resumed, saved + 1);

    evpl_rpc2_server_stop(server);
    evpl_rpc2_client_disconnect(thread, conn);
    evpl_rpc2_server_detach(thread, server);
    evpl_rpc2_thread_destroy(thread);
    evpl_rpc2_server_destroy(server);
    evpl_destroy(evpl);

    printf("Test PASSED\n");
    return 0;
} /* main */
