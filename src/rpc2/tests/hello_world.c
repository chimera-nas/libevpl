// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <assert.h>
#include <unistd.h>
#include <getopt.h>

#include "evpl/evpl.h"
#include "evpl/evpl_rpc2.h"

#include "core/test_log.h"
#include "test_common.h"

#include "hello_world_xdr.h"

/* Default protocol and port */
static enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
static int                   port  = 8000;

/* Test state shared between client and server */
struct test_state {
    int server_received;
    int client_received;
    int test_complete;
    int test_passed;
};

/* Server-side: Handle GREET request */
void
server_recv_greet(
    struct evpl           *evpl,
    struct evpl_rpc2_conn *conn,
    struct Hello          *request,
    struct evpl_rpc2_msg  *msg,
    void                  *private_data)
{
    struct test_state *state = private_data;
    struct HELLO_V1   *prog  = msg->program->program_data;
    struct Hello       reply;
    int                rc;

    evpl_test_info("Server received GREET request: id=%u, greeting='%s'",
                   request->id, request->greeting.str);

    /* Validate request */
    assert(request->id == 42);
    assert(strcmp(request->greeting.str, "Hello from client!") == 0);

    state->server_received = 1;

    /* Prepare reply */
    reply.id = 100;
    xdr_set_str_static(&reply, greeting, "Hello from server!", strlen("Hello from server!"));

    /* Send reply */
    rc = prog->send_reply_GREET(evpl, &reply, msg);

    if (unlikely(rc)) {
        fprintf(stderr, "Failed to send reply for GREET: %d\n", rc);
        exit(1);
    }

    evpl_test_info("Server sent GREET reply");
} /* server_recv_greet */

/* Client-side: Handle GREET reply */
void
client_recv_reply_greet(
    struct evpl  *evpl,
    struct Hello *reply,
    int           status,
    void         *callback_private_data)
{
    struct test_state *state = callback_private_data;

    evpl_test_info("Client received GREET reply: status=%d, id=%u, greeting='%s'",
                   status, reply->id, reply->greeting.str);

    /* Validate reply */
    assert(status == 0);  /* SUCCESS */
    assert(reply->id == 100);
    assert(strcmp(reply->greeting.str, "Hello from server!") == 0);

    state->client_received = 1;

    /* Test complete */
    if (state->server_received && state->client_received) {
        state->test_complete = 1;
        state->test_passed   = 1;
        evpl_test_info("Test PASSED!");
    }
} /* client_recv_reply_greet */

static void
usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s [-r protocol] [-p port]\n", prog_name);
    fprintf(stderr, "  -r protocol  Protocol to use (default: STREAM_SOCKET_TCP)\n");
    fprintf(stderr, "  -p port      Port to use (default: 8000)\n");
    exit(1);
}

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

    /* Initialize evpl first, before any evpl functions are called */
    test_evpl_config();

    /* Parse command line arguments */
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
        }
    }

    evpl = evpl_create(NULL);

    /* Initialize server program */
    HELLO_V1_init(&prog);
    prog.recv_call_GREET = server_recv_greet;
    programs[0]          = &prog.rpc2;

    /* Create RPC2 server */
    server = evpl_rpc2_server_init(programs, 1);

    /* Create endpoint */
    endpoint = evpl_endpoint_create("0.0.0.0", port);

    /* Start listening */
    evpl_rpc2_server_start(server, proto, endpoint);

    evpl_test_info("Server listening on port %d with protocol %d", port, proto);

    thread = evpl_rpc2_thread_init(evpl, programs, 1, NULL, NULL);

    /* Attach server to this thread */
    evpl_rpc2_server_attach(thread, server, &state);

    /* Connect to server */
    conn = evpl_rpc2_client_connect(thread, proto, endpoint, NULL, 0, NULL);

    if (!conn) {
        evpl_test_error("Failed to create RPC2 client");
        evpl_destroy(evpl);
        return -1;
    }

    evpl_test_info("Client connected to server");

    /* Prepare request */
    request.id = 42;
    xdr_set_str_static(&request, greeting, "Hello from client!", strlen("Hello from client!"));

    /* Make RPC call */
    evpl_test_info("Client sending GREET request");
    prog.send_call_GREET(&prog.rpc2, evpl, conn, &request, 0, 0, 0, client_recv_reply_greet, &state);

    /* Wait for reply */
    while (!state.test_complete) {
        evpl_continue(evpl);
    }
    /* Cleanup */
    evpl_rpc2_server_stop(server);
    evpl_rpc2_client_disconnect(thread, conn);
    evpl_rpc2_server_detach(thread, server);
    evpl_rpc2_thread_destroy(thread);
    evpl_rpc2_server_destroy(server);
    evpl_destroy(evpl);

    if (state.test_passed) {
        printf("Test PASSED\n");
        return 0;
    } else {
        printf("Test FAILED\n");
        return 1;
    }
} /* main */
