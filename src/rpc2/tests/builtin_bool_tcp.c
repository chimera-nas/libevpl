// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <assert.h>
#include <unistd.h>

#include "evpl/evpl.h"
#include "evpl/evpl_rpc2.h"

#include "builtin_bool_tcp_xdr.h"

/* RPC2 logging macros */
#define evpl_info(fmt, ...)  printf("[INFO] " fmt "\n", ## __VA_ARGS__)
#define evpl_error(fmt, ...) fprintf(stderr, "[ERROR] " fmt "\n", ## __VA_ARGS__)

/* Test state shared between client and server */
struct test_state {
    int server_received;
    int client_received;
    int test_complete;
    int test_passed;
};

/* Server-side: Handle PING request */
void
server_recv_ping(
    struct evpl           *evpl,
    struct evpl_rpc2_conn *conn,
    xdr_bool              *request,
    struct evpl_rpc2_msg  *msg,
    void                  *private_data)
{
    struct test_state      *state = private_data;
    struct BUILTIN_BOOL_V1 *prog  = msg->program->program_data;
    xdr_bool                reply;
    int                     rc;

    evpl_info("Server received PING request: value=%s", *request ? "true" : "false");

    /* Validate request */
    assert(*request == 1);

    state->server_received = 1;

    /* Prepare reply */
    reply = 1;

    /* Send reply */
    rc = prog->send_reply_PING(evpl, &reply, msg);

    if (unlikely(rc)) {
        fprintf(stderr, "Failed to send reply for PING: %d\n", rc);
        exit(1);
    }

    evpl_info("Server sent PING reply");
} /* server_recv_ping */

/* Client-side: Handle PING reply */
void
client_recv_reply_ping(
    struct evpl *evpl,
    xdr_bool    *reply,
    int          status,
    void        *callback_private_data)
{
    struct test_state *state = callback_private_data;

    evpl_info("Client received PING reply: status=%d, value=%s",
              status, *reply ? "true" : "false");

    /* Validate reply */
    assert(status == 0);  /* SUCCESS */
    assert(*reply == 1);

    state->client_received = 1;

    /* Test complete */
    if (state->server_received && state->client_received) {
        state->test_complete = 1;
        state->test_passed   = 1;
        evpl_info("Test PASSED!");
    }
} /* client_recv_reply_ping */

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
    struct BUILTIN_BOOL_V1    prog;
    xdr_bool                  request;
    struct evpl_rpc2_program *programs[1];
    struct test_state         state = { 0 };

    evpl_init(NULL);
    evpl = evpl_create(NULL);

    /* Initialize server program */
    BUILTIN_BOOL_V1_init(&prog);
    prog.recv_call_PING = server_recv_ping;
    programs[0]         = &prog.rpc2;

    /* Create RPC2 server */
    server = evpl_rpc2_server_init(programs, 1);

    /* Create endpoint for 0.0.0.0:8001 */
    endpoint = evpl_endpoint_create("0.0.0.0", 8001);

    /* Start listening */
    evpl_rpc2_server_start(server, EVPL_STREAM_SOCKET_TCP, endpoint);

    evpl_info("Server listening on port 8001");

    thread = evpl_rpc2_thread_init(evpl, programs, 1, NULL, NULL);

    /* Attach server to this thread */
    evpl_rpc2_server_attach(thread, server, &state);

    /* Connect to server */
    conn = evpl_rpc2_client_connect(thread, EVPL_STREAM_SOCKET_TCP, endpoint, NULL, 0, NULL);

    if (!conn) {
        evpl_error("Failed to create RPC2 client");
        evpl_destroy(evpl);
        return -1;
    }

    evpl_info("Client connected to server");

    /* Prepare request */
    request = 1;

    /* Make RPC call */
    evpl_info("Client sending PING request");
    prog.send_call_PING(&prog.rpc2, evpl, conn, &request, 0, 0, 0, client_recv_reply_ping, &state);

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
