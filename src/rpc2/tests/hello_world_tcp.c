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

#include "hello_world_tcp_xdr.h"

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

    evpl_info("Server received GREET request: id=%u, greeting='%s'",
              request->id, request->greeting.str);

    /* Validate request */
    assert(request->id == 42);
    assert(strcmp(request->greeting.str, "Hello from client!") == 0);

    state->server_received = 1;

    /* Prepare reply */
    reply.id = 100;
    xdr_set_str_static(&reply, greeting, "Hello from server!", strlen("Hello from server!"));

    /* Send reply */
    prog->send_reply_GREET(evpl, &reply, msg);

    evpl_info("Server sent GREET reply");
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

    evpl_info("Client received GREET reply: status=%d, id=%u, greeting='%s'",
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
        evpl_info("Test PASSED!");
    }
} /* client_recv_reply_greet */

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

    evpl_init(NULL);
    evpl = evpl_create(NULL);

    /* Initialize server program */
    HELLO_V1_init(&prog);
    prog.recv_call_GREET = server_recv_greet;
    programs[0]          = &prog.rpc2;

    /* Create RPC2 server */
    server = evpl_rpc2_server_init(programs, 1);

    /* Create endpoint for 0.0.0.0:8000 */
    endpoint = evpl_endpoint_create("0.0.0.0", 8000);

    /* Start listening */
    evpl_rpc2_server_start(server, EVPL_STREAM_SOCKET_TCP, endpoint);

    evpl_info("Server listening on port 8000");

    thread = evpl_rpc2_thread_init(evpl, programs, 1, NULL, NULL);

    /* Attach server to this thread */
    evpl_rpc2_server_attach(thread, server, &state);

    /* Connect to server */
    conn = evpl_rpc2_client_connect(thread, EVPL_STREAM_SOCKET_TCP, endpoint);

    if (!conn) {
        evpl_error("Failed to create RPC2 client");
        evpl_destroy(evpl);
        return -1;
    }

    evpl_info("Client connected to server");

    /* Prepare request */
    request.id = 42;
    xdr_set_str_static(&request, greeting, "Hello from client!", strlen("Hello from client!"));

    /* Make RPC call */
    evpl_info("Client sending GREET request");
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
