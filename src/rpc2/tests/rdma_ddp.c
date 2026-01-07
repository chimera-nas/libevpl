// SPDX-FileCopyrightText: 2025 Ben Jarvis
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

#include "rdma_ddp_xdr.h"

/* Default protocol and port */
static enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
static int                   port  = 8002;

/* Test data sizes */
#define READ_SIZE    4096
#define WRITE_SIZE   4096
#define REDUCE_SIZE  8192   /* Large enough to trigger reply chunk */

/* Test data buffer */
static char test_data[REDUCE_SIZE];

/* Static iovec for client WRITE request - needs to persist during async send */
static xdr_iovec write_req_iov;

/* Test state */
struct test_state {
    int read_done;
    int write_done;
    int reduce_done;
    int test_complete;
    int test_passed;
};

/* Initialize test data with pattern */
static void
init_test_data(void)
{
    int i;

    for (i = 0; i < REDUCE_SIZE; i++) {
        test_data[i] = (char) (i & 0xFF);
    }
}

/* Verify test data pattern */
static int
verify_data(const char *data, int offset, int length)
{
    int i;

    for (i = 0; i < length; i++) {
        if (data[i] != (char) ((offset + i) & 0xFF)) {
            evpl_test_error("Data mismatch at offset %d: expected %02x, got %02x",
                            offset + i, (offset + i) & 0xFF, (unsigned char) data[i]);
            return -1;
        }
    }
    return 0;
}

/* Server-side: Handle READ request */
void
server_recv_read(
    struct evpl             *evpl,
    struct evpl_rpc2_conn   *conn,
    struct ReadRequest      *request,
    struct evpl_rpc2_msg    *msg,
    void                    *private_data)
{
    struct RDMA_DDP_V1 *prog = msg->program->program_data;
    struct ReadResponse reply;
    xdr_iovec           iov;
    int                 rc;

    evpl_test_info("Server received READ request: offset=%llu, count=%u",
                   (unsigned long long) request->offset, request->count);

    /* Validate request */
    assert(request->offset == 0);
    assert(request->count == READ_SIZE);

    /* Allocate iovec for response data */
    evpl_iovec_alloc(evpl, READ_SIZE, 1, 1, &iov);
    memcpy(iov.data, test_data, READ_SIZE);
    iov.length = READ_SIZE;

    /* Prepare reply with test data */
    reply.count = READ_SIZE;
    reply.eof   = 1;
    xdr_set_ref(&reply, data, &iov, 1, READ_SIZE);

    /* Send reply */
    rc = prog->send_reply_READ(evpl, &reply, msg);

    if (unlikely(rc)) {
        evpl_test_error("Failed to send READ reply: %d", rc);
        exit(1);
    }

    evpl_test_info("Server sent READ reply: count=%u", reply.count);
}

/* Server-side: Handle WRITE request */
void
server_recv_write(
    struct evpl             *evpl,
    struct evpl_rpc2_conn   *conn,
    struct WriteRequest     *request,
    struct evpl_rpc2_msg    *msg,
    void                    *private_data)
{
    struct RDMA_DDP_V1  *prog = msg->program->program_data;
    struct WriteResponse reply;
    int                  rc, i;

    evpl_test_info("Server received WRITE request: offset=%llu, count=%u, data_len=%u",
                   (unsigned long long) request->offset, request->count,
                   request->data.length);

    /* Validate request */
    assert(request->offset == 0);
    assert(request->count == WRITE_SIZE);
    assert(request->data.length == WRITE_SIZE);
    assert(request->data.niov == 1);

    /* Verify the data */
    rc = verify_data(xdr_iovec_data(&request->data.iov[0]), 0, WRITE_SIZE);
    assert(rc == 0);

    /*
     * Release the request data iovecs in TCP mode only. In TCP mode, these
     * were cloned during unmarshalling. In RDMA mode (read_chunk.niov > 0),
     * the iovecs are from the read_chunk which RPC2's msg_free will release.
     */
    if (msg->read_chunk.niov == 0) {
        for (i = 0; i < request->data.niov; i++) {
            evpl_iovec_release(&request->data.iov[i]);
        }
    }

    /* Prepare reply */
    reply.count     = WRITE_SIZE;
    reply.committed = 1;

    /* Send reply */
    rc = prog->send_reply_WRITE(evpl, &reply, msg);

    if (unlikely(rc)) {
        evpl_test_error("Failed to send WRITE reply: %d", rc);
        exit(1);
    }

    evpl_test_info("Server sent WRITE reply: count=%u", reply.count);
}

/* Server-side: Handle REDUCE request */
void
server_recv_reduce(
    struct evpl             *evpl,
    struct evpl_rpc2_conn   *conn,
    struct ReduceRequest    *request,
    struct evpl_rpc2_msg    *msg,
    void                    *private_data)
{
    struct RDMA_DDP_V1   *prog = msg->program->program_data;
    struct ReduceResponse reply;
    int                   rc;

    evpl_test_info("Server received REDUCE request: response_size=%u",
                   request->response_size);

    /* Validate request */
    assert(request->response_size == REDUCE_SIZE);

    /* Prepare large reply to trigger reply chunk - use regular opaque */
    reply.data.data = test_data;
    reply.data.len  = REDUCE_SIZE;

    /* Send reply */
    rc = prog->send_reply_REDUCE(evpl, &reply, msg);

    if (unlikely(rc)) {
        evpl_test_error("Failed to send REDUCE reply: %d", rc);
        exit(1);
    }

    evpl_test_info("Server sent REDUCE reply: data_len=%u", REDUCE_SIZE);
}

/* Client-side: Handle READ reply */
void
client_recv_reply_read(
    struct evpl         *evpl,
    struct ReadResponse *reply,
    int                  status,
    void                *callback_private_data)
{
    struct test_state *state = callback_private_data;
    int                rc, i;

    evpl_test_info("Client received READ reply: status=%d, count=%u, eof=%d, data_len=%u",
                   status, reply->count, reply->eof, reply->data.length);

    /* Validate reply */
    assert(status == 0);
    assert(reply->count == READ_SIZE);
    assert(reply->eof == 1);
    assert(reply->data.length == READ_SIZE);
    assert(reply->data.niov == 1);

    /* Verify the data */
    rc = verify_data(xdr_iovec_data(&reply->data.iov[0]), 0, READ_SIZE);
    assert(rc == 0);

    /* Release the iovecs */
    for (i = 0; i < reply->data.niov; i++) {
        evpl_iovec_release(&reply->data.iov[i]);
    }

    state->read_done = 1;
    evpl_test_info("READ test PASSED!");

    /* Check if all tests complete */
    if (state->read_done && state->write_done && state->reduce_done) {
        state->test_complete = 1;
        state->test_passed   = 1;
    }
}

/* Client-side: Handle WRITE reply */
void
client_recv_reply_write(
    struct evpl          *evpl,
    struct WriteResponse *reply,
    int                   status,
    void                 *callback_private_data)
{
    struct test_state *state = callback_private_data;

    evpl_test_info("Client received WRITE reply: status=%d, count=%u, committed=%d",
                   status, reply->count, reply->committed);

    /* Validate reply */
    assert(status == 0);
    assert(reply->count == WRITE_SIZE);
    assert(reply->committed == 1);

    state->write_done = 1;
    evpl_test_info("WRITE test PASSED!");

    /* Check if all tests complete */
    if (state->read_done && state->write_done && state->reduce_done) {
        state->test_complete = 1;
        state->test_passed   = 1;
    }
}

/* Client-side: Handle REDUCE reply */
void
client_recv_reply_reduce(
    struct evpl           *evpl,
    struct ReduceResponse *reply,
    int                    status,
    void                  *callback_private_data)
{
    struct test_state *state = callback_private_data;
    int                rc;

    evpl_test_info("Client received REDUCE reply: status=%d, data_len=%u",
                   status, reply->data.len);

    /* Validate reply */
    assert(status == 0);
    assert(reply->data.len == REDUCE_SIZE);

    /* Verify the data - regular opaque uses .data and .len */
    rc = verify_data(reply->data.data, 0, REDUCE_SIZE);
    assert(rc == 0);

    /* No iovec release needed - regular opaque is managed by RPC2 */

    state->reduce_done = 1;
    evpl_test_info("REDUCE test PASSED!");

    /* Check if all tests complete */
    if (state->read_done && state->write_done && state->reduce_done) {
        state->test_complete = 1;
        state->test_passed   = 1;
    }
}

static void
usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s [-r protocol] [-p port]\n", prog_name);
    fprintf(stderr, "  -r protocol  Protocol to use (default: STREAM_SOCKET_TCP)\n");
    fprintf(stderr, "  -p port      Port to use (default: 8002)\n");
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
    struct RDMA_DDP_V1        prog;
    struct ReadRequest        read_req;
    struct WriteRequest       write_req;
    struct ReduceRequest      reduce_req;
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

    /* Initialize test data */
    init_test_data();

    evpl = evpl_create(NULL);

    /* Initialize server program */
    RDMA_DDP_V1_init(&prog);
    prog.recv_call_READ   = server_recv_read;
    prog.recv_call_WRITE  = server_recv_write;
    prog.recv_call_REDUCE = server_recv_reduce;
    programs[0]           = &prog.rpc2;

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

    /* Test 1: READ operation - uses reply chunk for DDP */
    evpl_test_info("Client sending READ request");
    read_req.offset = 0;
    read_req.count  = READ_SIZE;
    /* Enable DDP: ddp=1, no write chunk, reply chunk of READ_SIZE */
    prog.send_call_READ(&prog.rpc2, evpl, conn, &read_req, 1, 0, READ_SIZE,
                        client_recv_reply_read, &state);

    /* Test 2: WRITE operation - uses write chunk for DDP */
    evpl_test_info("Client sending WRITE request");
    write_req.offset = 0;
    write_req.count  = WRITE_SIZE;
    /* Allocate iovec for write data */
    evpl_iovec_alloc(evpl, WRITE_SIZE, 1, 1, &write_req_iov);
    memcpy(write_req_iov.data, test_data, WRITE_SIZE);
    write_req_iov.length = WRITE_SIZE;
    xdr_set_ref(&write_req, data, &write_req_iov, 1, WRITE_SIZE);
    /* Enable DDP: ddp=1, write chunk of WRITE_SIZE, no reply chunk */
    prog.send_call_WRITE(&prog.rpc2, evpl, conn, &write_req, 1, WRITE_SIZE, 0,
                         client_recv_reply_write, &state);

    /* Test 3: REDUCE operation - large reply to trigger reply chunk */
    evpl_test_info("Client sending REDUCE request");
    reduce_req.response_size = REDUCE_SIZE;
    /* Enable DDP: ddp=1, no write chunk, reply chunk of REDUCE_SIZE */
    prog.send_call_REDUCE(&prog.rpc2, evpl, conn, &reduce_req, 1, 0, REDUCE_SIZE,
                          client_recv_reply_reduce, &state);

    /* Wait for all replies */
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
}
