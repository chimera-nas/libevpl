// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
/*
 * The request-end hook fires exactly once, however a server request ends.
 *
 * A wrapper around the program's call dispatcher arms the hook on every call
 * before the generated dispatcher runs -- the same place a duplicate-request
 * cache arms it -- and then ends each call a different way:
 *
 *   1. answered with a reply;
 *   2. discarded with evpl_rpc2_discard_request;
 *   3. rejected before the handler ran: the wrapper returns 2, as a dispatcher
 *      that could not decode the arguments does, and rpc2 answers
 *      GARBAGE_ARGS itself;
 *   4. answered after the client disconnected: the reply is dropped, and the
 *      hook fires then -- not at the disconnect, while the call is still
 *      executing.
 *
 * Each case checks the count before and after the moment the request ends, so
 * firing early, late, twice or never all fail.
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

#include "server_request_end_xdr.h"

static enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
static int                   port  = 8000;

enum action {
    ACT_REPLY   = 0,
    ACT_DISCARD = 1,
    ACT_REJECT  = 2,
    ACT_HOLD    = 3,
};

struct test_state {
    struct HELLO_V1           *prog;
    int                        (*orig_dispatch)(
        struct evpl               *evpl,
        struct evpl_rpc2_conn     *conn,
        struct evpl_rpc2_encoding *encoding,
        uint32_t                   proc,
        void                      *program_data,
        struct evpl_rpc2_cred     *cred,
        xdr_iovec                 *iov,
        int                        niov,
        int                        length,
        void                      *private_data);
    enum action action;                    /* what to do with the next call */
    int                        ended;      /* request-end hook invocations */
    struct evpl_rpc2_encoding *held;
    int                        server_disconnects;
};

static struct test_state state;

struct call_ctx {
    int done;
    int status;
};

static void
request_end(void *private_data)
{
    struct test_state *s = private_data;

    s->ended++;
} /* request_end */

/* Arm the hook on every call, then either reject it here or hand it to the
 * generated dispatcher. */
static int
wrapped_dispatch(
    struct evpl               *evpl,
    struct evpl_rpc2_conn     *conn,
    struct evpl_rpc2_encoding *encoding,
    uint32_t                   proc,
    void                      *program_data,
    struct evpl_rpc2_cred     *cred,
    xdr_iovec                 *iov,
    int                        niov,
    int                        length,
    void                      *private_data)
{
    encoding->request_end_cb      = request_end;
    encoding->request_end_private = &state;

    if (state.action == ACT_REJECT) {
        return 2;   /* as if the arguments did not decode: GARBAGE_ARGS */
    }

    return state.orig_dispatch(evpl, conn, encoding, proc, program_data, cred,
                               iov, niov, length, private_data);
} /* wrapped_dispatch */

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
    int          rc;

    switch (state.action) {
        case ACT_DISCARD:
            evpl_rpc2_discard_request(evpl, encoding);
            return;
        case ACT_HOLD:
            state.held = encoding;
            return;
        default:
            break;
    } /* switch */

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
    if (notify->notify_type == EVPL_RPC2_NOTIFY_DISCONNECTED &&
        conn->server_binding) {
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
send_greet(
    struct evpl           *evpl,
    struct evpl_rpc2_conn *conn,
    uint32_t               id,
    struct call_ctx       *ctx)
{
    struct Hello request;

    memset(ctx, 0, sizeof(*ctx));
    request.id = id;
    xdr_set_str_static(&request, greeting, "hi", 2);
    state.prog->send_call_GREET(&state.prog->rpc2, evpl, conn, NULL, &request,
                                0, 0, NULL, 0, 0, client_recv_reply_greet, ctx);
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
    struct call_ctx           call, after;
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
    prog.recv_call_GREET         = server_recv_greet;
    state.prog                   = &prog;
    state.orig_dispatch          = prog.rpc2.recv_call_dispatch;
    prog.rpc2.recv_call_dispatch = wrapped_dispatch;
    programs[0]                  = &prog.rpc2;

    server   = evpl_rpc2_server_init(programs, 1);
    endpoint = evpl_endpoint_create(test_address(proto, "127.0.0.1", argv[0]), port);
    evpl_rpc2_server_start(server, proto, endpoint);

    thread = evpl_rpc2_thread_init(evpl, programs, 1, notify, &state);
    evpl_rpc2_server_attach(thread, server, &state);

    conn = evpl_rpc2_client_connect(thread, proto, endpoint, NULL, 0, NULL);
    evpl_test_abort_if(!conn, "Failed to create RPC2 client");

    /* 1. Answered. */
    state.action = ACT_REPLY;
    send_greet(evpl, conn, 1, &call);
    while (!call.done) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if(call.status != 0, "answered call failed: %d", call.status);
    evpl_test_abort_if(state.ended != 1, "after a reply the hook fired %d times, "
                       "expected 1", state.ended);

    /* 2. Discarded.  The client gets nothing; the hook fires when the server
     *    discards, which happens while it handles the call. */
    state.action = ACT_DISCARD;
    send_greet(evpl, conn, 2, &call);
    while (state.ended < 2) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if(call.done, "the discarded call was answered");
    evpl_test_abort_if(state.ended != 2, "after a discard the hook fired %d "
                       "times in all, expected 2", state.ended);

    /* 3. Rejected before the handler ran; rpc2 answers GARBAGE_ARGS. */
    state.action = ACT_REJECT;
    send_greet(evpl, conn, 3, &after);
    while (!after.done) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if(after.status == 0, "the rejected call got a success reply");
    evpl_test_abort_if(state.ended != 3, "after a rejection the hook fired %d "
                       "times in all, expected 3", state.ended);

    /* 4. Held; the client goes away; the server answers late. */
    state.action = ACT_HOLD;
    send_greet(evpl, conn, 4, &after);
    while (!state.held) {
        evpl_continue(evpl);
    }
    evpl_rpc2_client_disconnect(thread, conn);
    while (state.server_disconnects < 1 || !call.done || !after.done) {
        evpl_continue(evpl);
    }
    evpl_test_abort_if(state.ended != 3, "the hook fired at the disconnect, "
                       "while the call was still executing (%d)", state.ended);

    reply.id = 4;
    xdr_set_str_static(&reply, greeting, "late", 4);
    rc = prog.send_reply_GREET(evpl, NULL, &reply, state.held);
    evpl_test_abort_if(rc, "late send_reply_GREET failed: %d", rc);
    state.held = NULL;
    evpl_test_abort_if(state.ended != 4, "after the late reply the hook fired "
                       "%d times in all, expected 4", state.ended);

    evpl_rpc2_server_stop(server);
    evpl_rpc2_server_detach(thread, server);
    evpl_rpc2_thread_destroy(thread);
    evpl_rpc2_server_destroy(server);
    evpl_destroy(evpl);

    printf("Test PASSED\n");
    return 0;
} /* main */
