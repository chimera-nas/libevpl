// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
/*
 * A client disconnects while the server is still reading the call chunks of
 * the requests it sent.
 *
 * Every request the server took ends exactly once.  A request the server
 * dispatched ends through its request-end hook, whether the server replies to
 * it after the disconnect or discards it.  A request whose chunk read the
 * disconnect cut short is never dispatched and ends inside rpc2; the evidence
 * is that its connection, which the last request to end frees, is freed.  In
 * a sanitizer build LeakSanitizer reports the connection otherwise.  In any
 * build rpc2 aborts at the disconnect if a request is still waiting on a
 * read, which happens only if the read-completion guarantees (Tasks 1 and 2)
 * regress.
 *
 * Over the RDMA CM how many reads the disconnect cuts short depends on timing:
 * in some runs the server dispatches every call first.  With -c the scenario
 * therefore repeats on a fresh connection, up to MAX_ROUNDS times, until a
 * round both cuts a read short and sends a reply after the disconnect (the
 * held call is answered into the closed connection); every round passes the
 * checks above.
 *
 * The test counts the replies the server sends after the held call has
 * disconnected the client; rpc2 must drop each of them.  -c requires at
 * least one such reply, and that the disconnect cut at least one read short.
 * Over the RDMA CM the repeated rounds make both a read cut short and a
 * dropped reply hold with high probability, and with -c the test fails if
 * none of the MAX_ROUNDS rounds met both.  The other runs require neither:
 * the TCP instance cannot prove the hazard, so for it the counts are only
 * reported.
 * -a names the address; it defaults to EVPL_TEST_RDMA_IP, else 127.0.0.1.
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

#include "server_read_disconnect_xdr.h"

#define NUM_CALLS        32
#define CHUNK_SIZE       (256 * 1024)

static enum evpl_protocol_id proto = EVPL_DATAGRAM_TCP_RDMA;
static int                   port  = 8206;

#define MAX_ROUNDS       20
#define SETTLE_MIN_TICKS 5
#define SETTLE_MAX_TICKS 500

struct test_state {
    struct RDMA_DDP_V1        *prog;
    struct evpl_rpc2_thread   *thread;
    struct evpl_rpc2_conn     *client;
    struct evpl_rpc2_encoding *held;
    struct evpl_timer          settle;
    int                        dispatched;
    int                        was_dispatched[NUM_CALLS];
    int                        ended[NUM_CALLS];
    int                        dropped_replies;
    int                        settled;
    int                        client_connected;
    int                        server_disconnects;
    int                        client_disconnects;
};

struct call_ctx {
    int done;
    int status;
};

static void
request_end(void *private_data)
{
    int *ended = private_data;

    (*ended)++;
} /* request_end */

static void
server_recv_write(
    struct evpl               *evpl,
    struct evpl_rpc2_conn     *conn,
    struct evpl_rpc2_cred     *cred,
    struct WriteRequest       *call,
    struct evpl_rpc2_encoding *encoding,
    void                      *private_data)
{
    struct test_state   *state = private_data;
    struct WriteResponse reply;
    uint64_t             index = call->offset;
    int                  i, rc;

    (void) conn;
    (void) cred;

    evpl_test_abort_if(index >= NUM_CALLS, "call carried index %llu",
                       (unsigned long long) index);
    evpl_test_abort_if(state->was_dispatched[index], "call %llu dispatched twice",
                       (unsigned long long) index);
    state->was_dispatched[index] = 1;
    state->dispatched++;

    encoding->request_end_cb      = request_end;
    encoding->request_end_private = &state->ended[index];

    evpl_rpc2_encoding_take_read_chunk(encoding, NULL, NULL);
    for (i = 0; i < call->data.niov; i++) {
        evpl_iovec_release(evpl, &call->data.iov[i]);
    }

    /* The first call to arrive holds, and the client goes away while the
     * server is still reading the others. */
    if (!state->held) {
        state->held = encoding;
        evpl_rpc2_client_disconnect(state->thread, state->client);
        state->client = NULL;
        return;
    }

    /* Calls whose reads finish after that are answered into a connection
     * that is closing or closed; the reply is dropped. */
    state->dropped_replies++;
    reply.count     = call->count;
    reply.committed = 1;
    rc              = state->prog->send_reply_WRITE(evpl, NULL, &reply, encoding);
    evpl_test_abort_if(rc, "send_reply_WRITE failed: %d", rc);
} /* server_recv_write */

static void
notify(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_conn   *conn,
    struct evpl_rpc2_notify *notify,
    void                    *private_data)
{
    struct test_state *state = private_data;

    (void) thread;

    if (notify->notify_type == EVPL_RPC2_NOTIFY_CONNECTED) {
        if (!conn->server_binding) {
            state->client_connected = 1;
        }
        return;
    }

    if (notify->notify_type != EVPL_RPC2_NOTIFY_DISCONNECTED) {
        return;
    }

    if (conn->server_binding) {
        state->server_disconnects++;
    } else {
        state->client_disconnects++;
    }
} /* notify */

static void
client_recv_reply_write(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct WriteResponse        *reply,
    int                          status,
    void                        *callback_private_data)
{
    struct call_ctx *ctx = callback_private_data;

    (void) evpl;
    (void) verf;
    (void) reply;

    evpl_test_abort_if(ctx->done, "a call completed twice");
    ctx->done   = 1;
    ctx->status = status;
} /* client_recv_reply_write */

static void
settle_timer_cb(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    struct test_state *state = container_of(timer, struct test_state, settle);

    (void) evpl;
    state->settled++;
} /* settle_timer_cb */

static void
usage(const char *prog_name)
{
    fprintf(stderr, "Usage: %s [-r protocol] [-p port] [-a address] [-c]\n", prog_name);
    exit(1);
} /* usage */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl              *evpl;
    struct evpl_rpc2_server  *server;
    struct evpl_endpoint     *endpoint;
    struct RDMA_DDP_V1        prog;
    struct evpl_rpc2_program *programs[1];
    struct test_state         state = { 0 };
    struct evpl_rpc2_thread  *thread;
    struct call_ctx           calls[NUM_CALLS];
    struct WriteRequest       request;
    xdr_iovec                 iov;
    const char               *address = getenv("EVPL_TEST_RDMA_IP");
    int                       opt, rc, i, done, ended_once, cut = 0, require_cut = 0;
    int                       round, max_rounds;

    test_evpl_config();

    if (!address) {
        address = "127.0.0.1";
    }

    while ((opt = getopt(argc, argv, "r:p:a:c")) != -1) {
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
            case 'a':
                address = optarg;
                break;
            case 'c':
                require_cut = 1;
                break;
            default:
                usage(argv[0]);
        } /* switch */
    }

    evpl = evpl_create(NULL);

    RDMA_DDP_V1_init(&prog);
    prog.recv_call_WRITE = server_recv_write;
    programs[0]          = &prog.rpc2;
    state.prog           = &prog;

    server   = evpl_rpc2_server_init(programs, 1);
    endpoint = evpl_endpoint_create(test_address(proto, address, argv[0]), port);
    evpl_test_abort_if(evpl_rpc2_server_start(server, proto, endpoint),
                       "server start failed");

    state.thread = evpl_rpc2_thread_init(evpl, programs, 1, notify, &state);
    thread       = state.thread;
    evpl_rpc2_server_attach(state.thread, server, &state);

    max_rounds = require_cut ? MAX_ROUNDS : 1;

    for (round = 1; round <= max_rounds; round++) {
        /* Each round starts from clean per-round state on a fresh connection. */
        memset(&state, 0, sizeof(state));
        state.prog   = &prog;
        state.thread = thread;
        cut          = 0;

        state.client = evpl_rpc2_client_connect(state.thread, proto, endpoint, NULL, 0, NULL);
        evpl_test_abort_if(!state.client, "connect failed");

        /* Over the RDMA CM a call may not be issued until the bind is connected. */
        while (!state.client_connected) {
            evpl_continue(evpl);
        }

        memset(calls, 0, sizeof(calls));
        for (i = 0; i < NUM_CALLS; i++) {
            rc = evpl_iovec_alloc(evpl, CHUNK_SIZE, 4096, 1, 0, &iov);
            evpl_test_abort_if(rc != 1, "allocation failed");
            memset(iov.data, i, CHUNK_SIZE);
            iov.length     = CHUNK_SIZE;
            request.offset = i;
            request.count  = CHUNK_SIZE;
            xdr_set_ref(&request, data, &iov, 1, CHUNK_SIZE);
            /* ddp=1: the data travels as a read chunk the server reads.  The call
             * takes the iovec; the test does not release it. */
            prog.send_call_WRITE(&prog.rpc2, evpl, state.client, NULL, &request, 1, 0,
                                 NULL, 0, 0, client_recv_reply_write, &calls[i]);
        }

        for (;;) {
            for (done = 0, i = 0; i < NUM_CALLS; i++) {
                done += calls[i].done;
            }
            if (done == NUM_CALLS && state.server_disconnects == 1 &&
                state.client_disconnects == 1) {
                break;
            }
            evpl_continue(evpl);
        }

        evpl_test_abort_if(!state.held, "no call was dispatched");
        evpl_rpc2_discard_request(evpl, state.held);
        state.held = NULL;

        /* evpl_continue blocks until there is an event or a timer, so a periodic
        * 10 ms timer bounds each wait.  Every call is accounted for once each
        * dispatched call has ended; a call that was not dispatched was cut short
        * and has nothing further to do.  Keep running for a few ticks past that
        * so a late spurious request-end hook is seen, and give up after 5 s so a
        * hang cannot occur: the assertions below then report what is missing. */
        evpl_add_timer(evpl, &state.settle, settle_timer_cb, 10000);
        for (;;) {
            for (ended_once = 0, i = 0; i < NUM_CALLS; i++) {
                ended_once += state.was_dispatched[i] && state.ended[i] == 1;
            }
            if (state.settled >= SETTLE_MAX_TICKS ||
                (state.settled >= SETTLE_MIN_TICKS && ended_once == state.dispatched)) {
                break;
            }
            evpl_continue(evpl);
        }
        evpl_remove_timer(evpl, &state.settle);

        for (i = 0; i < NUM_CALLS; i++) {
            if (state.was_dispatched[i]) {
                evpl_test_abort_if(state.ended[i] != 1,
                                   "dispatched call %d ended %d times, expected once",
                                   i, state.ended[i]);
            } else {
                evpl_test_abort_if(state.ended[i] != 0,
                                   "undispatched call %d fired its request-end hook", i);
                cut++;
            }
        }

        evpl_test_info("round %d of at most %d: %d of %d calls dispatched, "
                       "%d cut short by the disconnect, "
                       "%d replies sent after the disconnect",
                       round, max_rounds, state.dispatched, NUM_CALLS, cut,
                       state.dropped_replies);
        /* With -c a round counts only if it cut a read short and the drop ran. */
        if (cut && (!require_cut || state.dropped_replies > 0)) {
            break;
        }
    }

    if (round > max_rounds) {
        round = max_rounds;
    }
    evpl_test_info("rounds used: %d", round);
    evpl_test_abort_if(require_cut && state.dropped_replies == 0,
                       "no reply was sent after the disconnect; the drop never ran "
                       "(after %d rounds)", round);
    evpl_test_abort_if(require_cut && cut == 0,
                       "the disconnect cut no read short; the test proved nothing "
                       "(after %d rounds)", round);

    evpl_rpc2_server_stop(server);
    evpl_rpc2_server_detach(state.thread, server);
    evpl_rpc2_thread_destroy(state.thread);
    evpl_rpc2_server_destroy(server);
    evpl_destroy(evpl);

    printf("Test PASSED\n");
    return 0;
} /* main */
