// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Multi-fragment ONC RPC TCP record-mark reassembly test.
 *
 * libevpl's send path never fragments outbound replies, so a
 * libevpl-on-libevpl client cannot exercise the new code. This test
 * runs a libevpl HELLO_PROGRAM server on a pump thread and drives it
 * from the main thread with a hand-rolled TCP client that splits one
 * RPC CALL across multiple record-mark fragments.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <pthread.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

#include "evpl/evpl.h"
#include "evpl/evpl_rpc2.h"

#include "core/test_log.h"
#include "test_common.h"

#include "multifrag_xdr.h"

static enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
static int                   port  = 8000;

struct server_ctx {
    struct HELLO_V1 prog;
    volatile int    ready;
    volatile int    stop;
    volatile int    received_count;
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
    struct server_ctx  *ctx = private_data;
    struct Hello        reply;
    int                 rc;

    static const char   expect[]   = "Hello from client!";
    static const size_t expect_len = sizeof(expect) - 1;

    evpl_test_info("server: GREET id=%u greeting_len=%u",
                   call->id, call->greeting.len);

    /* xdr_string is {len, str} with no NUL guarantee on str. */
    evpl_test_abort_if(call->id != 42, "id mismatch (got %u)", call->id);
    evpl_test_abort_if(call->greeting.len != expect_len,
                       "greeting length mismatch (got %u)", call->greeting.len);
    evpl_test_abort_if(memcmp(call->greeting.str, expect, expect_len) != 0,
                       "greeting content mismatch");

    ctx->received_count++;

    reply.id = 100;
    xdr_set_str_static(&reply, greeting, "Hello from server!",
                       strlen("Hello from server!"));

    rc = ctx->prog.send_reply_GREET(evpl, NULL, &reply, encoding);
    evpl_test_abort_if(rc, "send_reply_GREET failed: %d", rc);
} /* server_recv_greet */

static void *
server_pump(void *arg)
{
    struct server_ctx        *ctx = arg;
    struct evpl              *evpl;
    struct evpl_rpc2_server  *server;
    struct evpl_rpc2_thread  *thread;
    struct evpl_endpoint     *endpoint;
    struct evpl_rpc2_program *programs[1];

    evpl = evpl_create(NULL);

    HELLO_V1_init(&ctx->prog);
    ctx->prog.recv_call_GREET = server_recv_greet;
    programs[0]               = &ctx->prog.rpc2;

    server   = evpl_rpc2_server_init(programs, 1);
    endpoint = evpl_endpoint_create("0.0.0.0", port);
    evpl_rpc2_server_start(server, proto, endpoint);

    thread = evpl_rpc2_thread_init(evpl, programs, 1, NULL, NULL);
    evpl_rpc2_server_attach(thread, server, ctx);

    ctx->ready = 1;

    while (!ctx->stop) {
        evpl_continue(evpl);
    }

    evpl_rpc2_server_stop(server);
    evpl_rpc2_server_detach(thread, server);
    evpl_rpc2_thread_destroy(thread);
    evpl_rpc2_server_destroy(server);
    evpl_destroy(evpl);
    return NULL;
} /* server_pump */

/*
 * Hand-marshal a HELLO_PROGRAM GREET CALL into a flat buffer (no
 * leading record mark; the caller writes the marks).
 *
 * Returns the number of bytes written. The buffer must have room for
 * at least 68 bytes.
 */
static int
build_greet_call(
    unsigned char *buf,
    uint32_t       xid)
{
    static const char msg[]   = "Hello from client!";
    const uint32_t    msg_len = (uint32_t) (sizeof(msg) - 1);
    uint32_t         *w       = (uint32_t *) buf;

    *w++ = htonl(xid);
    *w++ = htonl(0);        /* mtype = CALL */
    *w++ = htonl(2);        /* rpcvers */
    *w++ = htonl(42);       /* prog = HELLO_PROGRAM */
    *w++ = htonl(1);        /* vers = HELLO_V1 */
    *w++ = htonl(1);        /* proc = GREET */
    *w++ = htonl(0);        /* cred.flavor = AUTH_NONE */
    *w++ = htonl(0);        /* cred.length */
    *w++ = htonl(0);        /* verf.flavor */
    *w++ = htonl(0);        /* verf.length */
    *w++ = htonl(42);       /* args: Hello.id */
    *w++ = htonl(msg_len);  /* args: greeting length */

    unsigned char *p = (unsigned char *) w;
    memcpy(p, msg, msg_len);
    p += msg_len;
    while (((uintptr_t) p) & 3u) {
        *p++ = 0;
    }
    return (int) (p - buf);
} /* build_greet_call */

/*
 * Receive a GREET reply on the raw socket and validate it.
 */
static void
recv_and_validate_reply(
    int      sock,
    uint32_t expect_xid)
{
    unsigned char buf[256] = { 0 };
    uint32_t      mark;
    uint32_t      frag_len;
    ssize_t       got;
    size_t        off;
    uint32_t     *r;

    got = recv(sock, &mark, 4, MSG_WAITALL);
    evpl_test_abort_if(got != 4, "short mark read: %zd", got);
    mark     = ntohl(mark);
    frag_len = mark & 0x7FFFFFFFu;
    evpl_test_abort_if(!(mark & 0x80000000u), "reply not L=1");
    evpl_test_abort_if(frag_len < 28, "reply too small: %u", frag_len);
    evpl_test_abort_if(frag_len > sizeof(buf), "reply too big: %u", frag_len);

    off = 0;
    while (off < frag_len) {
        got = recv(sock, buf + off, frag_len - off, 0);
        evpl_test_abort_if(got <= 0, "recv body: %zd", got);
        off += (size_t) got;
    }

    r = (uint32_t *) buf;
    evpl_test_abort_if(ntohl(r[0]) != expect_xid, "xid mismatch: 0x%x", ntohl(r[0]));
    evpl_test_abort_if(ntohl(r[1]) != 1, "mtype != REPLY: %u", ntohl(r[1]));
    evpl_test_abort_if(ntohl(r[2]) != 0, "reply_stat != MSG_ACCEPTED: %u", ntohl(r[2]));
    /* r[3]=verf.flavor, r[4]=verf.length, r[5]=accept_stat */
    evpl_test_abort_if(ntohl(r[5]) != 0, "accept_stat != SUCCESS: %u", ntohl(r[5]));
    evpl_test_abort_if(ntohl(r[6]) != 100, "result id != 100: %u", ntohl(r[6]));
} /* recv_and_validate_reply */

static int
connect_client(void)
{
    int                sock;
    int                one = 1;
    struct sockaddr_in sa;

    sock = socket(AF_INET, SOCK_STREAM, 0);
    evpl_test_abort_if(sock < 0, "socket: %m");
    setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    memset(&sa, 0, sizeof(sa));
    sa.sin_family      = AF_INET;
    sa.sin_port        = htons(port);
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    evpl_test_abort_if(connect(sock, (struct sockaddr *) &sa, sizeof(sa)) < 0,
                       "connect: %m");
    return sock;
} /* connect_client */

static void
send_all(
    int         sock,
    const void *buf,
    size_t      len)
{
    const unsigned char *p = buf;

    while (len) {
        ssize_t w = send(sock, p, len, 0);
        evpl_test_abort_if(w <= 0, "send: %zd %m", w);
        p   += w;
        len -= (size_t) w;
    }
} /* send_all */

/*
 * Sub-test: split one CALL across n_splits fragments and verify a
 * successful reply.
 */
static void
test_fragmented_call(
    int      n_splits,
    uint32_t xid)
{
    unsigned char call[128];
    int           call_len = build_greet_call(call, xid);
    int           sock     = connect_client();
    int           i;
    int           sent = 0;

    evpl_test_info("test: %d fragments, call_len=%d xid=0x%x",
                   n_splits, call_len, xid);

    for (i = 0; i < n_splits; i++) {
        int      remaining = n_splits - i;
        int      this_len  = (call_len - sent) / remaining;
        int      is_last   = (i == n_splits - 1);
        uint32_t mark      = (uint32_t) this_len;

        if (is_last) {
            this_len = call_len - sent;
            mark     = (uint32_t) this_len | 0x80000000u;
        }
        mark = htonl(mark);
        send_all(sock, &mark, 4);
        send_all(sock, call + sent, (size_t) this_len);
        sent += this_len;
    }
    evpl_test_abort_if(sent != call_len, "send accounting %d != %d", sent, call_len);

    recv_and_validate_reply(sock, xid);
    close(sock);
} /* test_fragmented_call */

/*
 * Sub-test: send a single L=0 fragment then close, exercising the
 * mid-reassembly disconnect cleanup path (evpl_rpc2_reasm_reset).
 *
 * Does not validate anything directly; subsequent sub-tests must
 * still pass, which is what proves the server cleaned up.
 */
static void
test_abandoned_fragment(uint32_t xid)
{
    unsigned char call[128];
    int           call_len = build_greet_call(call, xid);
    int           sock     = connect_client();
    int           half     = call_len / 2;
    uint32_t      mark     = htonl((uint32_t) half);  /* L=0 */

    evpl_test_info("test: abandoned mid-fragment, half=%d", half);

    send_all(sock, &mark, 4);
    send_all(sock, call, (size_t) half);
    close(sock);  /* peer never sends the terminal fragment */
} /* test_abandoned_fragment */

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
    struct server_ctx ctx = { 0 };
    pthread_t         pump;
    int               opt, rc;
    int               i;

    test_evpl_config();

    while ((opt = getopt(argc, argv, "r:p:")) != -1) {
        switch (opt) {
            case 'r':
                rc = evpl_protocol_lookup(&proto, optarg);
                if (rc) {
                    fprintf(stderr, "invalid protocol '%s'\n", optarg);
                    return 1;
                }
                break;
            case 'p': port = atoi(optarg); break;
            default:  usage(argv[0]);
        } /* switch */
    }

    /* This test is TCP-specific: the bug only exists for the
     * stream-oriented framing path. RDMA bypasses rpc2_segment_callback. */
    if (proto != EVPL_STREAM_SOCKET_TCP) {
        evpl_test_info("multifrag is TCP-only; skipping under protocol %d", proto);
        return 0;
    }

    rc = pthread_create(&pump, NULL, server_pump, &ctx);
    evpl_test_abort_if(rc != 0, "pthread_create: %d", rc);

    while (!ctx.ready) {
        usleep(1000);
    }

    /* Sub-test 1: 3-way fragmented CALL. */
    test_fragmented_call(3, 0x11111111);

    /* Sub-test 2: 10 fragments — exercises accumulator growth past
     * the initial cap of EVPL_RPC2_REASM_INIT_CAP=8 entries. */
    test_fragmented_call(10, 0x22222222);

    /* Sub-test 3: disconnect mid-fragment, then prove the server
     * survives by completing another fragmented call. */
    test_abandoned_fragment(0x33333333);
    test_fragmented_call(4, 0x44444444);

    /* Verify the server actually handled the expected calls. */
    for (i = 0; i < 200 && ctx.received_count < 3; i++) {
        usleep(5000);
    }
    evpl_test_abort_if(ctx.received_count != 3,
                       "server processed %d calls, expected 3",
                       ctx.received_count);

    ctx.stop = 1;
    pthread_join(pump, NULL);

    printf("Test PASSED\n");
    return 0;
} /* main */
