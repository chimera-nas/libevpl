// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Client-side RPCSEC_GSS: establish a context and make a call under it.
 *
 * Everything else in this suite exercises the acceptor -- the conformance
 * driver hand-builds GSS calls on a raw socket precisely because rpc2 could
 * not make them.  This drives the initiator instead, through the ordinary
 * generated client stub, so what it proves is that a caller can ask for
 * RPCSEC_GSS and have the library do the rest: the NULLPROC handshake, the
 * credential and sequence number on every call, and the verifier binding them
 * to the message.
 *
 * Both ends run in this process over the same evpl, which is what makes the
 * test hermetic: the acceptor is libevpl's own, the mechanism is real MIT
 * Kerberos with a ticket minted in-process (see krb5_local.c), and no KDC,
 * realm or keytab file exists anywhere.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>

#include "evpl/evpl.h"
#include "evpl/evpl_rpc2.h"
#include "evpl/evpl_rpc2_gss.h"

#include "core/test_log.h"
#include "test_common.h"

#include "krb5_local.h"
#include "hello_world_xdr.h"

static enum evpl_protocol_id proto = EVPL_STREAM_SOCKET_TCP;
static int                   port  = 8000;

struct test_state {
    struct HELLO_V1             *prog;
    struct evpl                 *evpl;
    struct evpl_rpc2_conn       *conn;
    struct evpl_rpc2_gss_client *gss;
    uint32_t                     service;
    int                          server_saw_gss;
    int                          complete;
    int                          passed;
    int                          after_destroy_fired;
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
    struct Hello       reply;

    /*
     * The point of the test: the acceptor must see an authenticated
     * RPCSEC_GSS caller, not AUTH_NONE.  A client that quietly fell back
     * would still get its echo, so checking the credential here is what makes
     * the difference observable.
     */
    if (cred && cred->flavor == EVPL_RPC2_AUTH_RPCSEC_GSS) {
        state->server_saw_gss = 1;
        evpl_test_info("server: call authenticated as '%s', service %u",
                       cred->gss.principal ? cred->gss.principal : "(none)",
                       cred->gss.service);
        evpl_test_abort_if(cred->gss.service != state->service,
                           "server saw service %u, client asked for %u",
                           cred->gss.service, state->service);
    } else {
        evpl_test_error("server: call was NOT RPCSEC_GSS (flavor %u)",
                        cred ? cred->flavor : 0);
    }

    reply.id = 100;
    xdr_set_str_static(&reply, greeting, "sealed hello", strlen("sealed hello"));

    evpl_test_abort_if(state->prog->send_reply_GREET(evpl, NULL, &reply,
                                                     encoding),
                       "server: failed to send reply");
} /* server_recv_greet */

static void
client_recv_reply(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct Hello                *reply,
    int                          status,
    void                        *private_data)
{
    struct test_state *state = private_data;

    if (status) {
        evpl_test_error("client: call failed, status %d", status);
        state->complete = 1;
        return;
    }

    evpl_test_abort_if(reply->id != 100, "reply id %u", reply->id);

    state->passed   = state->server_saw_gss;
    state->complete = 1;
} /* client_recv_reply */

/*
 * The second phase's completion.  What it reports is not interesting -- the
 * context it travelled under is gone by the time the reply lands, so an
 * unprotected reply to a context that no longer exists is the honest answer
 * either way.  What matters is that the call completes at all rather than
 * dereferencing the context that was freed underneath it.
 */
static void
client_recv_after_destroy(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct Hello                *reply,
    int                          status,
    void                        *private_data)
{
    struct test_state *state = private_data;

    evpl_test_info("client: in-flight call completed with status %d after the "
                   "context was retired", status);

    state->after_destroy_fired = 1;
} /* client_recv_after_destroy */

/* The context is ready (or was refused); either way the test moves on. */
static void
gss_ready(
    struct evpl_rpc2_gss_client *client,
    int                          status,
    void                        *private_data)
{
    struct test_state    *state = private_data;
    struct evpl_rpc2_cred cred;
    struct Hello          request;

    if (status || !client) {
        evpl_test_error("client: context establishment failed");
        state->complete = 1;
        return;
    }

    evpl_test_info("client: context established");
    state->gss = client;

    memset(&cred, 0, sizeof(cred));
    cred.flavor      = EVPL_RPC2_AUTH_RPCSEC_GSS;
    cred.gss.service = state->service;
    cred.gss.client  = client;

    request.id = 42;
    xdr_set_str_static(&request, greeting, "hello", strlen("hello"));

    state->prog->send_call_GREET(&state->prog->rpc2, state->evpl, state->conn,
                                 &cred, &request, 0, 0, NULL, 0, 0,
                                 client_recv_reply, state);
} /* gss_ready */

static void
usage(const char *p)
{
    fprintf(stderr, "usage: %s [-r proto] [-p port] [-s none|integrity|privacy]\n", p);
    exit(1);
} /* usage */

int
main(
    int    argc,
    char **argv)
{
    struct evpl              *evpl;
    struct evpl_rpc2_thread  *thread;
    struct evpl_rpc2_server  *server;
    struct evpl_endpoint     *endpoint;
    struct HELLO_V1           prog;
    struct evpl_rpc2_program *programs[1];
    struct test_state         state = { 0 };
    struct krb5_local        *kl;
    const char               *why = NULL;
    int                       opt;

    state.service = EVPL_RPC2_GSS_SVC_NONE;

    /* Before getopt, not after: evpl_protocol_lookup() brings the shared state
    * up on its own, and a configuration handed over after that is too late. */
    test_evpl_config();

    while ((opt = getopt(argc, argv, "r:p:s:")) != -1) {
        switch (opt) {
            case 'r':
                if (evpl_protocol_lookup(&proto, optarg)) {
                    fprintf(stderr, "unknown protocol '%s'\n", optarg);
                    return 1;
                }
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 's':
                if (!strcmp(optarg, "none")) {
                    state.service = EVPL_RPC2_GSS_SVC_NONE;
                } else if (!strcmp(optarg, "integrity")) {
                    state.service = EVPL_RPC2_GSS_SVC_INTEGRITY;
                } else if (!strcmp(optarg, "privacy")) {
                    state.service = EVPL_RPC2_GSS_SVC_PRIVACY;
                } else {
                    usage(argv[0]);
                }
                break;
            default:
                usage(argv[0]);
        } /* switch */
    }

    kl = krb5_local_create(&why);
    if (!kl) {
        /* No usable Kerberos on this host: skip rather than fail, matching how
         * the conformance suite treats the same absence. */
        evpl_test_info("skipping: %s", why ? why : "krb5 unavailable");
        return 77;
    }

    evpl = evpl_create(NULL);

    HELLO_V1_init(&prog);
    prog.recv_call_GREET = server_recv_greet;
    programs[0]          = &prog.rpc2;
    state.prog           = &prog;
    state.evpl           = evpl;

    server   = evpl_rpc2_server_init(programs, 1);
    endpoint = evpl_endpoint_create(test_address(proto, "0.0.0.0", argv[0]), port);

    evpl_rpc2_server_start(server, proto, endpoint);

    thread = evpl_rpc2_thread_init(evpl, programs, 1, NULL, NULL);

    /* The acceptor half: the same mechanism, so both ends of the handshake
     * are real even though neither leaves the process. */
    evpl_rpc2_set_gss_provider(thread, krb5_local_provider(),
                               krb5_local_arg(kl));

    evpl_rpc2_server_attach(thread, server, &state);

    state.conn = evpl_rpc2_client_connect(thread, proto, endpoint, NULL, 0, NULL);
    evpl_test_abort_if(!state.conn, "client connect failed");

    evpl_rpc2_gss_client_create(evpl, &prog.rpc2, state.conn,
                                krb5_local_initiator_provider(), kl,
                                state.service, "hello@localhost",
                                gss_ready, &state);

    while (!state.complete) {
        evpl_continue(evpl);
    }

    /*
     * Retiring a context with a call still outstanding.  A caller is entitled
     * to do this -- and evpl_rpc2_gss_client_destroy's own DESTROY is itself
     * such a call -- so the reply path must not be left holding a pointer to
     * the freed context.  Nothing here waits for the reply: the call is put on
     * the wire and the context pulled out from under it deliberately.
     */
    if (state.gss) {
        struct evpl_rpc2_cred cred;
        struct Hello          request;

        memset(&cred, 0, sizeof(cred));
        cred.flavor      = EVPL_RPC2_AUTH_RPCSEC_GSS;
        cred.gss.service = state.service;
        cred.gss.client  = state.gss;

        request.id = 43;
        xdr_set_str_static(&request, greeting, "bye", strlen("bye"));

        prog.send_call_GREET(&prog.rpc2, evpl, state.conn, &cred,
                             &request, 0, 0, NULL, 0, 0,
                             client_recv_after_destroy, &state);

        evpl_rpc2_gss_client_destroy(evpl, state.gss);
        state.gss = NULL;

        for (int i = 0; i < 20 && !state.after_destroy_fired; i++) {
            evpl_continue(evpl);
        }

        if (!state.after_destroy_fired) {
            evpl_test_error("the call outstanding across the retirement was "
                            "never completed");
            state.passed = 0;
        }
    }

    evpl_rpc2_server_stop(server);
    evpl_rpc2_client_disconnect(thread, state.conn);
    evpl_rpc2_server_detach(thread, server);
    evpl_rpc2_thread_destroy(thread);
    evpl_rpc2_server_destroy(server);
    krb5_local_destroy(kl);
    evpl_destroy(evpl);

    if (!state.passed) {
        evpl_test_error("client GSS call did not complete authenticated");
        return 1;
    }

    evpl_test_info("client GSS (service %u) OK", state.service);
    return 0;
} /* main */
