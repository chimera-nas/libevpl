// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * In-process endpoint construction, protocol pairing, name registration and
 * address rendering.
 *
 * The integration tests cover the data path; what they cannot reach is the
 * error behaviour around the registry -- a name already in use, a name nobody
 * is listening on, a protocol and endpoint that do not agree -- each of which
 * has to be reported rather than being fatal.
 *
 * Note the fixed names below.  The registry behind them is private to the
 * process, so two concurrent copies of this test cannot collide however they
 * are scheduled; that is the property that lets these run with no namespace
 * and no lock.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "evpl/evpl.h"

static int        failures;
static char       server_local[EVPL_ADDRESS_STRLEN];
static char       server_remote[EVPL_ADDRESS_STRLEN];
static char       server_local_trunc[8];
static int        conn_count;
static int        client_disconnects;

static const char shared_payload[] = "sent by reference, not by copy";
static char       server_data[sizeof(shared_payload)];
static int        server_bytes;

#define CHECK(cond, ...) \
        do { \
            if (!(cond)) { \
                printf("FAIL: " __VA_ARGS__); printf("\n"); failures++; \
            } else { \
                printf("ok:   " __VA_ARGS__); printf("\n"); \
            } \
        } while (0)

static void
server_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    if (notify->notify_type == EVPL_NOTIFY_RECV_DATA) {
        server_bytes = evpl_recv(evpl, bind, server_data, sizeof(server_data),
                                 EVPL_RECV_FLAG_ALL_OR_NONE);
        return;
    }

    if (notify->notify_type != EVPL_NOTIFY_CONNECTED) {
        return;
    }

    evpl_bind_get_local_address(bind, server_local, sizeof(server_local));
    evpl_bind_get_remote_address(bind, server_remote, sizeof(server_remote));

    /* The listener's name is longer than 8 bytes, so this is a genuine
     * truncation and must still land NUL terminated. */
    evpl_bind_get_local_address(bind, server_local_trunc,
                                sizeof(server_local_trunc));

    conn_count++;
} /* server_callback */

static void
accept_callback(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    *notify_callback = server_callback;
} /* accept_callback */

static void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    if (notify->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        client_disconnects++;
    }
} /* client_callback */

/* evpl_continue() blocks until something happens -- wait_ms defaults to -1 --
 * so only ever pump waiting for an event that is genuinely on its way. */
static void
wait_for_conns(
    struct evpl *evpl,
    int          target)
{
    while (conn_count < target) {
        evpl_continue(evpl);
    }
} /* wait_for_conns */

static void
wait_for_disconnects(
    struct evpl *evpl,
    int          target)
{
    while (client_disconnects < target) {
        evpl_continue(evpl);
    }
} /* wait_for_disconnects */

static void
wait_for_bytes(struct evpl *evpl)
{
    while (server_bytes == 0) {
        evpl_continue(evpl);
    }
} /* wait_for_bytes */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl                  *evpl;
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    struct evpl_endpoint         *ep, *inet_ep, *local_ep, *absent_ep;
    struct evpl_bind             *conn;
    struct evpl_iovec             iov;
    enum evpl_protocol_id         proto;
    char                          name[160];
    char                          expect[EVPL_ADDRESS_STRLEN];
    char                          sockpath[96];
    const char                   *dir;
    int                           rc;

    evpl_init(NULL);

    /* Scoped to this build tree and this process even though the endpoint
     * below is never bound: concurrent runs share the machine, so a socket
     * name that is not unique per run is a conflict waiting to happen the
     * moment someone binds it. */
    dir = getenv("EVPL_TEST_SOCKET_DIR");

    if (!dir || dir[0] != '/') {
        dir = "/tmp";
    }

    snprintf(sockpath, sizeof(sockpath), "%s/evpl-endpoint-inproc-%d.sock",
             dir, (int) getpid());

    /* --- rejected forms --- */
    CHECK(evpl_endpoint_create_inproc(NULL) == NULL, "NULL name rejected");
    CHECK(evpl_endpoint_create_inproc("") == NULL, "empty name rejected");
    CHECK(evpl_endpoint_create("inproc://", 0) == NULL,
          "bare 'inproc://' rejected");

    /* The name is stored NUL terminated in a 108 byte field, so 107 is the
     * longest that fits and 108 must be refused rather than truncated into a
     * different name. */
    memset(name, 'x', sizeof(name));
    name[108] = '\0';
    CHECK(evpl_endpoint_create_inproc(name) == NULL, "108-byte name rejected");

    name[107] = '\0';
    ep        = evpl_endpoint_create_inproc(name);
    CHECK(ep != NULL, "107-byte name accepted");
    if (ep) {
        evpl_endpoint_close(ep);
    }

    /* --- kinds are distinguished --- */
    ep = evpl_endpoint_create("inproc://endpoint-inproc", 0);
    CHECK(ep && evpl_endpoint_is_inproc(ep),
          "create('inproc://name') detects in-process");
    CHECK(ep && !evpl_endpoint_is_local(ep), "an inproc endpoint is not local");

    inet_ep = evpl_endpoint_create("127.0.0.1", 8299);
    CHECK(inet_ep && !evpl_endpoint_is_inproc(inet_ep),
          "create('127.0.0.1') stays inet");

    /* A pathname rather than an abstract name: this only has to be some local
     * endpoint that is not inproc, so there is no reason to reach for the one
     * form of it that is Linux-only. */
    local_ep = evpl_endpoint_create_local(sockpath);
    CHECK(local_ep && !evpl_endpoint_is_inproc(local_ep),
          "an AF_UNIX endpoint is not in-process");

    CHECK(strcmp(evpl_endpoint_address(ep), "inproc://endpoint-inproc") == 0,
          "endpoint address round-trips as '%s'", evpl_endpoint_address(ep));

    /* --- protocol predicates --- */
    CHECK(evpl_protocol_available(EVPL_STREAM_INPROC) == 1,
          "STREAM_INPROC available");
    CHECK(evpl_protocol_available(EVPL_DATAGRAM_INPROC) == 1,
          "DATAGRAM_INPROC available");
    CHECK(evpl_protocol_is_inproc(EVPL_STREAM_INPROC) == 1,
          "STREAM_INPROC is in-process");
    CHECK(evpl_protocol_is_inproc(EVPL_DATAGRAM_INPROC) == 1,
          "DATAGRAM_INPROC is in-process");
    CHECK(evpl_protocol_is_inproc(EVPL_STREAM_SOCKET_TCP) == 0,
          "STREAM_SOCKET_TCP is not in-process");
    CHECK(evpl_protocol_is_inproc(EVPL_STREAM_SOCKET_UNIX) == 0,
          "STREAM_SOCKET_UNIX is not in-process");
    CHECK(evpl_protocol_is_local(EVPL_STREAM_INPROC) == 0,
          "STREAM_INPROC is not a local socket");
    CHECK(evpl_protocol_is_stream(EVPL_STREAM_INPROC) == 1,
          "STREAM_INPROC is a stream");
    CHECK(evpl_protocol_is_stream(EVPL_DATAGRAM_INPROC) == 0,
          "DATAGRAM_INPROC is not a stream");

    rc = evpl_protocol_lookup(&proto, "DATAGRAM_INPROC");
    CHECK(rc == 0 && proto == EVPL_DATAGRAM_INPROC, "lookup by name");

    evpl     = evpl_create(NULL);
    listener = evpl_listener_create();

    /* --- a protocol/endpoint mismatch is an error, not an abort --- */
    CHECK(evpl_listen(listener, EVPL_STREAM_SOCKET_TCP, ep) == -1,
          "listen(TCP, inproc endpoint) refused");
    CHECK(evpl_listen(listener, EVPL_STREAM_INPROC, inet_ep) == -1,
          "listen(STREAM_INPROC, inet endpoint) refused");
    CHECK(evpl_listen(listener, EVPL_STREAM_INPROC, local_ep) == -1,
          "listen(STREAM_INPROC, unix endpoint) refused");
    CHECK(evpl_connect(evpl, EVPL_STREAM_SOCKET_UNIX, NULL, ep,
                       client_callback, NULL, NULL) == NULL,
          "connect(UNIX, inproc endpoint) refused");

    /* --- a real connection, and how its addresses render --- */
    binding = evpl_listener_attach(evpl, listener, accept_callback, NULL);

    CHECK(evpl_listen(listener, EVPL_STREAM_INPROC, ep) == 0,
          "listen(STREAM_INPROC, inproc endpoint) succeeds");

    conn = evpl_connect(evpl, EVPL_STREAM_INPROC, NULL, ep,
                        client_callback, NULL, NULL);
    CHECK(conn != NULL, "connect(STREAM_INPROC, inproc endpoint) succeeds");

    wait_for_conns(evpl, 1);
    CHECK(conn_count == 1, "server observed the connection");

    CHECK(strcmp(server_local, "inproc:endpoint-inproc") == 0,
          "listener renders as '%s'", server_local);

    /* The connecting end carries a serial, the way a TCP client carries an
     * ephemeral port, so the two ends are distinguishable. */
    snprintf(expect, sizeof(expect), "inproc:endpoint-inproc#%d", 1);
    CHECK(strcmp(server_remote, expect) == 0,
          "connected peer renders as '%s'", server_remote);

    CHECK(strlen(server_local_trunc) == sizeof(server_local_trunc) - 1 &&
          strncmp(server_local_trunc, server_local,
                  sizeof(server_local_trunc) - 1) == 0,
          "long name truncates safely to '%s'", server_local_trunc);

    /* --- a name already in use is reported, not fatal --- */
    CHECK(evpl_listen(listener, EVPL_STREAM_INPROC, ep) == -1,
          "listen on a name already in use returns -1");

    /* A second protocol does not get its own namespace: the registry is keyed
     * by name alone, so this collides too. */
    CHECK(evpl_listen(listener, EVPL_DATAGRAM_INPROC, ep) == -1,
          "listen on a name in use by another protocol returns -1");

    /* --- connecting to a name nobody has registered --- */
    absent_ep = evpl_endpoint_create_inproc("endpoint-inproc-absent");
    CHECK(absent_ep != NULL, "endpoint for an unregistered name created");

    conn = evpl_connect(evpl, EVPL_STREAM_INPROC, NULL, absent_ep,
                        client_callback, NULL, NULL);
    CHECK(conn != NULL, "connect to an unregistered name returns a bind");

    /* Reported the way a refused connection is, rather than by aborting. */
    wait_for_disconnects(evpl, 1);
    CHECK(client_disconnects == 1,
          "connect to an unregistered name reports disconnect");

    /* Having survived all of that, the process must still be able to serve. */
    conn = evpl_connect(evpl, EVPL_STREAM_INPROC, NULL, ep,
                        client_callback, NULL, NULL);
    CHECK(conn != NULL, "still accepting connections after failed listens");

    wait_for_conns(evpl, 2);
    CHECK(conn_count == 2, "listener still live after failed listens");

    snprintf(expect, sizeof(expect), "inproc:endpoint-inproc#%d", 2);
    CHECK(strcmp(server_remote, expect) == 0,
          "second connection gets its own serial, '%s'", server_remote);

    /* --- a payload the peer may take by reference --- */

    /* Every other test sends thread-local buffers, which the transport has to
     * copy into shared ones before the peer can release them.  A SHARED iovec
     * takes the other branch and crosses by reference, so it is worth proving
     * separately that it arrives intact -- half the send path is otherwise
     * never executed. */
    rc = evpl_iovec_alloc(evpl, sizeof(shared_payload), 0, 1,
                          EVPL_IOVEC_FLAG_SHARED, &iov);
    CHECK(rc == 1, "shared iovec allocated");

    memcpy(iov.data, shared_payload, sizeof(shared_payload));

    evpl_sendv(evpl, conn, &iov, 1, sizeof(shared_payload),
               EVPL_SEND_FLAG_TAKE_REF);

    wait_for_bytes(evpl);

    CHECK(server_bytes == (int) sizeof(shared_payload) &&
          memcmp(server_data, shared_payload, sizeof(shared_payload)) == 0,
          "zero-copy shared payload arrives intact");

    evpl_listener_detach(evpl, binding);
    evpl_listener_destroy(listener);
    evpl_destroy(evpl);

    evpl_endpoint_close(ep);
    evpl_endpoint_close(inet_ep);
    evpl_endpoint_close(local_ep);
    evpl_endpoint_close(absent_ep);

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);

    return failures != 0;
} /* main */
