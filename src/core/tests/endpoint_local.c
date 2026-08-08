// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Local (AF_UNIX) endpoint construction, protocol pairing, and address
 * rendering.
 *
 * The sockaddr_un length arithmetic is the fiddly part and is what this
 * mostly guards: a pathname socket carries its trailing NUL inside addrlen
 * while an abstract name must not, and getting either wrong yields a socket
 * that binds but is unreachable rather than an outright failure.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>

#include "evpl/evpl.h"

static int  failures;
static char server_local[EVPL_ADDRESS_STRLEN];
static char server_remote[EVPL_ADDRESS_STRLEN];
static char server_local_trunc[8];
static int  conn_count;

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
    if (notify->notify_type != EVPL_NOTIFY_CONNECTED) {
        return;
    }

    evpl_bind_get_local_address(bind, server_local, sizeof(server_local));
    evpl_bind_get_remote_address(bind, server_remote, sizeof(server_remote));

    /* The listener's path is longer than 8 bytes, so this is a genuine
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

int
main(
    int   argc,
    char *argv[])
{
    struct evpl                  *evpl;
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    struct evpl_endpoint         *ep, *abstract_ep, *inet_ep, *ep_denied;
    struct evpl_bind             *conn;
    enum evpl_protocol_id         proto;
    char                          path[EVPL_ADDRESS_STRLEN + 32];
    char                          sockpath[96];
    const char                   *dir;
    int                           rc;

    evpl_init(NULL);

    dir = getenv("EVPL_TEST_SOCKET_DIR");

    if (!dir || dir[0] != '/') {
        dir = "/tmp";
    }

    snprintf(sockpath, sizeof(sockpath), "%s/evpl-endpoint-local-%d.sock",
             dir, (int) getpid());

    /* --- rejected forms --- */
    CHECK(evpl_endpoint_create_local("relative/path") == NULL,
          "relative path rejected");
    CHECK(evpl_endpoint_create_local("@") == NULL, "bare '@' rejected");
    CHECK(evpl_endpoint_create_local("nohost") == NULL, "bare name rejected");
    CHECK(evpl_endpoint_create("/", 0) == NULL, "bare '/' rejected");

    /* sun_path is 108 bytes.  A pathname socket spends one on its trailing
     * NUL, so 107 is the longest that fits and 108 must be refused rather
     * than truncated into a different socket. */
    memset(path, 'x', sizeof(path));
    path[0]   = '/';
    path[108] = '\0';
    CHECK(evpl_endpoint_create_local(path) == NULL,
          "108-byte path rejected");

    path[107] = '\0';
    ep        = evpl_endpoint_create_local(path);
    CHECK(ep != NULL, "107-byte path accepted");
    if (ep) {
        evpl_endpoint_close(ep);
    }

    /* An abstract name spends its byte on the leading NUL instead, so the
     * whole 108 is usable. */
    memset(path, 'y', sizeof(path));
    path[0]   = '@';
    path[108] = '\0';
    ep        = evpl_endpoint_create_local(path);
    CHECK(ep != NULL, "108-byte abstract name accepted");
    if (ep) {
        evpl_endpoint_close(ep);
    }

    /* --- protocol predicates --- */
    CHECK(evpl_protocol_available(EVPL_STREAM_SOCKET_UNIX) == 1,
          "STREAM_SOCKET_UNIX available");
    CHECK(evpl_protocol_is_local(EVPL_STREAM_SOCKET_UNIX) == 1,
          "STREAM_SOCKET_UNIX is local");
    CHECK(evpl_protocol_is_local(EVPL_STREAM_SOCKET_TCP) == 0,
          "STREAM_SOCKET_TCP is not local");
    CHECK(evpl_protocol_is_stream(EVPL_STREAM_SOCKET_UNIX) == 1,
          "STREAM_SOCKET_UNIX is a stream");

    rc = evpl_protocol_lookup(&proto, "STREAM_SOCKET_UNIX");
    CHECK(rc == 0 && proto == EVPL_STREAM_SOCKET_UNIX, "lookup by name");

    /* --- evpl_endpoint_create recognizes a local socket name --- */
    ep = evpl_endpoint_create(sockpath, 0);
    CHECK(ep && evpl_endpoint_is_local(ep), "create('/path') detects local");

    abstract_ep = evpl_endpoint_create("@evpl-endpoint-local", 0);
    CHECK(abstract_ep && evpl_endpoint_is_local(abstract_ep),
          "create('@name') detects local");

    inet_ep = evpl_endpoint_create("127.0.0.1", 8299);
    CHECK(inet_ep && !evpl_endpoint_is_local(inet_ep),
          "create('127.0.0.1') stays inet");

    evpl     = evpl_create(NULL);
    listener = evpl_listener_create();

    /* --- a protocol/endpoint mismatch is an error, not an abort --- */
    CHECK(evpl_listen(listener, EVPL_STREAM_SOCKET_TCP, ep) == -1,
          "listen(TCP, local endpoint) refused");
    CHECK(evpl_listen(listener, EVPL_STREAM_SOCKET_UNIX, inet_ep) == -1,
          "listen(UNIX, inet endpoint) refused");
    CHECK(evpl_connect(evpl, EVPL_STREAM_SOCKET_TCP, NULL, ep,
                       client_callback, NULL, NULL) == NULL,
          "connect(TCP, local endpoint) refused");

    /* --- a real connection, and how its addresses render --- */
    binding = evpl_listener_attach(evpl, listener, accept_callback, NULL);

    CHECK(evpl_listen(listener, EVPL_STREAM_SOCKET_UNIX, ep) == 0,
          "listen(UNIX, local endpoint) succeeds");

    conn = evpl_connect(evpl, EVPL_STREAM_SOCKET_UNIX, NULL, ep,
                        client_callback, NULL, NULL);
    CHECK(conn != NULL, "connect(UNIX, local endpoint) succeeds");

    wait_for_conns(evpl, 1);
    CHECK(conn_count == 1, "server observed the connection");

    snprintf(path, sizeof(path), "unix:%s", sockpath);
    CHECK(strcmp(server_local, path) == 0,
          "listener renders as '%s'", server_local);

    /* A unix client is unbound unless it explicitly binds, so accept() hands
     * back just the family with an empty path. */
    CHECK(strcmp(server_remote, "unix:*") == 0,
          "unbound peer renders as '%s'", server_remote);

    CHECK(strlen(server_local_trunc) == sizeof(server_local_trunc) - 1 &&
          strncmp(server_local_trunc, path, sizeof(server_local_trunc) - 1) == 0,
          "long path truncates safely to '%s'", server_local_trunc);

    /* --- a backend listen failure is reported, not fatal --- */

    /* The socket is already bound and live above, and the stale-socket probe
     * will find a listener answering on it, so it must refuse rather than
     * displace it -- and must say so by returning rather than aborting. */
    CHECK(evpl_listen(listener, EVPL_STREAM_SOCKET_UNIX, ep) == -1,
          "listen on an address already in use returns -1");

    /* That check went through the stale-socket probe, which establishes a
     * real connection to prove someone is listening.  The server therefore
     * sees a connect it did not ask for; drain it so the accepted socket is
     * attached and freed rather than left in flight at teardown. */
    wait_for_conns(evpl, 2);

    /* A directory nobody may write to: bind() fails with EACCES. */
    ep_denied = evpl_endpoint_create_local("/proc/evpl-denied.sock");
    CHECK(ep_denied != NULL, "endpoint on an unwritable directory created");
    CHECK(evpl_listen(listener, EVPL_STREAM_SOCKET_UNIX, ep_denied) == -1,
          "listen on an unwritable directory returns -1");

    /* Having survived both, the process must still be able to serve. */
    conn = evpl_connect(evpl, EVPL_STREAM_SOCKET_UNIX, NULL, ep,
                        client_callback, NULL, NULL);
    CHECK(conn != NULL, "still accepting connections after failed listens");

    wait_for_conns(evpl, 3);
    CHECK(conn_count == 3, "listener still live after failed listens");

    evpl_listener_detach(evpl, binding);
    evpl_listener_destroy(listener);
    evpl_destroy(evpl);

    evpl_endpoint_close(ep);
    evpl_endpoint_close(abstract_ep);
    evpl_endpoint_close(inet_ep);
    evpl_endpoint_close(ep_denied);

    printf("\n%s (%d failures)\n", failures ? "FAILED" : "PASSED", failures);

    return failures != 0;
} /* main */
