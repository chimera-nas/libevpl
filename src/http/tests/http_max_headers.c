// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Exercises the configurable HTTP header block limit (http_max_header_size,
 * default 8192) in all four places it is enforced:
 *
 * 1. Outbound, both directions: evpl_http_request_add_header() refuses (-1)
 *    headers that would push the block past the limit, and the exchange
 *    still completes cleanly with the headers that fit.  Before the limit
 *    existed, emission built the block in a fixed 4096-byte iovec with
 *    unchecked snprintf cursor arithmetic, so an oversized block corrupted
 *    the heap.
 *
 * 2. Inbound at the server: a raw client sending more than the limit worth
 *    of request headers is answered with 400 Bad Request and disconnected,
 *    as Apache does when its LimitRequestField* limits are exceeded.
 *
 * 3. Inbound at the client: a raw server sending more than the limit worth
 *    of response headers gets the connection closed; previously each parsed
 *    header pinned a ~16KB struct with no bound on the count.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include "evpl/evpl.h"
#include "evpl/evpl_http.h"

#define TEST_PORT            8091
#define RAW_SERVER_PORT      8093

#define BIG_HEADER_VALUE_LEN 150
#define MAX_ADD_ATTEMPTS     200

static const char   response_body[] = "hello world";

static char         big_value[BIG_HEADER_VALUE_LEN + 1];

/* written by the server thread, read by main after the exchange completes */
static volatile int g_server_hdrs_added;
static volatile int g_server_hdrs_refused;

/* ------------------------------------------------------------- evpl server */

struct test_server {
    pthread_t            thread;
    volatile int         run;
    struct evpl_doorbell doorbell;
};

static void
server_wake(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
} /* server_wake */

static void
server_notify(
    struct evpl                *evpl,
    struct evpl_http_agent     *agent,
    struct evpl_http_request   *request,
    enum evpl_http_notify_type  notify_type,
    enum evpl_http_request_type request_type,
    const char                 *uri,
    void                       *notify_data,
    void                       *private_data)
{
    struct evpl_iovec iov;
    char              name[32];
    int               i;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            /* Attach far more response header bytes than the limit allows;
             * the surplus must be refused, not truncated on the wire. */
            for (i = 0; i < MAX_ADD_ATTEMPTS; i++) {
                snprintf(name, sizeof(name), "X-Meta-%d", i);
                if (evpl_http_request_add_header(request, name, big_value) == 0) {
                    g_server_hdrs_added++;
                } else {
                    g_server_hdrs_refused++;
                }
            }

            evpl_iovec_alloc(evpl, sizeof(response_body) - 1, 0, 1, 0, &iov);
            memcpy(iov.data, response_body, sizeof(response_body) - 1);
            iov.length = sizeof(response_body) - 1;
            evpl_http_server_set_response_length(request, sizeof(response_body) - 1);
            evpl_http_request_add_datav(request, &iov, 1);
            evpl_http_server_dispatch_default(request, 200);
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            /* The raw peers in this test hang up mid-conversation on purpose,
             * so a request that never completes is expected here. */
            break;
    } /* switch */
} /* server_notify */

static void
server_dispatch(
    struct evpl                 *evpl,
    struct evpl_http_agent      *agent,
    struct evpl_http_request    *request,
    evpl_http_notify_callback_t *notify_callback,
    void                       **notify_data,
    void                        *private_data)
{
    *notify_callback = server_notify;
    *notify_data     = NULL;
} /* server_dispatch */

static void *
server_function(void *ptr)
{
    struct test_server      *server_ctx = ptr;
    struct evpl_http_server *server;
    struct evpl             *evpl;
    struct evpl_endpoint    *endpoint;
    struct evpl_listener    *listener;
    struct evpl_http_agent  *agent;

    evpl = evpl_create(NULL);

    evpl_add_doorbell(evpl, &server_ctx->doorbell, server_wake);

    agent = evpl_http_init(evpl);

    endpoint = evpl_endpoint_create("0.0.0.0", TEST_PORT);

    listener = evpl_listener_create();

    server = evpl_http_attach(agent, listener, server_dispatch, NULL);

    evpl_listen(listener, EVPL_STREAM_SOCKET_TCP, endpoint);

    __sync_synchronize();

    server_ctx->run = 1;

    while (server_ctx->run) {
        evpl_continue(evpl);
    }

    evpl_http_server_destroy(agent, server);
    evpl_http_destroy(agent);

    evpl_listener_destroy(listener);
    evpl_destroy(evpl);

    return NULL;
} /* server_function */

/* ------------------------------------------------------------- evpl client */

struct req_ctx {
    int  done;
    int  failed;   /* EVPL_HTTP_ERROR_* if the request was abandoned */
    int  status;
    int  body_len;
    char body[256];
};

static void
client_drain(
    struct evpl              *evpl,
    struct evpl_http_request *request,
    struct req_ctx           *rc)
{
    struct evpl_iovec iov[8];
    uint64_t          avail;
    int               niov, i;

    avail = evpl_http_request_get_data_avail(request);

    while (avail > 0) {
        niov = evpl_http_request_get_datav(evpl, request, iov, (int) avail);

        for (i = 0; i < niov; i++) {
            memcpy(rc->body + rc->body_len, iov[i].data, iov[i].length);
            rc->body_len += iov[i].length;
            evpl_iovec_release(evpl, &iov[i]);
        }

        avail = evpl_http_request_get_data_avail(request);
    }
} /* client_drain */

static void
client_notify(
    struct evpl                *evpl,
    struct evpl_http_agent     *agent,
    struct evpl_http_request   *request,
    enum evpl_http_notify_type  notify_type,
    enum evpl_http_request_type request_type,
    const char                 *uri,
    void                       *notify_data,
    void                       *private_data)
{
    struct req_ctx *rc = notify_data;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
            rc->status = evpl_http_request_status(request);
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            client_drain(evpl, request, rc);
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            client_drain(evpl, request, rc);
            rc->done = 1;
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            /* Part 3's raw server answers with an oversized header block, so
             * this is the notification that the request is over -- which is
             * what the part asserts, now that there is one. */
            rc->failed = evpl_http_request_status(request);
            break;
    } /* switch */
} /* client_notify */

/*
 * Part 1: attach an oversized set of headers on the request, check the
 * surplus is refused, and check the exchange (whose response block is
 * likewise refused down to fit) completes cleanly.
 */
static int
test_outbound_limits(
    struct evpl           *evpl,
    struct evpl_http_conn *conn)
{
    struct evpl_http_request *request;
    struct req_ctx            rc;
    char                      name[32];
    int                       i, added = 0, refused = 0;

    memset(&rc, 0, sizeof(rc));

    request = evpl_http_request_create(conn, EVPL_HTTP_REQUEST_TYPE_GET, "/");

    if (!request) {
        fprintf(stderr, "outbound: request_create failed\n");
        return 1;
    }

    evpl_http_request_add_header(request, "Host", "localhost");

    for (i = 0; i < MAX_ADD_ATTEMPTS; i++) {
        snprintf(name, sizeof(name), "X-Req-Meta-%d", i);
        if (evpl_http_request_add_header(request, name, big_value) == 0) {
            added++;
        } else {
            refused++;
        }
    }

    if (refused == 0 || added == 0) {
        fprintf(stderr, "outbound: expected both accepted and refused "
                "request headers (added %d, refused %d)\n", added, refused);
        return 1;
    }

    evpl_http_client_set_request_length(request, 0);

    evpl_http_request_dispatch(request, client_notify, &rc);

    while (!rc.done) {
        evpl_continue(evpl);
    }

    if (rc.status != 200) {
        fprintf(stderr, "outbound: bad status %d\n", rc.status);
        return 1;
    }

    if (rc.body_len != (int) (sizeof(response_body) - 1) ||
        memcmp(rc.body, response_body, rc.body_len) != 0) {
        fprintf(stderr, "outbound: bad body '%.*s' (%d bytes)\n",
                rc.body_len, rc.body, rc.body_len);
        return 1;
    }

    if (g_server_hdrs_refused == 0 || g_server_hdrs_added == 0) {
        fprintf(stderr, "outbound: expected both accepted and refused "
                "response headers (added %d, refused %d)\n",
                g_server_hdrs_added, g_server_hdrs_refused);
        return 1;
    }

    fprintf(stderr, "outbound: ok (request %d/%d added, response %d/%d added)\n",
            added, added + refused,
            g_server_hdrs_added, g_server_hdrs_added + g_server_hdrs_refused);

    return 0;
} /* test_outbound_limits */

/*
 * Part 2: a raw client sends a request whose header block exceeds the
 * limit and must get 400 Bad Request back, then EOF.
 */
static int
test_inbound_server_limit(void)
{
    struct sockaddr_in addr;
    char               buf[65536];
    char               reply[256];
    int                fd, off = 0, n, got = 0;
    int                i;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("inbound-server: socket");
        return 1;
    }

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(TEST_PORT);

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("inbound-server: connect");
        return 1;
    }

    off += snprintf(buf + off, sizeof(buf) - off,
                    "GET / HTTP/1.1\r\nHost: localhost\r\n");

    /* ~64 lines x ~166 bytes: comfortably past the 8192 default */
    for (i = 0; i < 64; i++) {
        off += snprintf(buf + off, sizeof(buf) - off,
                        "X-Big-%d: %s\r\n", i, big_value);
    }

    if (write(fd, buf, off) != off) {
        perror("inbound-server: write");
        close(fd);
        return 1;
    }

    while (got < (int) sizeof(reply) - 1) {
        n = read(fd, reply + got, sizeof(reply) - 1 - got);
        if (n <= 0) {
            break;
        }
        got += n;
    }
    reply[got] = '\0';

    close(fd);

    if (strncmp(reply, "HTTP/1.1 400 ", 13) != 0) {
        fprintf(stderr, "inbound-server: expected 400, got '%.40s'\n", reply);
        return 1;
    }

    fprintf(stderr, "inbound-server: ok (got 400 Bad Request)\n");

    return 0;
} /* test_inbound_server_limit */

/* --------------------------------------------------------------- raw server */

/*
 * Part 3's peer: accept one connection, read the request, answer with more
 * response header bytes than the limit allows, then close.
 */
static void *
raw_server_function(void *ptr)
{
    struct sockaddr_in addr;
    char               buf[65536];
    int                lfd, cfd, off = 0, i, one = 1;
    ssize_t            n;

    lfd = socket(AF_INET, SOCK_STREAM, 0);
    if (lfd < 0) {
        perror("raw-server: socket");
        exit(2);
    }
    setsockopt(lfd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(RAW_SERVER_PORT);

    if (bind(lfd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        listen(lfd, 1) < 0) {
        perror("raw-server: bind/listen");
        exit(2);
    }

    cfd = accept(lfd, NULL, NULL);
    if (cfd < 0) {
        perror("raw-server: accept");
        exit(2);
    }

    n = read(cfd, buf, sizeof(buf));
    (void) n;

    off += snprintf(buf + off, sizeof(buf) - off, "HTTP/1.1 200 OK\r\n");

    for (i = 0; i < 80; i++) {
        off += snprintf(buf + off, sizeof(buf) - off,
                        "X-Resp-%d: %s\r\n", i, big_value);
    }

    /* the client is expected to hang up mid-block; ignore the short write */
    n = write(cfd, buf, off);
    (void) n;

    usleep(200000);
    close(cfd);
    close(lfd);

    return NULL;
} /* raw_server_function */

/*
 * Part 3: the evpl client must abandon a response whose header block
 * exceeds the limit by closing the connection, without completing the
 * request and without corrupting anything (the debug build's ASan checks
 * the teardown path).
 */
static int
test_inbound_client_limit(struct evpl *evpl)
{
    pthread_t                 raw_thread;
    struct evpl_http_agent   *agent;
    struct evpl_endpoint     *endpoint;
    struct evpl_http_conn    *conn;
    struct evpl_http_request *request;
    struct req_ctx            rc;
    int                       i;

    memset(&rc, 0, sizeof(rc));

    pthread_create(&raw_thread, NULL, raw_server_function, NULL);
    usleep(100000); /* let the raw server reach accept() */

    agent = evpl_http_init(evpl);

    endpoint = evpl_endpoint_create("127.0.0.1", RAW_SERVER_PORT);

    conn = evpl_http_client_connect(agent, EVPL_STREAM_SOCKET_TCP, endpoint,
                                    EVPL_HTTP_VERSION_HTTP1, NULL);

    request = evpl_http_request_create(conn, EVPL_HTTP_REQUEST_TYPE_GET, "/");

    evpl_http_request_add_header(request, "Host", "localhost");
    evpl_http_client_set_request_length(request, 0);
    evpl_http_request_dispatch(request, client_notify, &rc);

    /* pump long enough (bounded, wait_ms below caps each pass) to send the
     * request, hit the limit mid-parse, and tear the connection down */
    for (i = 0; i < 300 && !rc.done; i++) {
        evpl_continue(evpl);
    }

    pthread_join(raw_thread, NULL);

    evpl_http_destroy(agent);

    if (rc.done) {
        fprintf(stderr, "inbound-client: oversized response unexpectedly "
                "completed (status %d)\n", rc.status);
        return 1;
    }

    /* Not completing is only half of it: the caller has to be told the request
     * is over, or it waits on a completion that can no longer arrive. */
    if (rc.failed != EVPL_HTTP_ERROR_BAD_RESPONSE) {
        fprintf(stderr, "inbound-client: expected the request to be reported "
                "failed with BAD_RESPONSE, got %d\n", rc.failed);
        return 1;
    }

    fprintf(stderr, "inbound-client: ok (request reported failed)\n");

    return 0;
} /* test_inbound_client_limit */

int
main(
    int   argc,
    char *argv[])
{
    struct test_server         server;
    struct evpl               *evpl;
    struct evpl_http_agent    *agent;
    struct evpl_endpoint      *endpoint;
    struct evpl_http_conn     *conn;
    struct evpl_thread_config *tconfig;
    int                        rc = 0;

    /* the raw peers close mid-conversation; a late write must not kill us */
    signal(SIGPIPE, SIG_IGN);

    memset(big_value, 'A', BIG_HEADER_VALUE_LEN);
    big_value[BIG_HEADER_VALUE_LEN] = '\0';

    evpl_init(NULL);

    server.run = 0;

    pthread_create(&server.thread, NULL, server_function, &server);

    while (!server.run) {
        __sync_synchronize();
    }

    /* bound event waits so the part-3 pump loop keeps ticking when idle */
    tconfig = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(tconfig, 10);
    evpl = evpl_create(tconfig);

    agent = evpl_http_init(evpl);

    endpoint = evpl_endpoint_create("127.0.0.1", TEST_PORT);

    conn = evpl_http_client_connect(agent, EVPL_STREAM_SOCKET_TCP, endpoint,
                                    EVPL_HTTP_VERSION_HTTP1, NULL);

    rc |= test_outbound_limits(evpl, conn);

    evpl_http_client_close(agent, conn);

    rc |= test_inbound_server_limit();

    rc |= test_inbound_client_limit(evpl);

    evpl_http_destroy(agent);
    evpl_destroy(evpl);

    server.run = 0;
    __sync_synchronize();
    evpl_ring_doorbell(&server.doorbell);
    pthread_join(server.thread, NULL);

    if (rc == 0) {
        fprintf(stderr, "all header limit checks ok\n");
    }

    return rc;
} /* main */
