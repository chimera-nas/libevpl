// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * The abort lifecycle: every request an application is holding hears exactly
 * one terminal notification, however its exchange ends.
 *
 *   1. an HTTP/2 client cancels mid-stream: the server's request completes
 *      with FAILED/STREAM_RESET, and the connection survives -- the next
 *      request on it succeeds;
 *   2. an HTTP/2 client closes its connection with a stream in flight: both
 *      ends complete the request with FAILED/CONN_LOST;
 *   3. an HTTP/1.x client cancels mid-stream: the only abort HTTP/1.x has is
 *      the connection, so the server sees a disconnect and completes its
 *      half-answered request with FAILED/CONN_LOST.
 *
 * The server answers /stream with a chunked response that sends one chunk and
 * then stalls without ever finishing, so every abort lands mid-exchange by
 * construction -- no timing involved.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "evpl/evpl.h"
#include "evpl/evpl_http.h"

#define TEST_PORT 8087

static const char           response_body[] = "hello world";

/* terminal outcomes observed by the server thread, read by the main thread.
 * The doorbell wakes the client loop when a count changes -- without it the
 * client would sit in its event wait with nothing left to wake it. */
static volatile int         server_reset_failures = 0; /* FAILED with STREAM_RESET */
static volatile int         server_lost_failures  = 0; /* FAILED with CONN_LOST    */
static struct evpl_doorbell count_doorbell;

/* ------------------------------------------------------------------ server */

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
    int               status;

    /* Each /stream response sends exactly one chunk and then stalls (the
     * cases run one /stream exchange at a time).  Without the stall the
     * server would generate chunks unboundedly fast on HTTP/1.x, where no
     * flow control paces WANT_DATA. */
    static int        stream_chunk_sent;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            if (strcmp(uri, "/stream") == 0) {
                stream_chunk_sent = 0;
                evpl_http_server_set_response_chunked(request);
                evpl_http_server_dispatch_default(request, 200);
            } else {
                evpl_iovec_alloc(evpl, sizeof(response_body) - 1, 0, 1, 0, &iov);
                memcpy(iov.data, response_body, sizeof(response_body) - 1);
                iov.length = sizeof(response_body) - 1;
                evpl_http_server_set_response_length(request,
                                                     sizeof(response_body) - 1);
                evpl_http_request_add_datav(request, &iov, 1);
                evpl_http_server_dispatch_default(request, 200);
            }
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
            /* /stream: the one chunk, then nothing -- the exchange can only
             * end by being aborted */
            if (stream_chunk_sent) {
                break;
            }
            stream_chunk_sent = 1;

            evpl_iovec_alloc(evpl, sizeof(response_body) - 1, 0, 1, 0, &iov);
            memcpy(iov.data, response_body, sizeof(response_body) - 1);
            iov.length = sizeof(response_body) - 1;
            evpl_http_request_add_datav(request, &iov, 1);
            break;
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            /* the aborted /stream exchanges land here; anything else is a
             * broken test */
            if (strcmp(uri, "/stream") != 0) {
                fprintf(stderr, "server: %s failed unexpectedly (%d)\n",
                        uri, evpl_http_request_status(request));
                exit(1);
            }

            status = evpl_http_request_status(request);

            if (status == EVPL_HTTP_ERROR_STREAM_RESET) {
                __sync_fetch_and_add(&server_reset_failures, 1);
            } else if (status == EVPL_HTTP_ERROR_CONN_LOST) {
                __sync_fetch_and_add(&server_lost_failures, 1);
            } else {
                fprintf(stderr, "server: /stream failed with %d\n", status);
                exit(1);
            }

            evpl_ring_doorbell(&count_doorbell);
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

    if (evpl_listen(listener, EVPL_STREAM_SOCKET_TCP, endpoint)) {
        fprintf(stderr, "failed to listen\n");
        exit(1);
    }

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

/* ------------------------------------------------------------------ client */

enum req_mode {
    MODE_NORMAL,          /* expect a clean 200 + body; FAILED is fatal      */
    MODE_CANCEL_ON_DATA,  /* cancel on first data; nothing may follow        */
    MODE_CLOSE_ON_DATA,   /* note first data; main loop closes the conn and
                           * FAILED/CONN_LOST is the expected completion     */
};

struct req_ctx {
    enum req_mode mode;
    int           done;
    int           got_data;
    int           status;
    int           body_len;
    char          body[256];
};

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
    struct req_ctx   *rc = notify_data;
    struct evpl_iovec iov[8];
    uint64_t          avail;
    int               niov, i;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
            rc->status = evpl_http_request_status(request);
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            avail = evpl_http_request_get_data_avail(request);

            while (avail > 0) {
                niov = evpl_http_request_get_datav(evpl, request, iov, (int) avail);
                for (i = 0; i < niov; i++) {
                    if (rc->mode == MODE_NORMAL &&
                        rc->body_len + iov[i].length <= sizeof(rc->body)) {
                        memcpy(rc->body + rc->body_len, iov[i].data, iov[i].length);
                        rc->body_len += iov[i].length;
                    }
                    evpl_iovec_release(evpl, &iov[i]);
                }
                avail = evpl_http_request_get_data_avail(request);
            }

            if (rc->mode == MODE_CANCEL_ON_DATA && !rc->got_data) {
                rc->got_data = 1;
                /* nothing may reference the request after this returns, and
                 * no notification of any kind may follow */
                evpl_http_request_cancel(request);
                rc->done = 1;
            } else {
                rc->got_data = 1;
            }
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            if (rc->mode != MODE_NORMAL) {
                fprintf(stderr, "client: unexpected completion in mode %d\n",
                        rc->mode);
                exit(1);
            }
            rc->done = 1;
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            if (rc->mode != MODE_CLOSE_ON_DATA) {
                fprintf(stderr, "client: unexpected FAILED (%d) in mode %d\n",
                        evpl_http_request_status(request), rc->mode);
                exit(1);
            }

            if (evpl_http_request_status(request) != EVPL_HTTP_ERROR_CONN_LOST) {
                fprintf(stderr, "client: FAILED with %d, wanted CONN_LOST\n",
                        evpl_http_request_status(request));
                exit(1);
            }

            rc->done = 1;
            break;
    } /* switch */
} /* client_notify */

static struct evpl_http_request *
start_request(
    struct evpl_http_conn *conn,
    const char            *url,
    struct req_ctx        *rc,
    enum req_mode          mode)
{
    struct evpl_http_request *request;

    memset(rc, 0, sizeof(*rc));
    rc->mode = mode;

    request = evpl_http_request_create(conn, EVPL_HTTP_REQUEST_TYPE_GET, url);

    evpl_http_request_add_header(request, "Host", "localhost");
    evpl_http_client_set_request_length(request, 0);

    evpl_http_request_dispatch(request, client_notify, rc);

    return request;
} /* start_request */

static void
wait_done(
    struct evpl    *evpl,
    struct req_ctx *rc)
{
    while (!rc->done) {
        evpl_continue(evpl);
    }
} /* wait_done */

/* Wait until the server thread has recorded the expected terminal outcomes.
 * Event-driven on the server side; the client just keeps its loop turning. */
static void
wait_server_counts(
    struct evpl *evpl,
    int          resets,
    int          losses)
{
    while (server_reset_failures < resets || server_lost_failures < losses) {
        evpl_continue(evpl);
        __sync_synchronize();
    }
} /* wait_server_counts */

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
    struct evpl_global_config *config;
    struct req_ctx             rc;

    config = evpl_global_config_init();
    evpl_init(config);

    server.run = 0;

    pthread_create(&server.thread, NULL, server_function, &server);

    while (!server.run) {
        __sync_synchronize();
    }

    evpl = evpl_create(NULL);

    evpl_add_doorbell(evpl, &count_doorbell, server_wake);

    agent = evpl_http_init(evpl);

    endpoint = evpl_endpoint_create("127.0.0.1", TEST_PORT);

    /* 1. h2 cancel mid-stream; the connection survives it */
    conn = evpl_http_client_connect(agent, EVPL_STREAM_SOCKET_TCP, endpoint,
                                    EVPL_HTTP_VERSION_HTTP2, NULL);

    start_request(conn, "/stream", &rc, MODE_CANCEL_ON_DATA);
    wait_done(evpl, &rc);
    wait_server_counts(evpl, 1, 0);
    fprintf(stderr, "h2 cancel: ok\n");

    start_request(conn, "/ok", &rc, MODE_NORMAL);
    wait_done(evpl, &rc);

    if (rc.status != 200 ||
        rc.body_len != (int) (sizeof(response_body) - 1) ||
        memcmp(rc.body, response_body, rc.body_len) != 0) {
        fprintf(stderr, "post-cancel request broken (status %d, %d bytes)\n",
                rc.status, rc.body_len);
        exit(1);
    }
    fprintf(stderr, "post-cancel request: ok\n");

    evpl_http_client_close(agent, conn);

    /* 2. h2 connection closed with a stream in flight: FAILED/CONN_LOST on
     * both sides */
    conn = evpl_http_client_connect(agent, EVPL_STREAM_SOCKET_TCP, endpoint,
                                    EVPL_HTTP_VERSION_HTTP2, NULL);

    start_request(conn, "/stream", &rc, MODE_CLOSE_ON_DATA);

    while (!rc.got_data) {
        evpl_continue(evpl);
    }

    evpl_http_client_close(agent, conn);
    wait_done(evpl, &rc);
    wait_server_counts(evpl, 1, 1);
    fprintf(stderr, "h2 conn loss: ok\n");

    /* 3. h1 cancel: the connection is the only abort HTTP/1.x has */
    conn = evpl_http_client_connect(agent, EVPL_STREAM_SOCKET_TCP, endpoint,
                                    EVPL_HTTP_VERSION_HTTP1, NULL);

    start_request(conn, "/stream", &rc, MODE_CANCEL_ON_DATA);
    wait_done(evpl, &rc);
    wait_server_counts(evpl, 1, 2);
    fprintf(stderr, "h1 cancel: ok\n");

    evpl_http_client_close(agent, conn);

    evpl_http_destroy(agent);
    evpl_destroy(evpl);

    server.run = 0;
    __sync_synchronize();
    evpl_ring_doorbell(&server.doorbell);
    pthread_join(server.thread, NULL);

    fprintf(stderr, "all aborts ok\n");

    return 0;
} /* main */
