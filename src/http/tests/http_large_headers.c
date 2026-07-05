// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Regression test for the fixed-size 4096-byte header buffer in
 * evpl_http_server_send_headers() / evpl_http_client_send_headers().
 *
 * Both attach enough response/request headers to blow well past the
 * buffer's capacity (mirroring an S3 GET/HEAD response re-emitting large
 * stored x-amz-meta-* values). Before the fix, once the cumulative header
 * bytes exceeded 4096, `4096 - (rsp - rsp_base)` went negative and wrapped
 * to a huge size_t, so the next snprintf() wrote past the end of the
 * allocated iovec (heap corruption, easily caught by AddressSanitizer).
 *
 * This test doesn't assert on which headers survive truncation -- once
 * more header bytes are requested than the buffer can hold, some headers
 * are legitimately dropped. What it asserts is that the exchange completes
 * cleanly: no crash, no ASan trip, and the response that does arrive is a
 * well-formed HTTP response with the expected status and body.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "evpl/evpl.h"
#include "evpl/evpl_http.h"

#define TEST_PORT            8081

static const char response_body[] = "hello world";

/* 32 headers x ~150 bytes of value each is comfortably >4096 bytes of raw
 * header text, well past the fixed buffer this code path used to overflow. */
#define NUM_BIG_HEADERS      32
#define BIG_HEADER_VALUE_LEN 150

static char       big_value[BIG_HEADER_VALUE_LEN + 1];

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
    char              name[32];
    int               i;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            /* Attach far more response header bytes than the 4096-byte
             * buffer can hold, same as re-emitting large stored S3
             * metadata on a GET/HEAD response. */
            for (i = 0; i < NUM_BIG_HEADERS; i++) {
                snprintf(name, sizeof(name), "X-Meta-%d", i);
                evpl_http_request_add_header(request, name, big_value);
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

/* ------------------------------------------------------------------ client */

struct req_ctx {
    int  done;
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
    } /* switch */
} /* client_notify */

/*
 * Issue a request that itself carries many large headers, exercising
 * evpl_http_client_send_headers() the same way the GET below exercises
 * evpl_http_server_send_headers().
 */
static int
do_large_header_request(
    struct evpl           *evpl,
    struct evpl_http_conn *conn)
{
    struct evpl_http_request *request;
    struct req_ctx            rc;
    char                      name[32];
    int                       i;

    memset(&rc, 0, sizeof(rc));

    request = evpl_http_request_create(conn, EVPL_HTTP_REQUEST_TYPE_GET, "/");

    evpl_http_request_add_header(request, "Host", "localhost");

    for (i = 0; i < NUM_BIG_HEADERS; i++) {
        snprintf(name, sizeof(name), "X-Req-Meta-%d", i);
        evpl_http_request_add_header(request, name, big_value);
    }

    evpl_http_client_set_request_length(request, 0);

    evpl_http_request_dispatch(request, client_notify, &rc);

    while (!rc.done) {
        evpl_continue(evpl);
    }

    if (rc.status != 200) {
        fprintf(stderr, "large-header request: bad status %d\n", rc.status);
        return 1;
    }

    if (rc.body_len != (int) (sizeof(response_body) - 1) ||
        memcmp(rc.body, response_body, rc.body_len) != 0) {
        fprintf(stderr, "large-header request: bad body '%.*s' (%d bytes)\n",
                rc.body_len, rc.body, rc.body_len);
        return 1;
    }

    fprintf(stderr, "large-header request: ok (status %d, %d bytes)\n",
            rc.status, rc.body_len);

    return 0;
} /* do_large_header_request */

int
main(
    int   argc,
    char *argv[])
{
    struct test_server      server;
    struct evpl            *evpl;
    struct evpl_http_agent *agent;
    struct evpl_endpoint   *endpoint;
    struct evpl_http_conn  *conn;
    int                     rc = 0;

    memset(big_value, 'A', BIG_HEADER_VALUE_LEN);
    big_value[BIG_HEADER_VALUE_LEN] = '\0';

    evpl_init(NULL);

    server.run = 0;

    pthread_create(&server.thread, NULL, server_function, &server);

    while (!server.run) {
        __sync_synchronize();
    }

    evpl = evpl_create(NULL);

    agent = evpl_http_init(evpl);

    endpoint = evpl_endpoint_create("127.0.0.1", TEST_PORT);

    conn = evpl_http_client_connect(agent, EVPL_STREAM_SOCKET_TCP, endpoint,
                                    EVPL_HTTP_VERSION_HTTP1, NULL);

    rc |= do_large_header_request(evpl, conn);

    evpl_http_client_close(agent, conn);

    evpl_http_destroy(agent);
    evpl_destroy(evpl);

    server.run = 0;
    __sync_synchronize();
    evpl_ring_doorbell(&server.doorbell);
    pthread_join(server.thread, NULL);

    if (rc == 0) {
        fprintf(stderr, "large headers handled without corruption\n");
    }

    return rc;
} /* main */
