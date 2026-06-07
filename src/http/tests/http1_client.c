// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Exercises the libevpl HTTP client against the libevpl HTTP server over plain
 * HTTP/1.1: GET (no body), POST (fixed Content-Length), and a chunked request
 * answered with a chunked response.  The server runs in its own thread/event
 * loop; the client drives its own event loop in the main thread.
 *
 * The same harness backs http2_client (which selects HTTP/2 via the version
 * argument), so this also validates the unified, transport-agnostic API.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "evpl/evpl.h"
#include "evpl/evpl_http.h"

#ifndef TEST_PROTOCOL
#define TEST_PROTOCOL EVPL_STREAM_SOCKET_TCP
#endif /* ifndef TEST_PROTOCOL */

#ifndef TEST_VERSION
#define TEST_VERSION  EVPL_HTTP_VERSION_HTTP1
#endif /* ifndef TEST_VERSION */

#define TEST_PORT     8080

static const char response_body[] = "hello world";

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
    int               chunked;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            chunked = (strcmp(uri, "/chunked") == 0);

            evpl_http_request_add_header(request, "MyHeader", "MyValue");

            if (chunked) {
                evpl_http_server_set_response_chunked(request);
                evpl_http_server_dispatch_default(request, 200);
            } else {
                evpl_iovec_alloc(evpl, sizeof(response_body) - 1, 0, 1, 0, &iov);
                memcpy(iov.data, response_body, sizeof(response_body) - 1);
                iov.length = sizeof(response_body) - 1;
                evpl_http_server_set_response_length(request, sizeof(response_body) - 1);
                evpl_http_request_add_datav(request, &iov, 1);
                evpl_http_server_dispatch_default(request, 200);
            }
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
            /* chunked response: stream the body then finish */
            evpl_iovec_alloc(evpl, sizeof(response_body) - 1, 0, 1, 0, &iov);
            memcpy(iov.data, response_body, sizeof(response_body) - 1);
            iov.length = sizeof(response_body) - 1;
            evpl_http_request_add_datav(request, &iov, 1);
            evpl_http_request_add_datav(request, NULL, 0);
            break;
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

    evpl_listen(listener, TEST_PROTOCOL, endpoint);

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

static const char *
evpl_http_method_type_name(
    enum evpl_http_request_type t);

static int
do_request(
    struct evpl                *evpl,
    struct evpl_http_conn      *conn,
    enum evpl_http_request_type method,
    const char                 *url,
    const char                 *body,
    int                         chunked)
{
    struct evpl_http_request *request;
    struct req_ctx            rc;
    struct evpl_iovec         iov;
    size_t                    body_len = body ? strlen(body) : 0;

    memset(&rc, 0, sizeof(rc));

    request = evpl_http_request_create(conn, method, url);

    evpl_http_request_add_header(request, "Host", "localhost");

    if (chunked) {
        evpl_http_client_set_request_chunked(request);
        if (body_len) {
            evpl_iovec_alloc(evpl, body_len, 0, 1, 0, &iov);
            memcpy(iov.data, body, body_len);
            iov.length = body_len;
            evpl_http_request_add_datav(request, &iov, 1);
        }
        evpl_http_request_add_datav(request, NULL, 0);
    } else {
        evpl_http_client_set_request_length(request, body_len);
        if (body_len) {
            evpl_iovec_alloc(evpl, body_len, 0, 1, 0, &iov);
            memcpy(iov.data, body, body_len);
            iov.length = body_len;
            evpl_http_request_add_datav(request, &iov, 1);
        }
    }

    evpl_http_request_dispatch(request, client_notify, &rc);

    while (!rc.done) {
        evpl_continue(evpl);
    }

    if (rc.status != 200) {
        fprintf(stderr, "%s %s: bad status %d\n",
                evpl_http_method_type_name(method), url, rc.status);
        return 1;
    }

    if (rc.body_len != (int) (sizeof(response_body) - 1) ||
        memcmp(rc.body, response_body, rc.body_len) != 0) {
        fprintf(stderr, "%s %s: bad body '%.*s' (%d bytes)\n",
                evpl_http_method_type_name(method), url,
                rc.body_len, rc.body, rc.body_len);
        return 1;
    }

    fprintf(stderr, "%s %s: ok (status %d, %d bytes)\n",
            evpl_http_method_type_name(method), url, rc.status, rc.body_len);

    return 0;
} /* do_request */

/* method name for diagnostics only */
static const char *
evpl_http_method_type_name(enum evpl_http_request_type t)
{
    switch (t) {
        case EVPL_HTTP_REQUEST_TYPE_GET:
            return "GET";
        case EVPL_HTTP_REQUEST_TYPE_POST:
            return "POST";
        default:
            return "?";
    } /* switch */
} /* evpl_http_method_type_name */

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
    int                        rc = 0;

    /* TLS variants use a self-signed server cert; skip peer verification. */
    config = evpl_global_config_init();
    evpl_global_config_set_tls_verify_peer(config, 0);
    evpl_init(config);

    server.run = 0;

    pthread_create(&server.thread, NULL, server_function, &server);

    while (!server.run) {
        __sync_synchronize();
    }

    evpl = evpl_create(NULL);

    agent = evpl_http_init(evpl);

    endpoint = evpl_endpoint_create("127.0.0.1", TEST_PORT);

    conn = evpl_http_client_connect(agent, TEST_PROTOCOL, endpoint,
                                    TEST_VERSION, NULL);

    rc |= do_request(evpl, conn, EVPL_HTTP_REQUEST_TYPE_GET, "/", NULL, 0);
    rc |= do_request(evpl, conn, EVPL_HTTP_REQUEST_TYPE_POST, "/", "ping pong", 0);
    rc |= do_request(evpl, conn, EVPL_HTTP_REQUEST_TYPE_POST, "/chunked", "streamed", 1);

    evpl_http_client_close(agent, conn);

    evpl_http_destroy(agent);
    evpl_destroy(evpl);

    server.run = 0;
    __sync_synchronize();
    evpl_ring_doorbell(&server.doorbell);
    pthread_join(server.thread, NULL);

    if (rc == 0) {
        fprintf(stderr, "all requests ok\n");
    }

    return rc;
} /* main */
