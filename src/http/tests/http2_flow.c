// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * HTTP/2 inbound flow control follows the application's consumption: window
 * credit is granted as data is drained through evpl_http_request_get_datav,
 * so a peer can never have more than one flow-control window in flight
 * beyond what the application has taken.
 *
 * A 1MB chunked download and a 1MB chunked upload each get drained half at a
 * time, so the receiver is always behind the sender and the windows are what
 * paces the transfer.  Two things are asserted on each direction: the full
 * content arrives (the WINDOW_UPDATEs earned by draining keep the transfer
 * alive at all -- with consumption unreported it would stall inside the
 * first window), and the receive buffer never holds more than one window of
 * undrained content (the peer respected the credit).
 *
 * http2_flow_window runs the same file with a 256KB window configured via
 * evpl_global_config_set_http2_window_size, proving the knob reaches both
 * the stream and connection windows.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "evpl/evpl.h"
#include "evpl/evpl_http.h"

#ifndef TEST_PORT
#define TEST_PORT     8088
#endif /* ifndef TEST_PORT */

/* 0: keep the RFC 9113 default window of 65535 bytes */
#ifndef TEST_WINDOW
#define TEST_WINDOW   0
#endif /* ifndef TEST_WINDOW */

#define WINDOW_BOUND  (TEST_WINDOW ? TEST_WINDOW : 65535)

#define TRANSFER_SIZE (1024 * 1024)
#define CHUNK_SIZE    (32 * 1024)

/* ------------------------------------------------------------------ shared */

/* Drain about half of what is buffered, in bounded steps, and account it.
 * Returns the bytes taken. */
static uint64_t
drain_half(
    struct evpl              *evpl,
    struct evpl_http_request *request,
    uint64_t                 *total,
    uint64_t                 *max_avail)
{
    struct evpl_iovec iov[64];
    uint64_t          avail = evpl_http_request_get_data_avail(request);
    uint64_t          target;
    uint64_t          taken = 0;
    int               niov, i;

    if (avail > *max_avail) {
        *max_avail = avail;
    }

    target = (avail + 1) / 2;

    while (taken < target) {
        uint64_t step = target - taken;

        if (step > CHUNK_SIZE) {
            step = CHUNK_SIZE;
        }

        niov = evpl_http_request_get_datav(evpl, request, iov, (int) step);

        if (niov <= 0) {
            break;
        }

        for (i = 0; i < niov; i++) {
            taken += iov[i].length;
            evpl_iovec_release(evpl, &iov[i]);
        }
    }

    *total += taken;

    return taken;
} /* drain_half */

static void
drain_all(
    struct evpl              *evpl,
    struct evpl_http_request *request,
    uint64_t                 *total,
    uint64_t                 *max_avail)
{
    while (evpl_http_request_get_data_avail(request) > 0) {
        drain_half(evpl, request, total, max_avail);
    }
} /* drain_all */

static void
add_chunk(
    struct evpl              *evpl,
    struct evpl_http_request *request)
{
    struct evpl_iovec iov;

    evpl_iovec_alloc(evpl, CHUNK_SIZE, 0, 1, 0, &iov);
    memset(iov.data, 'x', CHUNK_SIZE);
    iov.length = CHUNK_SIZE;

    evpl_http_request_add_datav(request, &iov, 1);
} /* add_chunk */

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

/* one exchange at a time, so per-exchange state can live here */
static uint64_t download_sent;
static uint64_t upload_received;
static uint64_t upload_max_avail;

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
    int               n;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            /* the /upload body: drain half, so the client runs ahead of us
             * and the window is what stops it */
            drain_half(evpl, request, &upload_received, &upload_max_avail);
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            if (strcmp(uri, "/download") == 0) {
                download_sent = 0;
                evpl_http_server_set_response_chunked(request);
                evpl_http_server_dispatch_default(request, 200);
            } else {
                /* /upload: take the tail, then answer with the byte count */
                drain_all(evpl, request, &upload_received, &upload_max_avail);

                if (upload_max_avail > WINDOW_BOUND) {
                    fprintf(stderr,
                            "server: %llu bytes buffered, window is %d\n",
                            (unsigned long long) upload_max_avail,
                            WINDOW_BOUND);
                    exit(1);
                }

                evpl_iovec_alloc(evpl, 32, 0, 1, 0, &iov);
                n = snprintf(iov.data, 32, "%llu",
                             (unsigned long long) upload_received);
                iov.length = n;

                evpl_http_server_set_response_length(request, n);
                evpl_http_request_add_datav(request, &iov, 1);
                evpl_http_server_dispatch_default(request, 200);
            }
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
            /* the /download body: the next chunk, until 1MB is out */
            if (download_sent >= TRANSFER_SIZE) {
                break;
            }

            add_chunk(evpl, request);
            download_sent += CHUNK_SIZE;

            if (download_sent >= TRANSFER_SIZE) {
                evpl_http_request_add_datav(request, NULL, 0);
            }
            break;
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            fprintf(stderr, "server: %s failed unexpectedly (%d)\n",
                    uri, evpl_http_request_status(request));
            exit(1);
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

struct req_ctx {
    int      done;
    int      status;
    int      upload;      /* this request streams the 1MB request body */
    uint64_t sent;
    uint64_t received;
    uint64_t max_avail;
    char     small_body[64];
    int      small_len;
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
            if (rc->upload) {
                /* the count reply is tiny; take it whole */
                avail = evpl_http_request_get_data_avail(request);

                while (avail > 0) {
                    niov = evpl_http_request_get_datav(evpl, request, iov,
                                                       (int) avail);
                    for (i = 0; i < niov; i++) {
                        if (rc->small_len + iov[i].length <=
                            sizeof(rc->small_body)) {
                            memcpy(rc->small_body + rc->small_len,
                                   iov[i].data, iov[i].length);
                            rc->small_len += iov[i].length;
                        }
                        evpl_iovec_release(evpl, &iov[i]);
                    }
                    avail = evpl_http_request_get_data_avail(request);
                }
            } else {
                drain_half(evpl, request, &rc->received, &rc->max_avail);
            }
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            if (!rc->upload) {
                drain_all(evpl, request, &rc->received, &rc->max_avail);
            }
            rc->done = 1;
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
            if (!rc->upload || rc->sent >= TRANSFER_SIZE) {
                break;
            }

            add_chunk(evpl, request);
            rc->sent += CHUNK_SIZE;

            if (rc->sent >= TRANSFER_SIZE) {
                evpl_http_request_add_datav(request, NULL, 0);
            }
            break;
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            fprintf(stderr, "client: %s failed unexpectedly (%d)\n",
                    uri, evpl_http_request_status(request));
            exit(1);
    } /* switch */
} /* client_notify */

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
    struct evpl_http_request  *request;
    struct evpl_global_config *config;
    struct req_ctx             rc;

    config = evpl_global_config_init();

    if (TEST_WINDOW) {
        evpl_global_config_set_http2_window_size(config, TEST_WINDOW);
    }

    evpl_init(config);

    server.run = 0;

    pthread_create(&server.thread, NULL, server_function, &server);

    while (!server.run) {
        __sync_synchronize();
    }

    evpl = evpl_create(NULL);

    agent = evpl_http_init(evpl);

    endpoint = evpl_endpoint_create("127.0.0.1", TEST_PORT);

    conn = evpl_http_client_connect(agent, EVPL_STREAM_SOCKET_TCP, endpoint,
                                    EVPL_HTTP_VERSION_HTTP2, NULL);

    /* 1MB download, drained half at a time */
    memset(&rc, 0, sizeof(rc));

    request = evpl_http_request_create(conn, EVPL_HTTP_REQUEST_TYPE_GET,
                                       "/download");
    evpl_http_request_add_header(request, "Host", "localhost");
    evpl_http_client_set_request_length(request, 0);
    evpl_http_request_dispatch(request, client_notify, &rc);

    while (!rc.done) {
        evpl_continue(evpl);
    }

    if (rc.status != 200 || rc.received != TRANSFER_SIZE) {
        fprintf(stderr, "download: status %d, %llu of %d bytes\n",
                rc.status, (unsigned long long) rc.received, TRANSFER_SIZE);
        exit(1);
    }

    if (rc.max_avail > WINDOW_BOUND) {
        fprintf(stderr, "download: %llu bytes buffered, window is %d\n",
                (unsigned long long) rc.max_avail, WINDOW_BOUND);
        exit(1);
    }

    fprintf(stderr, "download: ok (%llu bytes, high-water %llu)\n",
            (unsigned long long) rc.received,
            (unsigned long long) rc.max_avail);

    /* 1MB upload; the server drains half at a time and replies with the
     * byte count it received */
    memset(&rc, 0, sizeof(rc));
    rc.upload = 1;

    request = evpl_http_request_create(conn, EVPL_HTTP_REQUEST_TYPE_POST,
                                       "/upload");
    evpl_http_request_add_header(request, "Host", "localhost");
    evpl_http_client_set_request_chunked(request);
    evpl_http_request_dispatch(request, client_notify, &rc);

    while (!rc.done) {
        evpl_continue(evpl);
    }

    rc.small_body[rc.small_len < (int) sizeof(rc.small_body) ?
                  rc.small_len : (int) sizeof(rc.small_body) - 1] = '\0';

    if (rc.status != 200 ||
        strtoull(rc.small_body, NULL, 10) != TRANSFER_SIZE) {
        fprintf(stderr, "upload: status %d, server counted '%s'\n",
                rc.status, rc.small_body);
        exit(1);
    }

    fprintf(stderr, "upload: ok (server received %s bytes)\n", rc.small_body);

    evpl_http_client_close(agent, conn);

    evpl_http_destroy(agent);
    evpl_destroy(evpl);

    server.run = 0;
    __sync_synchronize();
    evpl_ring_doorbell(&server.doorbell);
    pthread_join(server.thread, NULL);

    fprintf(stderr, "flow control ok\n");

    return 0;
} /* main */
