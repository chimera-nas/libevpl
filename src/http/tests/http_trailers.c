// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * Trailer fields in both directions, over the evpl client <-> evpl server
 * harness of http1_client:
 *
 *   - a chunked POST carrying request trailers, answered by a chunked
 *     response carrying response trailers, each end reading the other's
 *     section back through evpl_http_request_trailer after receive completes;
 *   - a bodiless chunked response that is nothing but trailers;
 *   - a Content-Length response with trailers staged, which HTTP/1.x must
 *     drop (the coding has no place for them) and HTTP/2 must deliver --
 *     the one place the two protocols are documented to diverge.
 *
 * The requests run in order on one connection, so the HTTP/1.x variant also
 * proves the parser leaves a clean stream behind a trailer section on a
 * kept-alive connection.  http2_trailers runs the same file over h2c.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>

#include "evpl/evpl.h"
#include "evpl/evpl_http.h"

#ifndef TEST_VERSION
#define TEST_VERSION EVPL_HTTP_VERSION_HTTP1
#endif /* ifndef TEST_VERSION */

#ifndef TEST_PORT
#define TEST_PORT    8085
#endif /* ifndef TEST_PORT */

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
server_check_request_trailers(struct evpl_http_request *request)
{
    const char *value = evpl_http_request_trailer(request, "X-Req-Trailer");

    if (!value || strcmp(value, "reqval") != 0) {
        fprintf(stderr, "server: request trailer X-Req-Trailer '%s'\n",
                value ? value : "(missing)");
        exit(1);
    }

    value = evpl_http_request_trailer(request, "X-Req-Sum");

    if (!value || strcmp(value, "42") != 0) {
        fprintf(stderr, "server: request trailer X-Req-Sum '%s'\n",
                value ? value : "(missing)");
        exit(1);
    }
} /* server_check_request_trailers */

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

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:

            if (evpl_http_request_protocol(request) !=
                (TEST_VERSION == EVPL_HTTP_VERSION_HTTP2 ?
                 EVPL_HTTP_PROTOCOL_HTTP2 : EVPL_HTTP_PROTOCOL_HTTP1)) {
                fprintf(stderr, "server: unexpected request protocol\n");
                exit(1);
            }

            if (strcmp(uri, "/echo") == 0) {
                /* the chunked POST carried trailers; read them back */
                server_check_request_trailers(request);

                evpl_http_server_set_response_chunked(request);
                evpl_http_server_dispatch_default(request, 200);
            } else if (strcmp(uri, "/trailers-only") == 0) {
                /* a response that is nothing but its trailer section */
                evpl_http_server_set_response_chunked(request);

                if (evpl_http_request_add_trailer(request, "X-Only", "solo")) {
                    fprintf(stderr, "server: add_trailer refused\n");
                    exit(1);
                }

                evpl_http_request_add_datav(request, NULL, 0);
                evpl_http_server_dispatch_default(request, 200);
            } else {
                /* /length: fixed Content-Length with trailers staged */
                evpl_iovec_alloc(evpl, sizeof(response_body) - 1, 0, 1, 0, &iov);
                memcpy(iov.data, response_body, sizeof(response_body) - 1);
                iov.length = sizeof(response_body) - 1;

                evpl_http_server_set_response_length(request,
                                                     sizeof(response_body) - 1);

                if (evpl_http_request_add_trailer(request, "X-Length", "framed")) {
                    fprintf(stderr, "server: add_trailer refused\n");
                    exit(1);
                }

                evpl_http_request_add_datav(request, &iov, 1);
                evpl_http_server_dispatch_default(request, 200);
            }
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
            /* the /echo chunked response: stream the body, stage the
             * trailers, then finish -- the section must be complete before
             * the end of the content is signalled */
            evpl_iovec_alloc(evpl, sizeof(response_body) - 1, 0, 1, 0, &iov);
            memcpy(iov.data, response_body, sizeof(response_body) - 1);
            iov.length = sizeof(response_body) - 1;
            evpl_http_request_add_datav(request, &iov, 1);

            if (evpl_http_request_add_trailer(request, "X-Resp-Trailer", "respval")) {
                fprintf(stderr, "server: add_trailer refused\n");
                exit(1);
            }

            evpl_http_request_add_datav(request, NULL, 0);

            /* too late now: the message is finished */
            if (evpl_http_request_add_trailer(request, "X-Late", "no") == 0) {
                fprintf(stderr, "server: trailer accepted after finish\n");
                exit(1);
            }
            break;
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            /* A clean exchange: nothing here should ever be abandoned. */
            fprintf(stderr, "request failed unexpectedly (%d)\n",
                    evpl_http_request_status(request));
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

/* what one exchange expects of the response's trailer section */
struct trailer_expect {
    const char *name;   /* NULL: expect no trailers at all */
    const char *value;
};

struct req_ctx {
    int                          done;
    int                          status;
    int                          body_len;
    char                         body[256];
    const struct trailer_expect *expect;
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
count_trailer(
    const char *name,
    const char *value,
    void       *private_data)
{
    int *count = private_data;

    (*count)++;
} /* count_trailer */

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

            /* nothing has finished arriving yet: the section must be empty */
            if (evpl_http_request_trailer(request, "X-Resp-Trailer") ||
                evpl_http_request_trailer(request, "X-Only")) {
                fprintf(stderr, "client: trailer visible before complete\n");
                exit(1);
            }
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            client_drain(evpl, request, rc);
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
        {
            const struct trailer_expect *expect = rc->expect;
            const char                  *value;
            int                          count = 0;

            client_drain(evpl, request, rc);

            evpl_http_request_trailer_iterate(request, count_trailer, &count);

            if (expect->name) {
                value = evpl_http_request_trailer(request, expect->name);

                if (!value || strcmp(value, expect->value) != 0) {
                    fprintf(stderr, "client: %s trailer %s = '%s', wanted '%s'\n",
                            uri, expect->name,
                            value ? value : "(missing)", expect->value);
                    exit(1);
                }

                if (count != 1) {
                    fprintf(stderr, "client: %s carried %d trailers, wanted 1\n",
                            uri, count);
                    exit(1);
                }
            } else if (count != 0) {
                fprintf(stderr, "client: %s carried %d trailers, wanted none\n",
                        uri, count);
                exit(1);
            }

            rc->done = 1;
            break;
        }
        case EVPL_HTTP_NOTIFY_WANT_DATA:
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            /* A clean exchange: nothing here should ever be abandoned. */
            fprintf(stderr, "response failed unexpectedly (%d)\n",
                    evpl_http_request_status(request));
            exit(1);
    } /* switch */
} /* client_notify */

static int
do_request(
    struct evpl                 *evpl,
    struct evpl_http_conn       *conn,
    const char                  *url,
    int                          chunked_with_trailers,
    int                          expect_body,
    const struct trailer_expect *expect)
{
    struct evpl_http_request *request;
    struct req_ctx            rc;
    struct evpl_iovec         iov;
    static const char         request_body[] = "streamed";

    memset(&rc, 0, sizeof(rc));
    rc.expect = expect;

    request = evpl_http_request_create(conn,
                                       chunked_with_trailers ?
                                       EVPL_HTTP_REQUEST_TYPE_POST :
                                       EVPL_HTTP_REQUEST_TYPE_GET, url);

    evpl_http_request_add_header(request, "Host", "localhost");

    if (chunked_with_trailers) {
        evpl_http_client_set_request_chunked(request);

        evpl_iovec_alloc(evpl, sizeof(request_body) - 1, 0, 1, 0, &iov);
        memcpy(iov.data, request_body, sizeof(request_body) - 1);
        iov.length = sizeof(request_body) - 1;
        evpl_http_request_add_datav(request, &iov, 1);

        if (evpl_http_request_add_trailer(request, "X-Req-Trailer", "reqval") ||
            evpl_http_request_add_trailer(request, "X-Req-Sum", "42")) {
            fprintf(stderr, "client: add_trailer refused\n");
            return 1;
        }

        /* the grammar refusals apply to trailers as they do to headers */
        if (evpl_http_request_add_trailer(request, "bad name", "x") == 0 ||
            evpl_http_request_add_trailer(request, "X-Evil", "a\r\nb") == 0) {
            fprintf(stderr, "client: malformed trailer accepted\n");
            return 1;
        }

        evpl_http_request_add_datav(request, NULL, 0);
    } else {
        evpl_http_client_set_request_length(request, 0);
    }

    evpl_http_request_dispatch(request, client_notify, &rc);

    while (!rc.done) {
        evpl_continue(evpl);
    }

    if (rc.status != 200) {
        fprintf(stderr, "%s: bad status %d\n", url, rc.status);
        return 1;
    }

    if (expect_body) {
        if (rc.body_len != (int) (sizeof(response_body) - 1) ||
            memcmp(rc.body, response_body, rc.body_len) != 0) {
            fprintf(stderr, "%s: bad body '%.*s' (%d bytes)\n",
                    url, rc.body_len, rc.body, rc.body_len);
            return 1;
        }
    } else if (rc.body_len != 0) {
        fprintf(stderr, "%s: unexpected body (%d bytes)\n", url, rc.body_len);
        return 1;
    }

    fprintf(stderr, "%s: ok (status %d, %d bytes)\n", url, rc.status, rc.body_len);

    return 0;
} /* do_request */

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
    struct trailer_expect      expect_echo   = { "X-Resp-Trailer", "respval" };
    struct trailer_expect      expect_only   = { "X-Only", "solo" };
    struct trailer_expect      expect_length = { "X-Length", "framed" };
    struct trailer_expect      expect_none   = { NULL, NULL };
    int                        rc            = 0;

    config = evpl_global_config_init();
    evpl_init(config);

    server.run = 0;

    pthread_create(&server.thread, NULL, server_function, &server);

    while (!server.run) {
        __sync_synchronize();
    }

    evpl = evpl_create(NULL);

    agent = evpl_http_init(evpl);

    endpoint = evpl_endpoint_create("127.0.0.1", TEST_PORT);

    /* All three exchanges share one connection: the HTTP/1.x variant then
     * also proves the stream is clean behind each trailer section. */
    conn = evpl_http_client_connect(agent, EVPL_STREAM_SOCKET_TCP, endpoint,
                                    TEST_VERSION, NULL);

    rc |= do_request(evpl, conn, "/echo", 1, 1, &expect_echo);
    rc |= do_request(evpl, conn, "/trailers-only", 0, 0, &expect_only);

    /* HTTP/1.x cannot carry trailers on a Content-Length message; HTTP/2
     * carries them on any */
    rc |= do_request(evpl, conn, "/length", 0, 1,
                     TEST_VERSION == EVPL_HTTP_VERSION_HTTP2 ?
                     &expect_length : &expect_none);

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
