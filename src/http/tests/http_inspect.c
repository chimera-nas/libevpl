// SPDX-FileCopyrightText: 2026 Chimera-NAS Project Contributors
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
/*
 * Connection inspection of an HTTP server: evpl_http_server_connection_count
 * and evpl_http_visit_server_connections.
 *
 * The server runs in its own thread, and that thread is the only one allowed
 * to inspect it.  So the checks run there, from inside the request handler
 * (one connection open) and after the client has gone (none), and record what
 * they saw for the main thread to judge.  curl is the client.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evpl/evpl_platform.h"
#include <curl/curl.h>

#include "evpl/evpl.h"
#include "evpl/evpl_config.h"
#include "evpl/evpl_http.h"

#define TEST_PORT 8097

struct visit_ctx {
    unsigned int                     n;
    int                              stop;
    struct evpl_http_connection_info first;
};

struct test_server {
    evpl_native_thread_t             thread;
    volatile int                     run;
    struct evpl_doorbell             doorbell;
    struct evpl_http_server         *server;

    /* What the server thread saw. */
    unsigned int                     open_count;
    unsigned int                     visited, scanned;
    int                              truncated;
    unsigned int                     visited_limit0, scanned_limit0;
    int                              truncated_limit0;
    unsigned int                     visited_stop;
    int                              truncated_stop;
    struct evpl_http_connection_info info;
    unsigned int                     final_count;
    unsigned int                     final_visited;
};

static void
server_wake(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
} /* server_wake */

static int
visit_cb(
    const struct evpl_http_connection_info *info,
    void                                   *private_data)
{
    struct visit_ctx *v = private_data;

    if (!v->n) {
        v->first = *info;
    }

    v->n++;

    return !v->stop;
} /* visit_cb */

static void
inspect(struct test_server *ctx)
{
    struct visit_ctx v;
    int              truncated;

    ctx->open_count = evpl_http_server_connection_count(ctx->server);

    memset(&v, 0, sizeof(v));
    ctx->scanned = evpl_http_visit_server_connections(ctx->server, 16, visit_cb,
                                                      &v, &truncated);
    ctx->visited   = v.n;
    ctx->truncated = truncated;
    ctx->info      = v.first;

    memset(&v, 0, sizeof(v));
    ctx->scanned_limit0 = evpl_http_visit_server_connections(ctx->server, 0,
                                                             visit_cb, &v,
                                                             &truncated);
    ctx->visited_limit0   = v.n;
    ctx->truncated_limit0 = truncated;

    memset(&v, 0, sizeof(v));
    v.stop = 1;
    evpl_http_visit_server_connections(ctx->server, 16, visit_cb, &v, &truncated);
    ctx->visited_stop   = v.n;
    ctx->truncated_stop = truncated;
} /* inspect */

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
    struct test_server *ctx = notify_data;
    struct evpl_iovec   iov;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            inspect(ctx);

            evpl_iovec_alloc(evpl, 11, 0, 1, 0, &iov);
            memcpy(iov.data, "hello world", 11);
            iov.length = 11;
            evpl_http_server_set_response_length(request, 11);
            evpl_http_request_add_datav(request, &iov, 1);
            evpl_http_server_dispatch_default(request, 200);
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            fprintf(stderr, "request failed unexpectedly (%d)\n",
                    evpl_http_request_status(request));
            exit(1);
        default:
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
    *notify_data     = private_data;
} /* server_dispatch */

static void *
server_function(void *ptr)
{
    struct test_server        *ctx = ptr;
    struct evpl_thread_config *config;
    struct evpl_http_agent    *agent;
    struct evpl_endpoint      *endpoint;
    struct evpl_listener      *listener;
    struct evpl               *evpl;
    struct visit_ctx           v;
    int                        truncated, i;

    config = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(config, 1);
    evpl = evpl_create(config);

    evpl_add_doorbell(evpl, &ctx->doorbell, server_wake);

    agent    = evpl_http_init(evpl);
    endpoint = evpl_endpoint_create("127.0.0.1", TEST_PORT);
    listener = evpl_listener_create();

    ctx->server = evpl_http_attach(agent, listener, server_dispatch, ctx);

    if (evpl_listen(listener, EVPL_STREAM_SOCKET_TCP, endpoint)) {
        fprintf(stderr, "failed to listen\n");
        exit(1);
    }

    atomic_thread_fence(memory_order_seq_cst);

    ctx->run = 1;

    while (ctx->run) {
        evpl_continue(evpl);
    }

    /* The client closed its connection before it stopped us: once the server
     * has seen that, nothing is left to count or visit. */
    for (i = 0; i < 1000 && evpl_http_server_connection_count(ctx->server); i++) {
        evpl_continue(evpl);
    }

    ctx->final_count = evpl_http_server_connection_count(ctx->server);

    memset(&v, 0, sizeof(v));
    evpl_http_visit_server_connections(ctx->server, 16, visit_cb, &v, &truncated);
    ctx->final_visited = v.n;

    evpl_http_server_destroy(agent, ctx->server);
    evpl_http_destroy(agent);

    evpl_listener_destroy(listener);
    evpl_endpoint_close(endpoint);
    evpl_destroy(evpl);

    return NULL;
} /* server_function */

static size_t
discard_callback(
    char  *ptr,
    size_t size,
    size_t nmemb,
    void  *userdata)
{
    return size * nmemb;
} /* discard_callback */

#define EXPECT(cond, ...) \
        do { \
            if (!(cond)) { \
                fprintf(stderr, "FAILED: " __VA_ARGS__); \
                fprintf(stderr, "\n"); \
                return 1; \
            } \
        } while (0)

int
main(
    int   argc,
    char *argv[])
{
    static struct test_server server;
    CURL                     *curl;
    CURLcode                  res;
    long                      http_code = 0;

    evpl_native_thread_create(&server.thread, NULL, server_function, &server);

    while (!server.run) {
        atomic_thread_fence(memory_order_seq_cst);
    }

    curl = curl_easy_init();
    EXPECT(curl, "curl_easy_init");

    curl_easy_setopt(curl, CURLOPT_URL, "http://127.0.0.1:" "8097");
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_callback);
    curl_easy_setopt(curl, CURLOPT_POSTFIELDS, "hello world");
    curl_easy_setopt(curl, CURLOPT_POST, 1L);

    res = curl_easy_perform(curl);

    if (res == CURLE_OK) {
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_code);
    }

    curl_easy_cleanup(curl);

    server.run = 0;
    atomic_thread_fence(memory_order_seq_cst);

    evpl_ring_doorbell(&server.doorbell);

    evpl_native_thread_join(server.thread, NULL);

    EXPECT(res == CURLE_OK && http_code == 200, "request: curl %d, http %ld",
           (int) res, http_code);

    EXPECT(server.open_count == 1, "connection count %u, expected 1",
           server.open_count);
    EXPECT(server.visited == 1, "visited %u connections, expected 1",
           server.visited);
    EXPECT(server.scanned >= server.visited, "examined %u, visited %u",
           server.scanned, server.visited);
    EXPECT(!server.truncated, "a complete walk reported truncation");

    EXPECT(!strcmp(server.info.framing, "h1"), "framing '%s', expected h1",
           server.info.framing);
    EXPECT(server.info.bind.protocol == EVPL_STREAM_SOCKET_TCP, "protocol");
    EXPECT(!strcmp(server.info.bind.local.family, "ipv4") &&
           !strcmp(server.info.bind.local.address, "127.0.0.1") &&
           server.info.bind.local.port == TEST_PORT,
           "local endpoint %s %s:%d", server.info.bind.local.family,
           server.info.bind.local.address, server.info.bind.local.port);
    EXPECT(!strcmp(server.info.bind.remote.address, "127.0.0.1") &&
           server.info.bind.remote.port > 0, "remote endpoint %s:%d",
           server.info.bind.remote.address, server.info.bind.remote.port);
    EXPECT(server.info.bind.serial && server.info.bind.created_monotonic_ns &&
           !server.info.bind.closing, "bind identity");

    EXPECT(server.scanned_limit0 == 0 && server.visited_limit0 == 0,
           "limit 0 examined %u, visited %u", server.scanned_limit0,
           server.visited_limit0);
    EXPECT(server.truncated_limit0, "a walk cut by the limit did not say so");

    EXPECT(server.visited_stop == 1, "a visitor that stops saw %u connections",
           server.visited_stop);
    EXPECT(!server.truncated_stop, "stopping on the last connection reported "
           "truncation");

    EXPECT(server.final_count == 0, "connection count %u after the client left",
           server.final_count);
    EXPECT(server.final_visited == 0, "visited %u connections after the client "
           "left", server.final_visited);

    return 0;
} /* main */
