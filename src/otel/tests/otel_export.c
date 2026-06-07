// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * End-to-end transport test: emit a parent + child span through oteltracing-c,
 * ship them with the evpl_otel exporter over h2c to a libevpl HTTP/2 server, and
 * have the server reassemble the request body, strip the 5-byte gRPC frame, and
 * decode the OTLP ExportTraceServiceRequest with protobuf-c -- verifying the two
 * spans, their parent linkage, and the service name survived the wire path.
 *
 * The server runs in its own thread/event loop; the client + exporter drive the
 * main thread's loop, exactly like the http client tests.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <arpa/inet.h>

#include "evpl/evpl.h"
#include "evpl/evpl_http.h"
#include "evpl/evpl_otel.h"

#include "oteltracing.h"
#include "opentelemetry/proto/collector/trace/v1/trace_service.pb-c.h"

#define TEST_PORT 8131

/* ------------------------------------------------------------------ server */

struct test_server {
    pthread_t            thread;
    volatile int         run;
    volatile int         verified;   /* set once the OTLP body checked out */
    volatile int         failed;
    struct evpl_doorbell doorbell;
    uint8_t              body[1 << 20];
    size_t               body_len;
};

static struct test_server *g_server;

static void
server_wake(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
} /* server_wake */

#define SCHECK(cond) do {                                           \
        if (!(cond)) {                                              \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond); \
            g_server->failed = 1;                                  \
        }                                                          \
} while (0)

struct grpc_hdr {
    uint8_t  compressed;
    uint32_t length;
} __attribute__((packed));

static void
server_verify_body(void)
{
    struct test_server *s = g_server;
    struct grpc_hdr    *hdr;
    uint32_t            plen;

    SCHECK(s->body_len > sizeof(struct grpc_hdr));
    if (s->body_len <= sizeof(struct grpc_hdr)) {
        return;
    }

    hdr  = (struct grpc_hdr *) s->body;
    plen = ntohl(hdr->length);
    SCHECK(hdr->compressed == 0);
    SCHECK(plen == s->body_len - sizeof(*hdr));
    if (plen != s->body_len - sizeof(*hdr)) {
        return;
    }

    Opentelemetry__Proto__Collector__Trace__V1__ExportTraceServiceRequest *req =
        opentelemetry__proto__collector__trace__v1__export_trace_service_request__unpack(
            NULL, plen, s->body + sizeof(*hdr));
    SCHECK(req != NULL);

    if (req) {
        SCHECK(req->n_resource_spans == 1);
        Opentelemetry__Proto__Trace__V1__ResourceSpans *rs = req->resource_spans[0];
        SCHECK(rs->n_scope_spans == 1);
        Opentelemetry__Proto__Trace__V1__ScopeSpans *ss = rs->scope_spans[0];
        SCHECK(ss->n_spans == 2);

        Opentelemetry__Proto__Trace__V1__Span *parent = NULL, *child = NULL;
        for (size_t i = 0; i < ss->n_spans; i++) {
            if (strcmp(ss->spans[i]->name, "parent-op") == 0) {
                parent = ss->spans[i];
            } else if (strcmp(ss->spans[i]->name, "child-op") == 0) {
                child = ss->spans[i];
            }
        }
        SCHECK(parent && child);
        if (parent && child) {
            SCHECK(child->parent_span_id.len == 8);
            SCHECK(memcmp(child->parent_span_id.data, parent->span_id.data, 8) == 0);
            SCHECK(memcmp(child->trace_id.data, parent->trace_id.data, 16) == 0);
        }
        opentelemetry__proto__collector__trace__v1__export_trace_service_request__free_unpacked(
            req, NULL);
    }

    if (!s->failed) {
        s->verified = 1;
    }
} /* server_verify_body */

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
    struct evpl_iovec iov[8];
    uint64_t          avail;
    int               niov, i;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            avail = evpl_http_request_get_data_avail(request);
            while (avail > 0) {
                niov = evpl_http_request_get_datav(evpl, request, iov,
                                                   (int) avail);
                for (i = 0; i < niov; i++) {
                    memcpy(g_server->body + g_server->body_len,
                           iov[i].data, iov[i].length);
                    g_server->body_len += iov[i].length;
                    evpl_iovec_release(evpl, &iov[i]);
                }
                avail = evpl_http_request_get_data_avail(request);
            }

            if (notify_type == EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE) {
                server_verify_body();
                evpl_http_server_set_response_length(request, 0);
                evpl_http_server_dispatch_default(request, 200);
            }
            break;
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
        case EVPL_HTTP_NOTIFY_WANT_DATA:
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

    evpl     = evpl_create(NULL);
    evpl_add_doorbell(evpl, &server_ctx->doorbell, server_wake);
    agent    = evpl_http_init(evpl);
    endpoint = evpl_endpoint_create("0.0.0.0", TEST_PORT);
    listener = evpl_listener_create();
    server   = evpl_http_attach(agent, listener, server_dispatch, NULL);
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

int
main(
    int   argc,
    char *argv[])
{
    struct test_server         server;
    struct evpl               *evpl;
    struct evpl_global_config *config;
    struct evpl_otel_exporter *exporter;
    struct otel_span           parent, child;
    int                        i;

    memset(&server, 0, sizeof(server));
    g_server = &server;

    config = evpl_global_config_init();
    evpl_init(config);

    pthread_create(&server.thread, NULL, server_function, &server);
    while (!server.run) {
        __sync_synchronize();
    }

    evpl = evpl_create(NULL);

    /* Initialize tracing and register the transport BEFORE producing spans:
     * otel_span_start only records once a transport is live (OT.enabled). */
    otel_init("evpl-otel-test");
    exporter = evpl_otel_exporter_create(evpl, "127.0.0.1", TEST_PORT);
    otel_thread_register();

    otel_span_start(&parent, "parent-op", OTEL_SPAN_SERVER);
    otel_span_attr_str(&parent, "peer", "1.2.3.4");
    otel_span_start_child(&child, "child-op", OTEL_SPAN_INTERNAL, &parent);
    otel_span_end(&child);
    otel_span_end(&parent);

    /* flush drains the spans and POSTs them; pump the loop until the server has
     * received + verified, with a bounded guard so a failure can't hang CI. */
    evpl_otel_exporter_flush(exporter);

    for (i = 0; i < 1000000 && !server.verified && !server.failed; i++) {
        evpl_continue(evpl);
    }

    otel_thread_unregister();
    otel_shutdown();
    evpl_otel_exporter_destroy(exporter);
    evpl_destroy(evpl);

    server.run = 0;
    __sync_synchronize();
    evpl_ring_doorbell(&server.doorbell);
    pthread_join(server.thread, NULL);

    if (server.failed || !server.verified) {
        fprintf(stderr, "otel_export: FAILED (verified=%d failed=%d)\n",
                server.verified, server.failed);
        return 1;
    }

    fprintf(stderr, "otel_export: OK (2 spans exported over h2c and decoded)\n");
    return 0;
} /* main */
