// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * evpl_otel: oteltracing-c transport implemented over the libevpl HTTP/2
 * client.  See include/evpl/evpl_otel.h.
 *
 * The transport callback receives a complete gRPC-framed OTLP
 * ExportTraceServiceRequest from otel_drain() and POSTs it to
 *   <collector>/opentelemetry.proto.collector.trace.v1.TraceService/Export
 * over h2c.  The buffer is only borrowed for the call, so it is copied into an
 * evpl_iovec the request owns.  Note this glue is protobuf-free: oteltracing-c
 * did all the encoding.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "evpl/evpl.h"
#include "evpl/evpl_http.h"
#include "evpl/evpl_otel.h"

#include "core/macros.h"

#include "oteltracing.h"

#define OTEL_EXPORT_PATH \
    "/opentelemetry.proto.collector.trace.v1.TraceService/Export"

struct evpl_otel_exporter {
    struct evpl            *evpl;
    struct evpl_http_agent *agent;
    struct evpl_endpoint   *endpoint;
    struct evpl_http_conn  *conn;
    char                    authority[256];   /* host:port for the Host header */
};

/*
 * Per-request callback.  The OTLP gRPC response body is small (an empty/partial
 * success message); we drain and discard it.  Export failures are best-effort:
 * spans are fire-and-forget telemetry, so a bad status is dropped silently here
 * (the collector / its logs are the place to notice).
 */
static void
otel_request_notify(
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
                    evpl_iovec_release(evpl, &iov[i]);
                }
                avail = evpl_http_request_get_data_avail(request);
            }
            break;
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
        case EVPL_HTTP_NOTIFY_WANT_DATA:
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            break;
    } /* switch */
} /* otel_request_notify */

/* oteltracing-c transport hook: POST one gRPC-framed batch. */
static void
otel_http_transport(
    const void *buf,
    size_t      len,
    void       *priv)
{
    struct evpl_otel_exporter *exporter = priv;
    struct evpl_http_request  *request;
    struct evpl_iovec          iov;

    request = evpl_http_request_create(exporter->conn,
                                       EVPL_HTTP_REQUEST_TYPE_POST,
                                       OTEL_EXPORT_PATH);

    /* Host -> :authority; gRPC servers reject a request that lacks it. */
    evpl_http_request_add_header(request, "Host", exporter->authority);
    evpl_http_request_add_header(request, "content-type", "application/grpc");

    evpl_iovec_alloc(exporter->evpl, len, 0, 1, 0, &iov);
    memcpy(iov.data, buf, len);
    iov.length = len;

    evpl_http_client_set_request_length(request, len);
    evpl_http_request_add_datav(request, &iov, 1);

    evpl_http_request_dispatch(request, otel_request_notify, exporter);
} /* otel_http_transport */

SYMBOL_EXPORT struct evpl_otel_exporter *
evpl_otel_exporter_create(
    struct evpl *evpl,
    const char  *host,
    int          port)
{
    struct evpl_otel_exporter *exporter;

    exporter = calloc(1, sizeof(*exporter));

    exporter->evpl     = evpl;
    exporter->agent    = evpl_http_init(evpl);
    exporter->endpoint = evpl_endpoint_create(host, port);
    exporter->conn     = evpl_http_client_connect(exporter->agent,
                                                  EVPL_STREAM_SOCKET_TCP,
                                                  exporter->endpoint,
                                                  EVPL_HTTP_VERSION_HTTP2,
                                                  exporter);

    snprintf(exporter->authority, sizeof(exporter->authority), "%s:%d",
             host, port);

    otel_set_transport(otel_http_transport, exporter);

    return exporter;
} /* evpl_otel_exporter_create */

SYMBOL_EXPORT int
evpl_otel_exporter_flush(struct evpl_otel_exporter *exporter)
{
    return otel_drain();
} /* evpl_otel_exporter_flush */

SYMBOL_EXPORT void
evpl_otel_exporter_destroy(struct evpl_otel_exporter *exporter)
{
    otel_set_transport(NULL, NULL);

    evpl_http_client_close(exporter->agent, exporter->conn);
    evpl_http_destroy(exporter->agent);
    evpl_endpoint_close(exporter->endpoint);
    free(exporter);
} /* evpl_otel_exporter_destroy */
