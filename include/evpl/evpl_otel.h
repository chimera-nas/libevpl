// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * evpl_otel -- an optional adapter that ships oteltracing-c spans to an
 * OpenTelemetry collector over OTLP/gRPC using libevpl's HTTP/2 client.
 *
 * oteltracing-c itself has no dependency on libevpl: it encodes finished spans
 * into gRPC-framed OTLP buffers and hands them to a transport callback.  This
 * adapter is that callback, implemented over evpl_http -- it is the one piece
 * that knows about both.  A different embedder could provide a different
 * transport (curl, raw sockets, a file) without changing oteltracing-c.
 *
 * The adapter is single-threaded like the rest of libevpl: create it on, and
 * flush it from, one evpl thread.  That thread becomes the sole consumer that
 * drains spans produced (lock-free) by all the threads that started them.
 */

#ifndef EVPL_OTEL_H
#define EVPL_OTEL_H

struct evpl;
struct evpl_otel_exporter;

/*
 * Create an exporter bound to `evpl`, open an h2c (cleartext HTTP/2) client
 * connection to the collector at host:port (typically 4317), and register it as
 * the oteltracing-c transport.  otel_init() must have been called first.
 * Returns NULL on failure (e.g. tracing not initialized).
 */
struct evpl_otel_exporter *
evpl_otel_exporter_create(
    struct evpl *evpl,
    const char  *host,
    int          port);

/*
 * Drain all finished spans and POST them to the collector.  Must be called on
 * the exporter's evpl thread (e.g. from an evpl loop hook or a timer).  Returns
 * the number of spans shipped.
 */
int
evpl_otel_exporter_flush(
    struct evpl_otel_exporter *exporter);

/* Close the collector connection and free the exporter. */
void
evpl_otel_exporter_destroy(
    struct evpl_otel_exporter *exporter);

#endif /* EVPL_OTEL_H */
