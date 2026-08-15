// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <evpl/evpl.h>

struct evpl;
struct evpl_http_agent;
struct evpl_http_request;
struct evpl_endpoint;
struct evpl_iovec;
struct evpl_http_server;
struct evpl_http_conn;

struct evpl_http_agent *
evpl_http_init(
    struct evpl *evpl);

void evpl_http_destroy(
    struct evpl_http_agent *agent);

enum evpl_http_notify_type {
    EVPL_HTTP_NOTIFY_RECEIVE_DATA,
    EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE,
    EVPL_HTTP_NOTIFY_WANT_DATA,
    EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE,
    /* Client direction only: the response status line and headers have been
     * received and may be queried (evpl_http_request_status /
     * evpl_http_response_header).  Fired before any RECEIVE_DATA. */
    EVPL_HTTP_NOTIFY_RESPONSE_HEADERS,
    /*
     * The request is over and will not complete.
     *
     * Every request still outstanding on a connection is completed with this
     * when the connection goes down, so that a caller is never left waiting on
     * a completion that can no longer happen.  Client-side it also covers a
     * response the library could not parse.
     *
     * Exactly one of RECEIVE_COMPLETE (client), RESPONSE_COMPLETE (server) or
     * FAILED reaches a given request, so this is the place to release whatever
     * the application attached to it.  evpl_http_request_status() carries the
     * reason (see EVPL_HTTP_ERROR_* below).
     *
     * The request is freed as soon as the callback returns, so nothing may
     * reference it afterwards.
     */
    EVPL_HTTP_NOTIFY_FAILED,
};

/*
 * Reasons reported through evpl_http_request_status() when a request is
 * completed by EVPL_HTTP_NOTIFY_FAILED rather than by a response.  Negative so
 * they cannot collide with an HTTP status code, which is 100..599.
 */

/*
 * The connection was lost before the request completed.  The peer may simply
 * have gone away, so a retry against it is not obviously futile.
 */
#define EVPL_HTTP_ERROR_CONN_LOST     (-1)

/*
 * Client direction: the peer's response could not be parsed -- a status line
 * that is not one, a header field that is not one, or a Content-Length that is
 * not a length.  Distinct from CONN_LOST because retrying against the same
 * peer will produce the same unparseable response.
 */
#define EVPL_HTTP_ERROR_BAD_RESPONSE  (-2)

/* Protocol version selection for a client connection. */
enum evpl_http_version {
    EVPL_HTTP_VERSION_AUTO,   /* HTTP/1.1, upgrading to h2 only if ALPN selects it */
    EVPL_HTTP_VERSION_HTTP1,  /* force HTTP/1.1 */
    EVPL_HTTP_VERSION_HTTP2,  /* force HTTP/2 (h2c prior-knowledge on TCP, or
                               * require "h2" via ALPN on TLS) */
};

enum evpl_http_request_type {
    EVPL_HTTP_REQUEST_TYPE_UNKNOWN,
    EVPL_HTTP_REQUEST_TYPE_GET,
    EVPL_HTTP_REQUEST_TYPE_HEAD,
    EVPL_HTTP_REQUEST_TYPE_POST,
    EVPL_HTTP_REQUEST_TYPE_PUT,
    EVPL_HTTP_REQUEST_TYPE_DELETE,

};

typedef void (*evpl_http_notify_callback_t)(
    struct evpl                *evpl,
    struct evpl_http_agent     *agent,
    struct evpl_http_request   *request,
    enum evpl_http_notify_type  notify_type,
    enum evpl_http_request_type request_type,
    const char                 *uri,
    void                       *notify_data,
    void                       *private_data);

typedef void (*evpl_http_dispatch_callback_t)(
    struct evpl                 *evpl,
    struct evpl_http_agent      *agent,
    struct evpl_http_request    *request,
    evpl_http_notify_callback_t *notify_callback,
    void                       **notify_data,
    void                        *private_data);

struct evpl_http_server *
evpl_http_attach(
    struct evpl_http_agent       *agent,
    struct evpl_listener         *listener,
    evpl_http_dispatch_callback_t dispatch_callback,
    void                         *private_data);

void
evpl_http_server_destroy(
    struct evpl_http_agent  *agent,
    struct evpl_http_server *server);

/*
 * Attach a header to the outbound block (request headers on a client
 * connection, response headers on a server connection).  Returns 0 on
 * success, or -1 if adding the header would push the block past the
 * configured http_max_header_size (see
 * evpl_global_config_set_http_max_header_size); the header is not added.
 */
int
evpl_http_request_add_header(
    struct evpl_http_request *request,
    const char               *name,
    const char               *value);


enum evpl_http_request_type
evpl_http_request_type(
    struct evpl_http_request *request);


const char *
evpl_http_request_type_to_string(
    struct evpl_http_request *request);

const char *
evpl_http_request_url(
    struct evpl_http_request *request,
    int                      *len);

const char *
evpl_http_request_header(
    struct evpl_http_request *request,
    const char               *name);

typedef void (*evpl_http_request_header_cb_t)(
    const char *name,
    const char *value,
    void       *private_data);

void
evpl_http_request_header_iterate(
    struct evpl_http_request     *request,
    evpl_http_request_header_cb_t callback,
    void                         *private_data);

uint64_t
evpl_http_request_get_data_avail(
    struct evpl_http_request *request);

int
evpl_http_request_get_datav(
    struct evpl              *evpl,
    struct evpl_http_request *request,
    struct evpl_iovec        *iov,
    int                       length);

void
evpl_http_request_add_datav(
    struct evpl_http_request *request,
    struct evpl_iovec        *iov,
    int                       niov);

void
evpl_http_server_set_response_length(
    struct evpl_http_request *request,
    uint64_t                  content_length);

void
evpl_http_server_set_response_chunked(
    struct evpl_http_request *request);

void
evpl_http_server_dispatch_default(
    struct evpl_http_request *request,
    int                       status);

/*
 * Client API
 *
 * The same request lifecycle and notify callbacks are used as for the server,
 * but in the response direction:
 *   EVPL_HTTP_NOTIFY_RESPONSE_HEADERS  - status + response headers received
 *   EVPL_HTTP_NOTIFY_RECEIVE_DATA      - a chunk of the response body arrived
 *   EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE  - the full response body was received
 *   EVPL_HTTP_NOTIFY_WANT_DATA         - the request body may be extended
 *   EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE - the request was fully transmitted
 */

struct evpl_http_conn *
evpl_http_client_connect(
    struct evpl_http_agent *agent,
    enum evpl_protocol_id   protocol_id,
    struct evpl_endpoint   *endpoint,
    enum evpl_http_version  version,
    void                   *private_data);

void
evpl_http_client_close(
    struct evpl_http_agent *agent,
    struct evpl_http_conn  *conn);

/*
 * Create a client request.  Returns NULL if the request line alone (method
 * plus url) cannot fit within the configured http_max_header_size.
 */
struct evpl_http_request *
evpl_http_request_create(
    struct evpl_http_conn      *conn,
    enum evpl_http_request_type method,
    const char                 *url);

void
evpl_http_client_set_request_length(
    struct evpl_http_request *request,
    uint64_t                  content_length);

void
evpl_http_client_set_request_chunked(
    struct evpl_http_request *request);

void
evpl_http_request_dispatch(
    struct evpl_http_request   *request,
    evpl_http_notify_callback_t notify_callback,
    void                       *notify_data);

/*
 * The response status, 100..599, once EVPL_HTTP_NOTIFY_RESPONSE_HEADERS has
 * fired.  On a request completed by EVPL_HTTP_NOTIFY_FAILED this carries the
 * reason instead, as one of the negative EVPL_HTTP_ERROR_* codes.
 */
int
evpl_http_request_status(
    struct evpl_http_request *request);

const char *
evpl_http_response_header(
    struct evpl_http_request *request,
    const char               *name);

void
evpl_http_response_header_iterate(
    struct evpl_http_request     *request,
    evpl_http_request_header_cb_t callback,
    void                         *private_data);