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
};

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

void
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