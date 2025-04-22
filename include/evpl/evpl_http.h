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
    void                       *private_data);

typedef void (*evpl_http_dispatch_callback_t)(
    struct evpl                 *evpl,
    struct evpl_http_agent      *agent,
    struct evpl_http_request    *request,
    evpl_http_notify_callback_t *notify_callback,
    void                        *private_data);

struct evpl_http_server *
evpl_http_listen(
    struct evpl_http_agent       *agent,
    struct evpl_endpoint         *endpoint,
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

void
evpl_http_request_add_datav(
    struct evpl_http_request *request,
    struct evpl_iovec        *iov,
    size_t                    niov);

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