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
     * a completion that can no longer happen.  On HTTP/2 it also completes a
     * request whose stream ended without it (reset by the peer, or refused by
     * a GOAWAY) while the connection lives on, and client-side it covers a
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

/*
 * HTTP/2 only: the request's stream ended without the request completing --
 * the peer reset it (a client cancelled, a server refused), or the stream was
 * refused by a GOAWAY -- while the connection itself remains usable.  Distinct
 * from CONN_LOST because nothing else on the connection is affected: other
 * requests proceed, and new ones may be dispatched.
 */
#define EVPL_HTTP_ERROR_STREAM_RESET  (-3)

/* Protocol version selection for a client connection. */
enum evpl_http_version {
    EVPL_HTTP_VERSION_AUTO,   /* HTTP/1.1, upgrading to h2 only if ALPN selects it */
    EVPL_HTTP_VERSION_HTTP1,  /* force HTTP/1.1 */
    EVPL_HTTP_VERSION_HTTP2,  /* force HTTP/2 (h2c prior-knowledge on TCP, or
                               * require "h2" via ALPN on TLS) */
};

/* The protocol a request is actually travelling over, as distinct from the
 * enum above, which is what a client asked for before the connection knew. */
enum evpl_http_protocol {
    EVPL_HTTP_PROTOCOL_HTTP1,
    EVPL_HTTP_PROTOCOL_HTTP2,
};

/*
 * Which protocol carries this request.  Meaningful from the moment the
 * request reaches the application (dispatch on a server, create on a client
 * whose connection has settled its version), for callers whose behaviour
 * depends on the transport's capabilities -- a gRPC endpoint, say, which
 * exists only over HTTP/2.
 */
enum evpl_http_protocol
evpl_http_request_protocol(
    struct evpl_http_request *request);

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
 * success, or -1 with the header not added if either:
 *
 *   - it would push the block past the configured http_max_header_size (see
 *     evpl_global_config_set_http_max_header_size), or
 *
 *   - the name is not a token (RFC 9110 section 5.1), or the value contains
 *     CR or LF, which section 5.5 calls "invalid and dangerous" and puts
 *     outside the field-value grammar.  A CRLF in a value ends the field, so
 *     everything after it would be read as further fields and then as
 *     content -- one message becoming two, the second chosen by whoever
 *     supplied the value.  Worth testing the return wherever a value comes
 *     from outside the program.
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

/*
 * Stage a trailer field on the outbound message (the response on a server
 * connection, the request on a client connection).  Trailers are fields that
 * travel after the content instead of before it (RFC 9110 section 6.5), for
 * values that are not known until the content has been produced -- a checksum,
 * a signature, a final status.
 *
 * All trailers must be staged before the end of the content is signalled with
 * evpl_http_request_add_datav(request, NULL, 0) (or, for a length-delimited
 * message, before the final bytes of the declared length are staged): the
 * trailer section travels with the last piece of the message, so a trailer
 * added after that has nothing left to travel with.  Returns -1 with the
 * trailer not added once the message is finished, and under the same two
 * refusals as evpl_http_request_add_header -- the accounting limit and the
 * field grammar.
 *
 * Where the trailer section lands depends on the message's framing, which is
 * the library's to decide:
 *
 *   - HTTP/2: a trailing HEADERS frame, on any message.
 *   - HTTP/1.x chunked: the trailer section of RFC 9112 section 7.1.2.
 *   - HTTP/1.x with a Content-Length (or close-delimited): the coding has no
 *     place for trailers, so staged ones are not sent.  A caller that needs
 *     trailers on HTTP/1.x asks for a chunked message.
 */
int
evpl_http_request_add_trailer(
    struct evpl_http_request *request,
    const char               *name,
    const char               *value);

/*
 * The value of a trailer field received from the peer (the response's trailers
 * on a client connection, the request's on a server connection), or NULL if
 * the peer sent no such trailer.  Trailers arrive with the end of the content,
 * so they are complete once EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE has fired and
 * not before.  A peer speaking HTTP/1.x only carries them on a chunked
 * message; HTTP/2 carries them on any.
 */
const char *
evpl_http_request_trailer(
    struct evpl_http_request *request,
    const char               *name);

void
evpl_http_request_trailer_iterate(
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

/*
 * Abandon a request.  The caller is declaring it is done with the exchange:
 * the request pointer is invalid once this returns, and no notification of
 * any kind follows -- not even the EVPL_HTTP_NOTIFY_FAILED the teardown
 * paths otherwise owe an abandoned request, since the caller abandoned it
 * itself.
 *
 * On HTTP/2 the request's stream is reset (RST_STREAM with CANCEL) and the
 * connection is untouched: other requests in flight proceed, and new ones
 * may be dispatched.  The peer sees the reset and completes its side of the
 * exchange with EVPL_HTTP_ERROR_STREAM_RESET.
 *
 * HTTP/1.x has no way to abandon one exchange within a connection -- the
 * only wire action that can end a message early is ending the connection --
 * so there the connection closes, and every other request outstanding on it
 * is completed with EVPL_HTTP_NOTIFY_FAILED exactly as for a connection the
 * peer closed.  A client request that was created but never dispatched is
 * simply released, on either protocol.
 */
void
evpl_http_request_cancel(
    struct evpl_http_request *request);

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

/*
 * Release a client connection.
 *
 * The connection handle belongs to the caller from evpl_http_client_connect()
 * until this is called, and stays valid even after the peer has gone away: a
 * connection that has been dropped is retired but not freed, so that the
 * pointer its owner is holding never becomes stale at a moment the owner
 * cannot observe.  Every request outstanding on it is completed with
 * EVPL_HTTP_NOTIFY_FAILED when that happens, which is how the owner learns.
 *
 * Calling this on a connection whose peer has already gone is therefore fine,
 * and is how such a connection is finally released.  Dispatching a request on
 * one is also safe: it completes immediately with EVPL_HTTP_NOTIFY_FAILED,
 * before evpl_http_request_dispatch() returns.
 *
 * The handle must not be used afterwards.
 */
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