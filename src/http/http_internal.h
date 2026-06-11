// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <string.h>
#include <utlist.h>

#include "core/evpl.h"
#include "evpl/evpl.h"
#include "core/iovec_ring.h"
#include "evpl/evpl_http.h"

#define evpl_http_debug(...) evpl_debug("http", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_http_info(...)  evpl_info("http", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_http_error(...) evpl_error("http", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_http_fatal(...) evpl_fatal("http", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_http_abort(...) evpl_abort("http", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_http_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "http", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_http_abort_if(cond, ...) \
        evpl_abort_if(cond, "http", __FILE__, __LINE__, __VA_ARGS__)

enum evpl_http_request_state {
    EVPL_HTTP_REQUEST_STATE_INIT,
    EVPL_HTTP_REQUEST_STATE_HEADERS,
    EVPL_HTTP_REQUEST_STATE_BODY,
    EVPL_HTTP_REQUEST_STATE_COMPLETE,
};

enum evpl_http_request_http_version {
    EVPL_HTTP_REQUEST_HTTP_VERSION_1_0,
    EVPL_HTTP_REQUEST_HTTP_VERSION_1_1,
};

enum evpl_http_request_transfer_encoding {
    EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT,
    EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED,
};

/* Protocol spoken on a connection.  UNKNOWN until decided (by ALPN on TLS or
 * the h2c client preface / requested version on TCP). */
enum evpl_http_proto {
    EVPL_HTTP_PROTO_UNKNOWN = 0,
    EVPL_HTTP_PROTO_H1,
    EVPL_HTTP_PROTO_H2,
};

struct evpl_http_request_header {
    struct evpl_http_request_header *prev;
    struct evpl_http_request_header *next;
    char                             name[256];
    char                             value[16384];
};

#define EVPL_HTTP_REQUEST_WANTS_CONTINUE    0x01
#define EVPL_HTTP_REQUEST_EXPECT_CHUNK_NL   0x02
#define EVPL_HTTP_REQUEST_RESPONSE_READY    0x04
#define EVPL_HTTP_REQUEST_RESPONSE_HDR_SENT 0x08
#define EVPL_HTTP_REQUEST_RESPONSE_FINISHED 0x10
/* Client: the request (headers + body) has been fully written to the wire and
 * is now awaiting its response. */
#define EVPL_HTTP_REQUEST_REQUEST_SENT      0x20

/* Per-stream HTTP/2 bookkeeping, embedded in every request.  Only meaningful
 * when request->conn->proto == EVPL_HTTP_PROTO_H2. */
struct evpl_http2_stream {
    int32_t stream_id;
    int     headers_submitted;  /* nghttp2_submit_response/request already done */
    int     deferred;           /* data provider returned NGHTTP2_ERR_DEFERRED  */
    int     want_data;          /* provider needs more body; fire WANT_DATA      */
    int     eof;                /* outgoing body finished (add_datav(NULL,0))    */
};

struct evpl_http_request {
    enum evpl_http_request_type              request_type;
    enum evpl_http_request_state             request_state;
    enum evpl_http_request_http_version      http_version;
    enum evpl_http_request_transfer_encoding request_transfer_encoding;
    enum evpl_http_request_transfer_encoding response_transfer_encoding;
    evpl_http_notify_callback_t              notify_callback;
    void                                    *notify_data;
    uint64_t                                 request_length;
    uint64_t                                 request_left;
    uint64_t                                 request_chunk_left;
    uint64_t                                 response_length;
    uint64_t                                 response_left;
    uint64_t                                 request_flags;
    int                                      status;
    int                                      uri_len;
    struct evpl_http_conn                   *conn;
    struct evpl_iovec_ring                   send_ring;
    struct evpl_iovec_ring                   recv_ring;
    struct evpl_http_request_header         *request_headers;
    struct evpl_http_request_header         *response_headers;
    struct evpl_http2_stream                 h2;
    struct evpl_http_request                *prev;
    struct evpl_http_request                *next;
    char                                     uri[16384];
};

struct evpl_http_conn {
    int                       is_server;
    enum evpl_http_proto proto;
    enum evpl_http_version version;        /* requested version (client) */
    int                       connected;   /* bind handshake/connect done */
    struct evpl_http_server  *server;
    struct evpl_http_agent   *agent;
    struct evpl_bind         *bind;
    struct evpl_deferral      flush;
    struct evpl_http_request *current_request;
    struct evpl_http_request *pending_requests;
    struct evpl_http2_conn   *h2;          /* NULL unless proto == H2 */
    void                     *private_data;
    /* Agent-wide live-connection list (agent->conns): every conn's bind holds
     * notify callbacks that dereference the agent, so evpl_http_destroy must
     * be able to find and retire them before the agent is freed. */
    struct evpl_http_conn    *prev;
    struct evpl_http_conn    *next;
};

struct evpl_http_server {
    struct evpl_http_agent       *agent;
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    void                         *private_data;
    evpl_http_dispatch_callback_t dispatch_callback;
};

struct evpl_http_agent {
    struct evpl_http_request        *free_requests;
    struct evpl_http_request_header *free_headers;
    struct evpl_http_conn           *conns; /* live connections; see conn */
    struct evpl                     *evpl;
};

static inline struct evpl_http_request_header *
evpl_http_request_header_alloc(struct evpl_http_agent *agent)
{
    struct evpl_http_request_header *header;

    header = agent->free_headers;

    if (header) {
        agent->free_headers = header->next;
    } else {
        header = evpl_zalloc(sizeof(*header));
    }

    return header;
} /* evpl_http_request_header_alloc */

static inline void
evpl_http_request_header_free(
    struct evpl_http_agent          *agent,
    struct evpl_http_request_header *header)
{
    LL_PREPEND(agent->free_headers, header);
} /* evpl_http_request_header_free */

static inline struct evpl_http_request *
evpl_http_request_alloc(struct evpl_http_agent *agent)
{
    struct evpl_http_request *request;

    request = agent->free_requests;

    if (request) {
        agent->free_requests = request->next;
    } else {
        request = evpl_zalloc(sizeof(*request));
        evpl_iovec_ring_alloc(&request->send_ring, 1024, 4096);
        evpl_iovec_ring_alloc(&request->recv_ring, 1024, 4096);
    }

    request->request_type               = EVPL_HTTP_REQUEST_TYPE_UNKNOWN;
    request->request_state              = EVPL_HTTP_REQUEST_STATE_INIT;
    request->http_version               = EVPL_HTTP_REQUEST_HTTP_VERSION_1_1;
    request->request_transfer_encoding  = EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT;
    request->response_transfer_encoding = EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT;
    request->request_length             = 0;
    request->request_left               = 0;
    request->request_chunk_left         = 0;
    request->response_length            = 0;
    request->response_left              = 0;
    request->request_flags              = 0;
    request->status                     = 0;
    request->uri_len                    = 0;
    request->notify_callback            = NULL;
    request->notify_data                = NULL;
    request->request_headers            = NULL;
    request->response_headers           = NULL;
    memset(&request->h2, 0, sizeof(request->h2));
    return request;
} /* evpl_http_request_alloc */

static inline void
evpl_http_request_free(
    struct evpl_http_agent   *agent,
    struct evpl_http_request *request)
{
    struct evpl_http_request_header *header;

    while (request->request_headers) {
        header = request->request_headers;
        DL_DELETE(request->request_headers, header);
        evpl_http_request_header_free(agent, header);
    }

    while (request->response_headers) {
        header = request->response_headers;
        DL_DELETE(request->response_headers, header);
        evpl_http_request_header_free(agent, header);
    }

    evpl_iovec_ring_clear(agent->evpl, &request->recv_ring);
    evpl_iovec_ring_clear(agent->evpl, &request->send_ring);

    LL_PREPEND(agent->free_requests, request);
} /* evpl_http_request_free */

static inline int
evpl_copy_string(
    char       *dst,
    const char *src,
    int         maxlen)
{
    const char *sp = src;
    char       *dp = dst;

    while (*sp) {

        if (unlikely(dp - dst >= maxlen - 1)) {
            return -1;
        }

        *dp++ = *sp++;
    }

    *dp = '\0';

    return dp - dst;
} /* evpl_copy_string */

static inline enum evpl_http_request_type
evpl_http_method_from_string(const char *token)
{
    if (strcmp(token, "GET") == 0) {
        return EVPL_HTTP_REQUEST_TYPE_GET;
    } else if (strcmp(token, "HEAD") == 0) {
        return EVPL_HTTP_REQUEST_TYPE_HEAD;
    } else if (strcmp(token, "POST") == 0) {
        return EVPL_HTTP_REQUEST_TYPE_POST;
    } else if (strcmp(token, "PUT") == 0) {
        return EVPL_HTTP_REQUEST_TYPE_PUT;
    } else if (strcmp(token, "DELETE") == 0) {
        return EVPL_HTTP_REQUEST_TYPE_DELETE;
    } else {
        return EVPL_HTTP_REQUEST_TYPE_UNKNOWN;
    }
} /* evpl_http_method_from_string */

static inline const char *
evpl_http_method_to_wire(enum evpl_http_request_type type)
{
    switch (type) {
        case EVPL_HTTP_REQUEST_TYPE_GET:
            return "GET";
        case EVPL_HTTP_REQUEST_TYPE_HEAD:
            return "HEAD";
        case EVPL_HTTP_REQUEST_TYPE_POST:
            return "POST";
        case EVPL_HTTP_REQUEST_TYPE_PUT:
            return "PUT";
        case EVPL_HTTP_REQUEST_TYPE_DELETE:
            return "DELETE";
        default:
            return "GET";
    } /* switch */
} /* evpl_http_method_to_wire */

/* Private data passed to notify/dispatch callbacks: the server's private data
 * for accepted connections, the connection's private data for clients. */
static inline void *
evpl_http_priv(struct evpl_http_conn *conn)
{
    return conn->is_server ? conn->server->private_data : conn->private_data;
} /* evpl_http_priv */

/* The single flush deferral entry point; dispatches by protocol/direction. */
void
evpl_http_flush(
    struct evpl *evpl,
    void        *arg);

#ifdef HAVE_NGHTTP2

/* HTTP/2 codec entry points (src/http/http2.c). */

void
evpl_http2_conn_init(
    struct evpl_http_conn *conn);

void
evpl_http2_conn_destroy(
    struct evpl_http_conn *conn);

void
evpl_http2_recv(
    struct evpl_http_conn *conn);

void
evpl_http2_flush(
    struct evpl *evpl,
    void        *arg);

/* Submit a request (client) or response (server) to the nghttp2 session and
 * pump.  Called when the application dispatches a request/response on an
 * already-established h2 connection. */
void
evpl_http2_dispatch(
    struct evpl_http_request *request);

/* Resume a deferred body / pump the session after the application appended more
 * body data via evpl_http_request_add_datav on an h2 connection. */
void
evpl_http2_submit(
    struct evpl_http_request *request);

#endif /* HAVE_NGHTTP2 */
