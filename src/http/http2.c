// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * HTTP/2 codec for libevpl, built on nghttp2.
 *
 * The framing, HPACK and flow control live in nghttp2; this file glues its
 * callback model onto libevpl's asynchronous bind I/O and zero-copy iovec
 * buffering.  Each HTTP/2 stream maps onto one struct evpl_http_request so the
 * same dispatch/notify lifecycle and request object are used as for HTTP/1.x.
 *
 * Buffering: nghttp2's internal allocations are routed to evpl_malloc/free via
 * nghttp2_mem.  Inbound DATA is copied once into evpl iovecs (nghttp2 owns the
 * framing buffer); outbound DATA is sent straight from the request send_ring by
 * reference (NGHTTP2_DATA_FLAG_NO_COPY + send_data callback), i.e. zero-copy.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <nghttp2/nghttp2.h>

#include "http_internal.h"

struct evpl_http2_conn {
    struct evpl_http_conn    *conn;
    nghttp2_session          *session;
    struct evpl_http_request *streams; /* live streams, DL list via prev/next */
};

/* ----- nghttp2 memory hooks -> libevpl allocator ----- */

static void *
evpl_http2_malloc(
    size_t size,
    void  *user)
{
    return evpl_malloc(size);
} /* evpl_http2_malloc */

static void
evpl_http2_free(
    void *ptr,
    void *user)
{
    if (ptr) {
        evpl_free(ptr);
    }
} /* evpl_http2_free */

static void *
evpl_http2_calloc(
    size_t nmemb,
    size_t size,
    void  *user)
{
    return evpl_calloc(nmemb, size);
} /* evpl_http2_calloc */

static void *
evpl_http2_realloc(
    void  *ptr,
    size_t size,
    void  *user)
{
    return evpl_realloc(ptr, size);
} /* evpl_http2_realloc */

static nghttp2_mem evpl_http2_mem = {
    NULL,
    evpl_http2_malloc,
    evpl_http2_free,
    evpl_http2_calloc,
    evpl_http2_realloc,
};

/* ----- helpers ----- */

static inline void
evpl_http2_lower(char *s)
{
    for (; *s; s++) {
        if (*s >= 'A' && *s <= 'Z') {
            *s += 'a' - 'A';
        }
    }
} /* evpl_http2_lower */

/* Connection-specific (hop-by-hop) header fields that are illegal in HTTP/2
 * (RFC 7540 8.1.2.2); names are compared lowercased. */
static inline int
evpl_http2_hop_by_hop(const char *name)
{
    return strcmp(name, "connection") == 0 ||
           strcmp(name, "keep-alive") == 0 ||
           strcmp(name, "proxy-connection") == 0 ||
           strcmp(name, "transfer-encoding") == 0 ||
           strcmp(name, "upgrade") == 0;
} /* evpl_http2_hop_by_hop */

static inline void
evpl_http2_notify(
    struct evpl_http_request  *request,
    enum evpl_http_notify_type type)
{
    struct evpl_http_conn *conn = request->conn;

    if (request->notify_callback) {
        request->notify_callback(conn->agent->evpl, conn->agent, request, type,
                                 request->request_type, request->uri,
                                 request->notify_data, evpl_http_priv(conn));
    }
} /* evpl_http2_notify */

/* ----- outbound DATA: zero-copy from request->send_ring ----- */

/*
 * Submit the staged trailer section as the stream's trailing HEADERS frame.
 * Called from inside the data provider once the body is done, which is the
 * pattern nghttp2 documents for trailers: the provider marks its final frame
 * NGHTTP2_DATA_FLAG_NO_END_STREAM so the END_STREAM travels on the HEADERS
 * submitted here instead.
 */
static void
evpl_http2_submit_trailers(
    nghttp2_session          *session,
    struct evpl_http_request *request)
{
    struct evpl_http_request_header *trailer;
    nghttp2_nv                       nva[64];
    size_t                           nvlen = 0;
    int                              rc;

    if (request->h2.trailers_submitted) {
        return;
    }

    request->h2.trailers_submitted = 1;

    DL_FOREACH(request->send_trailers, trailer)
    {
        evpl_http2_lower(trailer->name);

        if (nvlen >= 64) {
            break;
        }

        nva[nvlen].name     = (uint8_t *) trailer->name;
        nva[nvlen].namelen  = strlen(trailer->name);
        nva[nvlen].value    = (uint8_t *) trailer->value;
        nva[nvlen].valuelen = strlen(trailer->value);
        nva[nvlen].flags    = NGHTTP2_NV_FLAG_NONE;
        nvlen++;
    }

    rc = nghttp2_submit_trailer(session, request->h2.stream_id, nva, nvlen);

    if (rc != 0) {
        evpl_http_error("nghttp2 submit_trailer error: %s",
                        nghttp2_strerror(rc));
    }
} /* evpl_http2_submit_trailers */

static ssize_t
evpl_http2_data_read(
    nghttp2_session     *session,
    int32_t              stream_id,
    uint8_t             *buf,
    size_t               length,
    uint32_t            *data_flags,
    nghttp2_data_source *source,
    void                *user)
{
    struct evpl_http_request *request = source->ptr;
    uint64_t                  avail   = evpl_iovec_ring_bytes(&request->send_ring);
    int                       chunked = request->response_transfer_encoding ==
        EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED;
    size_t                    n;

    if (avail == 0) {
        if (request->h2.eof || (!chunked && request->response_left == 0)) {
            *data_flags |= NGHTTP2_DATA_FLAG_EOF;

            if (request->send_trailers) {
                *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
                evpl_http2_submit_trailers(session, request);
            }

            return 0;
        }

        /* No body staged yet: hold the DATA frame and request more from the
         * application.  The WANT_DATA notification (and the application's
         * resulting nghttp2_session_resume_data) must run AFTER this send
         * completes -- resuming while still inside the read callback races with
         * nghttp2 marking the stream deferred and the resume would be lost. */
        request->h2.deferred  = 1;
        request->h2.want_data = 1;
        return NGHTTP2_ERR_DEFERRED;
    }

    n = avail < length ? avail : length;

    *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;

    if ((chunked && request->h2.eof && n == avail) ||
        (!chunked && n == request->response_left)) {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;

        if (request->send_trailers) {
            *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
            evpl_http2_submit_trailers(session, request);
        }
    }

    return (ssize_t) n;
} /* evpl_http2_data_read */

static int
evpl_http2_send_data(
    nghttp2_session     *session,
    nghttp2_frame       *frame,
    const uint8_t       *framehd,
    size_t               length,
    nghttp2_data_source *source,
    void                *user)
{
    struct evpl_http_conn    *conn    = user;
    struct evpl_http_request *request = source->ptr;
    struct evpl              *evpl    = conn->agent->evpl;
    struct evpl_bind         *bind    = conn->bind;
    struct evpl_iovec         hd;
    struct evpl_iovec        *iovp;
    struct evpl_iovec         part;
    uint64_t                  left = length;

    /* 9-byte DATA frame header (we never emit padding). */
    evpl_iovec_alloc(evpl, 9, 0, 1, 0, &hd);
    memcpy(hd.data, framehd, 9);
    hd.length = 9;
    evpl_sendv(evpl, bind, &hd, 1, 9, EVPL_SEND_FLAG_TAKE_REF);

    while (left > 0) {
        iovp = evpl_iovec_ring_tail(&request->send_ring);

        if (!iovp) {
            break;
        }

        if (iovp->length <= left) {
            evpl_sendv(evpl, bind, iovp, 1, iovp->length, EVPL_SEND_FLAG_TAKE_REF);
            left -= iovp->length;
            evpl_iovec_ring_remove(&request->send_ring);
        } else {
            evpl_iovec_clone_segment(&part, iovp, 0, left);
            evpl_sendv(evpl, bind, &part, 1, left, EVPL_SEND_FLAG_TAKE_REF);
            iovp->data                += left;
            iovp->length              -= left;
            request->send_ring.length -= left;
            left                       = 0;
        }
    }

    if (request->response_transfer_encoding ==
        EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT) {
        request->response_left -= length;
    }

    return 0;
} /* evpl_http2_send_data */

/* ----- control / HEADERS frame output ----- */

static ssize_t
evpl_http2_send(
    nghttp2_session *session,
    const uint8_t   *data,
    size_t           length,
    int              flags,
    void            *user)
{
    struct evpl_http_conn *conn = user;
    struct evpl           *evpl = conn->agent->evpl;
    struct evpl_iovec      iov;

    evpl_iovec_alloc(evpl, length, 0, 1, 0, &iov);
    memcpy(iov.data, data, length);
    iov.length = length;

    evpl_sendv(evpl, conn->bind, &iov, 1, length, EVPL_SEND_FLAG_TAKE_REF);

    return (ssize_t) length;
} /* evpl_http2_send */

/* ----- inbound frame callbacks ----- */

static int
evpl_http2_on_begin_headers(
    nghttp2_session     *session,
    const nghttp2_frame *frame,
    void                *user)
{
    struct evpl_http_conn    *conn = user;
    struct evpl_http_request *request;

    if (frame->hd.type != NGHTTP2_HEADERS) {
        return 0;
    }

    /* The server allocates a request per inbound stream; on the client the
     * request already exists (created by the application and passed as
     * stream_user_data to nghttp2_submit_request). */
    if (conn->is_server && frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
        request               = evpl_http_request_alloc(conn->agent);
        request->conn         = conn;
        request->h2.stream_id = frame->hd.stream_id;

        DL_APPEND(conn->h2->streams, request);

        nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, request);
    }

    /* Decide here, once per frame, whether its fields are trailers.  An
     * HCAT_HEADERS frame is one that opens nothing: on a server every such
     * frame is the request's trailer section, and on a client it is the
     * response's -- unless the response so far is an interim 1xx, in which
     * case nghttp2 files the *final* response HEADERS in this category too,
     * and only the status already parsed before this frame tells the two
     * apart.  Deciding per frame matters for exactly that case: by the time
     * the final response's regular fields arrive, its own :status has
     * already overwritten the interim one, so a per-field test would take
     * them for trailers. */
    if (frame->headers.cat == NGHTTP2_HCAT_HEADERS) {
        request = nghttp2_session_get_stream_user_data(session,
                                                       frame->hd.stream_id);

        if (request && (conn->is_server || request->status >= 200)) {
            request->h2.in_trailers = 1;
        }
    }

    return 0;
} /* evpl_http2_on_begin_headers */

static int
evpl_http2_on_header(
    nghttp2_session     *session,
    const nghttp2_frame *frame,
    const uint8_t       *name,
    size_t               namelen,
    const uint8_t       *value,
    size_t               valuelen,
    uint8_t              flags,
    void                *user)
{
    struct evpl_http_conn           *conn = user;
    struct evpl_http_request        *request;
    struct evpl_http_request_header *header;
    int                              n;

    request = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    if (!request) {
        return 0;
    }

    if (namelen > 0 && name[0] == ':') {
        char tmp[256];

        n = valuelen < sizeof(tmp) - 1 ? (int) valuelen : (int) sizeof(tmp) - 1;

        memcpy(tmp, value, n);
        tmp[n] = '\0';

        if (conn->is_server) {
            if (namelen == 7 && memcmp(name, ":method", 7) == 0) {
                request->request_type = evpl_http_method_from_string(tmp);
            } else if (namelen == 5 && memcmp(name, ":path", 5) == 0) {
                request->uri_len = evpl_copy_string(request->uri, tmp, sizeof(request->uri));
            } else if (namelen == 10 && memcmp(name, ":authority", 10) == 0) {
                header = evpl_http_request_header_alloc(conn->agent);
                strncpy(header->name, "Host", sizeof(header->name) - 1);
                strncpy(header->value, tmp, sizeof(header->value) - 1);
                DL_APPEND(request->request_headers, header);
            }
        } else {
            if (namelen == 7 && memcmp(name, ":status", 7) == 0) {
                request->status = atoi(tmp);
            }
        }

        return 0;
    }

    header = evpl_http_request_header_alloc(conn->agent);

    n = namelen < sizeof(header->name) - 1 ? namelen : sizeof(header->name) - 1;
    memcpy(header->name, name, n);
    header->name[n] = '\0';

    n = valuelen < sizeof(header->value) - 1 ? valuelen : sizeof(header->value) - 1;
    memcpy(header->value, value, n);
    header->value[n] = '\0';

    /* Routing decided per frame in on_begin_headers -- see the comment
     * there.  Trailer fields carry no framing, so the content-length
     * bookkeeping below is for real header blocks alone. */
    if (request->h2.in_trailers) {
        DL_APPEND(request->recv_trailers, header);
        return 0;
    }

    if (conn->is_server) {
        DL_APPEND(request->request_headers, header);
    } else {
        DL_APPEND(request->response_headers, header);
    }

    /* Inbound body length (request body on the server, response body on the
    * client) is tracked via request_left for the END_STREAM bookkeeping. */
    if (strncasecmp(header->name, "content-length", 14) == 0) {
        request->request_length = strtoull(header->value, NULL, 10);
        request->request_left   = request->request_length;
    }

    return 0;
} /* evpl_http2_on_header */

static int
evpl_http2_on_frame_recv(
    nghttp2_session     *session,
    const nghttp2_frame *frame,
    void                *user)
{
    struct evpl_http_conn    *conn = user;
    struct evpl_http_request *request;

    request = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    if (!request) {
        return 0;
    }

    if (frame->hd.type == NGHTTP2_HEADERS &&
        (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)) {

        if (conn->is_server) {
            if (frame->headers.cat == NGHTTP2_HCAT_REQUEST) {
                conn->server->dispatch_callback(conn->agent->evpl, conn->agent,
                                                request, &request->notify_callback,
                                                &request->notify_data,
                                                conn->server->private_data);
            }
        } else if (!request->h2.in_trailers) {
            /* Not for a trailer frame: those end the response rather than
             * announce it, and the END_STREAM they carry is what fires
             * RECEIVE_COMPLETE below. */
            evpl_http2_notify(request, EVPL_HTTP_NOTIFY_RESPONSE_HEADERS);
        }
    }

    if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) &&
        (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        request->request_state = EVPL_HTTP_REQUEST_STATE_COMPLETE;

        /* For a client this is the terminal notification -- the response has
         * arrived, nothing more is owed.  A server's request still owes its
         * response, so its terminal point is RESPONSE_COMPLETE instead. */
        if (!conn->is_server) {
            request->h2.complete = 1;
        }

        evpl_http2_notify(request, EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE);
    }

    return 0;
} /* evpl_http2_on_frame_recv */

static int
evpl_http2_on_data_chunk(
    nghttp2_session *session,
    uint8_t          flags,
    int32_t          stream_id,
    const uint8_t   *data,
    size_t           len,
    void            *user)
{
    struct evpl_http_conn    *conn = user;
    struct evpl_http_request *request;
    struct evpl_iovec         iov;

    request = nghttp2_session_get_stream_user_data(session, stream_id);

    if (!request || len == 0) {
        /* Data for a stream nobody holds (reset locally, or already closed)
         * still occupied the connection window; with auto window updates off
         * it has to be consumed here or that share of the window is lost for
         * the connection's remaining life. */
        if (len > 0) {
            nghttp2_session_consume_connection(session, len);
        }
        return 0;
    }

    evpl_iovec_alloc(conn->agent->evpl, len, 0, 1, 0, &iov);
    memcpy(iov.data, data, len);
    iov.length = len;

    evpl_iovec_ring_add(&request->recv_ring, &iov);

    if (request->request_left >= len) {
        request->request_left -= len;
    }

    evpl_http2_notify(request, EVPL_HTTP_NOTIFY_RECEIVE_DATA);

    return 0;
} /* evpl_http2_on_data_chunk */

static int
evpl_http2_on_frame_send(
    nghttp2_session     *session,
    const nghttp2_frame *frame,
    void                *user)
{
    struct evpl_http_request *request;

    if ((frame->hd.type != NGHTTP2_HEADERS && frame->hd.type != NGHTTP2_DATA) ||
        !(frame->hd.flags & NGHTTP2_FLAG_END_STREAM)) {
        return 0;
    }

    request = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    if (request) {
        /* The local message (response on the server, request on the client) has
         * been fully transmitted.  For a server that is the terminal
         * notification -- the exchange it owed is done. */
        if (((struct evpl_http_conn *) user)->is_server) {
            request->h2.complete = 1;
        }

        evpl_http2_notify(request, EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE);
    }

    return 0;
} /* evpl_http2_on_frame_send */

static int
evpl_http2_on_stream_close(
    nghttp2_session *session,
    int32_t          stream_id,
    uint32_t         error_code,
    void            *user)
{
    struct evpl_http_conn    *conn = user;
    struct evpl_http_request *request;

    request = nghttp2_session_get_stream_user_data(session, stream_id);

    if (!request) {
        return 0;
    }

    nghttp2_session_set_stream_user_data(session, stream_id, NULL);

    DL_DELETE(conn->h2->streams, request);

    /* Whatever the application never drained still occupied the connection
     * window; give that share back before the request (and its ring) is
     * freed.  The stream's own window dies with the stream. */
    if (evpl_iovec_ring_bytes(&request->recv_ring) > 0) {
        nghttp2_session_consume_connection(session,
                                           evpl_iovec_ring_bytes(&request->recv_ring));
    }

    /* A stream that closed before the request's terminal notification fired
     * ends an exchange nobody finished: reset by the peer, refused by a
     * GOAWAY, or torn down by a protocol error.  The application holding the
     * request has to hear that it is over before the free below -- a request
     * freed behind its back leaves it waiting on a completion that can no
     * longer happen, and still holding whatever it attached.  The connection
     * itself lives on, which is what STREAM_RESET says. */
    if (!request->h2.complete && request->notify_callback) {
        request->status = EVPL_HTTP_ERROR_STREAM_RESET;
        evpl_http2_notify(request, EVPL_HTTP_NOTIFY_FAILED);
    }

    evpl_http_request_free(conn->agent, request);

    return 0;
} /* evpl_http2_on_stream_close */

/* ----- session lifecycle ----- */

void
evpl_http2_conn_init(struct evpl_http_conn *conn)
{
    struct evpl_http2_conn    *h2;
    nghttp2_session_callbacks *callbacks;
    nghttp2_option            *option;
    nghttp2_settings_entry     iv[2];
    size_t                     niv;
    unsigned int               window = conn->agent->http2_window_size;

    h2       = evpl_zalloc(sizeof(*h2));
    h2->conn = conn;
    conn->h2 = h2;

    nghttp2_session_callbacks_new(&callbacks);

    nghttp2_session_callbacks_set_send_callback(callbacks, evpl_http2_send);
    nghttp2_session_callbacks_set_send_data_callback(callbacks, evpl_http2_send_data);
    nghttp2_session_callbacks_set_on_begin_headers_callback(callbacks, evpl_http2_on_begin_headers);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, evpl_http2_on_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, evpl_http2_on_frame_recv);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, evpl_http2_on_data_chunk);
    nghttp2_session_callbacks_set_on_frame_send_callback(callbacks, evpl_http2_on_frame_send);
    nghttp2_session_callbacks_set_on_stream_close_callback(callbacks, evpl_http2_on_stream_close);

    /* Inbound flow control follows the application's consumption rather than
     * the library's arrival processing: WINDOW_UPDATE goes out as data is
     * drained through evpl_http_request_get_datav (nghttp2_session_consume),
     * so a peer can have at most a window of content in flight beyond what
     * the application has taken.  With the default auto-update the library
     * acknowledges data the moment it buffers it, and a stream fed faster
     * than its application drains buffers without bound. */
    nghttp2_option_new(&option);
    nghttp2_option_set_no_auto_window_update(option, 1);

    if (conn->is_server) {
        nghttp2_session_server_new3(&h2->session, callbacks, conn, option, &evpl_http2_mem);
    } else {
        nghttp2_session_client_new3(&h2->session, callbacks, conn, option, &evpl_http2_mem);
    }

    nghttp2_session_callbacks_del(callbacks);
    nghttp2_option_del(option);

    iv[0].settings_id = NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS;
    iv[0].value       = 100;
    niv               = 1;

    if (window) {
        iv[niv].settings_id = NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE;
        iv[niv].value       = window;
        niv++;

        /* The setting covers stream windows; the connection window (stream
         * 0) is adjusted directly, or it would stay at the 65535-byte
         * protocol default and cap all streams together. */
        nghttp2_session_set_local_window_size(h2->session, NGHTTP2_FLAG_NONE,
                                              0, (int32_t) window);
    }

    nghttp2_submit_settings(h2->session, NGHTTP2_FLAG_NONE, iv, niv);
} /* evpl_http2_conn_init */

void
evpl_http2_conn_destroy(struct evpl_http_conn *conn)
{
    struct evpl_http2_conn   *h2 = conn->h2;
    struct evpl_http_request *request;

    if (!h2) {
        return;
    }

    /* The connection is going down with these exchanges unfinished: no
     * response can arrive for a client's streams now, and a server has
     * nowhere left to send the ones it was answering.  Tell each caller so
     * before the free, exactly as the HTTP/1.x teardown does for its lists --
     * nghttp2_session_del below runs no stream-close callbacks, so this walk
     * is the only place these applications can hear it. */
    while (h2->streams) {
        request = h2->streams;
        DL_DELETE(h2->streams, request);

        if (!request->h2.complete && request->notify_callback) {
            request->status = conn->error ? conn->error :
                EVPL_HTTP_ERROR_CONN_LOST;
            evpl_http2_notify(request, EVPL_HTTP_NOTIFY_FAILED);
        }

        evpl_http_request_free(conn->agent, request);
    }

    nghttp2_session_del(h2->session);

    evpl_free(h2);
    conn->h2 = NULL;
} /* evpl_http2_conn_destroy */

void
evpl_http2_recv(struct evpl_http_conn *conn)
{
    struct evpl      *evpl = conn->agent->evpl;
    struct evpl_bind *bind = conn->bind;
    struct evpl_iovec iov[8];
    int               niov, i, length;
    ssize_t           rc;

    while (1) {
        niov = evpl_recvv(evpl, bind, iov, 8, 256 * 1024, &length);

        if (niov <= 0) {
            break;
        }

        for (i = 0; i < niov; i++) {
            rc = nghttp2_session_mem_recv(conn->h2->session, iov[i].data, iov[i].length);

            evpl_iovec_release_internal(evpl, &iov[i]);

            if (rc < 0) {
                evpl_http_error("nghttp2 recv error: %s", nghttp2_strerror((int) rc));
                evpl_close(evpl, bind);
                return;
            }
        }
    }

    evpl_http2_flush(evpl, conn);
} /* evpl_http2_recv */

void
evpl_http2_flush(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_http_conn    *conn = arg;
    struct evpl_http_request *request, *tmp;
    int                       rc;

    if (!conn->connected || !conn->h2) {
        return;
    }

    rc = nghttp2_session_send(conn->h2->session);

    if (rc != 0) {
        evpl_http_error("nghttp2 send error: %s", nghttp2_strerror(rc));
        evpl_close(evpl, conn->bind);
        return;
    }

    /* Now that the send pass has completed, ask the application to supply more
     * body for any stream whose data provider ran dry.  Doing this here (rather
     * than inside the provider callback) means the resulting
     * nghttp2_session_resume_data runs outside nghttp2_session_send. */
    DL_FOREACH_SAFE(conn->h2->streams, request, tmp)
    {
        if (request->h2.want_data) {
            request->h2.want_data = 0;
            evpl_http2_notify(request, EVPL_HTTP_NOTIFY_WANT_DATA);
        }
    }
} /* evpl_http2_flush */

/* ----- request/response submission ----- */

static void
evpl_http2_submit_response(struct evpl_http_request *request)
{
    struct evpl_http_conn           *conn = request->conn;
    struct evpl_http_request_header *header;
    nghttp2_nv                       nva[64];
    nghttp2_data_provider            prd;
    nghttp2_data_provider           *pprd;
    size_t                           nvlen = 0;
    const char                      *date;
    char                             status_str[8];
    int                              has_body;

    snprintf(status_str, sizeof(status_str), "%d", request->status);

    nva[nvlen].name     = (uint8_t *) ":status";
    nva[nvlen].namelen  = 7;
    nva[nvlen].value    = (uint8_t *) status_str;
    nva[nvlen].valuelen = strlen(status_str);
    nva[nvlen].flags    = NGHTTP2_NV_FLAG_NONE;
    nvlen++;

    /* RFC 9110 section 6.6.1 is about HTTP, not about a version of it: an
     * origin server with a clock MUST send a Date field on every response
     * outside 1xx and 5xx.  Same rule and same caveat as the HTTP/1.x path --
     * only where the application did not supply its own, since section 5.3
     * does not allow two. */
    if (!evpl_http_response_header(request, "Date")) {
        date = evpl_http_date(conn->agent);

        nva[nvlen].name     = (uint8_t *) "date";
        nva[nvlen].namelen  = 4;
        nva[nvlen].value    = (uint8_t *) date;
        nva[nvlen].valuelen = strlen(date);
        nva[nvlen].flags    = NGHTTP2_NV_FLAG_NONE;
        nvlen++;
    }

    DL_FOREACH(request->response_headers, header)
    {
        evpl_http2_lower(header->name);

        if (evpl_http2_hop_by_hop(header->name) ||
            strcmp(header->name, "content-length") == 0) {
            continue;
        }

        if (nvlen >= 64) {
            break;
        }

        nva[nvlen].name     = (uint8_t *) header->name;
        nva[nvlen].namelen  = strlen(header->name);
        nva[nvlen].value    = (uint8_t *) header->value;
        nva[nvlen].valuelen = strlen(header->value);
        nva[nvlen].flags    = NGHTTP2_NV_FLAG_NONE;
        nvlen++;
    }

    /* Staged trailers force a data provider even on a bodiless message: the
     * provider is where the trailing HEADERS is submitted, so without one the
     * initial HEADERS would carry END_STREAM and the section could never
     * follow. */
    has_body = (request->response_transfer_encoding ==
                EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED) ||
        request->response_left > 0 ||
        request->send_trailers != NULL;

    if (has_body) {
        prd.source.ptr    = request;
        prd.read_callback = evpl_http2_data_read;
        pprd              = &prd;
    } else {
        pprd = NULL;
    }

    nghttp2_submit_response(conn->h2->session, request->h2.stream_id,
                            nva, nvlen, pprd);
} /* evpl_http2_submit_response */

static void
evpl_http2_submit_request(struct evpl_http_request *request)
{
    struct evpl_http_conn           *conn = request->conn;
    struct evpl_http_request_header *header;
    nghttp2_nv                       nva[64];
    nghttp2_data_provider            prd;
    nghttp2_data_provider           *pprd;
    size_t                           nvlen = 0;
    const char                      *scheme;
    const char                      *authority = NULL;
    int                              has_body;
    int32_t                          stream_id;

    scheme = (evpl_bind_get_protocol(conn->bind) == EVPL_STREAM_SOCKET_TLS) ?
        "https" : "http";

    nva[nvlen].name     = (uint8_t *) ":method";
    nva[nvlen].namelen  = 7;
    nva[nvlen].value    = (uint8_t *) evpl_http_method_to_wire(request->request_type);
    nva[nvlen].valuelen = strlen((char *) nva[nvlen].value);
    nva[nvlen].flags    = NGHTTP2_NV_FLAG_NONE;
    nvlen++;

    nva[nvlen].name     = (uint8_t *) ":scheme";
    nva[nvlen].namelen  = 7;
    nva[nvlen].value    = (uint8_t *) scheme;
    nva[nvlen].valuelen = strlen(scheme);
    nva[nvlen].flags    = NGHTTP2_NV_FLAG_NONE;
    nvlen++;

    nva[nvlen].name     = (uint8_t *) ":path";
    nva[nvlen].namelen  = 5;
    nva[nvlen].value    = (uint8_t *) request->uri;
    nva[nvlen].valuelen = strlen(request->uri);
    nva[nvlen].flags    = NGHTTP2_NV_FLAG_NONE;
    nvlen++;

    /* HTTP/2 requires every pseudo-header (those starting with ':') to precede
     * the regular headers, so resolve Host -> :authority and emit it here,
     * before the request-header loop below.  Emitting it afterwards produces a
     * pseudo-header after a regular one, which the peer rejects (the stream is
     * reset and the request silently never arrives). */
    DL_FOREACH(request->request_headers, header)
    {
        evpl_http2_lower(header->name);

        if (strcmp(header->name, "host") == 0) {
            authority = header->value;
            break;
        }
    }

    if (authority) {
        nva[nvlen].name     = (uint8_t *) ":authority";
        nva[nvlen].namelen  = 10;
        nva[nvlen].value    = (uint8_t *) authority;
        nva[nvlen].valuelen = strlen(authority);
        nva[nvlen].flags    = NGHTTP2_NV_FLAG_NONE;
        nvlen++;
    }

    DL_FOREACH(request->request_headers, header)
    {
        evpl_http2_lower(header->name);

        if (strcmp(header->name, "host") == 0 ||
            evpl_http2_hop_by_hop(header->name) ||
            strcmp(header->name, "content-length") == 0) {
            continue;
        }

        if (nvlen >= 64) {
            break;
        }

        nva[nvlen].name     = (uint8_t *) header->name;
        nva[nvlen].namelen  = strlen(header->name);
        nva[nvlen].value    = (uint8_t *) header->value;
        nva[nvlen].valuelen = strlen(header->value);
        nva[nvlen].flags    = NGHTTP2_NV_FLAG_NONE;
        nvlen++;
    }

    /* Staged trailers force a data provider even on a bodiless message --
     * same reasoning as in evpl_http2_submit_response. */
    has_body = (request->response_transfer_encoding ==
                EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED) ||
        request->response_left > 0 ||
        request->send_trailers != NULL;

    if (has_body) {
        prd.source.ptr    = request;
        prd.read_callback = evpl_http2_data_read;
        pprd              = &prd;
    } else {
        pprd = NULL;
    }

    stream_id = nghttp2_submit_request(conn->h2->session, NULL, nva, nvlen,
                                       pprd, request);

    if (stream_id < 0) {
        evpl_http_error("nghttp2 submit_request error: %s",
                        nghttp2_strerror(stream_id));
        return;
    }

    request->h2.stream_id = stream_id;
} /* evpl_http2_submit_request */

void
evpl_http2_dispatch(struct evpl_http_request *request)
{
    struct evpl_http_conn *conn = request->conn;

    /* A body finished with add_datav(NULL, 0) before the connection had
     * settled on h2 recorded that only in the protocol-independent flag: the
     * h2 branch of add_datav was not taken because conn->proto was still
     * UNKNOWN.  Carry it over now, or the data provider waits forever for an
     * end it was already given. */
    if (request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_FINISHED) {
        request->h2.eof = 1;
    }

    if (conn->is_server) {
        evpl_http2_submit_response(request);
    } else {
        DL_APPEND(conn->h2->streams, request);
        evpl_http2_submit_request(request);
    }

    request->h2.headers_submitted = 1;

    evpl_defer(conn->agent->evpl, &conn->flush);
} /* evpl_http2_dispatch */

void
evpl_http2_submit(struct evpl_http_request *request)
{
    struct evpl_http_conn *conn = request->conn;

    if (request->h2.headers_submitted && request->h2.deferred) {
        request->h2.deferred = 0;
        nghttp2_session_resume_data(conn->h2->session, request->h2.stream_id);
    }

    evpl_defer(conn->agent->evpl, &conn->flush);
} /* evpl_http2_submit */

void
evpl_http2_consume(
    struct evpl_http_request *request,
    uint64_t                  bytes)
{
    struct evpl_http_conn *conn = request->conn;

    nghttp2_session_consume(conn->h2->session, request->h2.stream_id, bytes);

    /* the WINDOW_UPDATEs this earns go out with the next send pass */
    evpl_defer(conn->agent->evpl, &conn->flush);
} /* evpl_http2_consume */

void
evpl_http2_cancel(struct evpl_http_request *request)
{
    struct evpl_http_conn *conn = request->conn;

    nghttp2_submit_rst_stream(conn->h2->session, NGHTTP2_FLAG_NONE,
                              request->h2.stream_id, NGHTTP2_CANCEL);

    /* The request is freed when nghttp2 processes the reset and closes the
     * stream (evpl_http2_on_stream_close); its notify callback is already
     * cleared, so nothing is delivered from there. */
    evpl_defer(conn->agent->evpl, &conn->flush);
} /* evpl_http2_cancel */
