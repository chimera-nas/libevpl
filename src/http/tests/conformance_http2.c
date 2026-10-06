// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <nghttp2/nghttp2.h>
#include "tests/test_mbt.h"
#include "evpl/evpl_http.h"
#include "http2_cases.h"
#ifdef HAVE_TLS
#include "core/tls/tls.h"
#endif /* ifdef HAVE_TLS */

/* Only the system under test uses evpl_http. The peer uses nghttp2 directly
 * to control stream resets, interim headers, DATA availability and windows.
 * Payload and callback oracles are independent of both HTTP implementations. */
#define MAX_RECORDS   512
#define WIRE_CAPACITY (2 * 1024 * 1024)
struct stream {
    struct evpl_http_request *request;
    struct h2_stream_state    model;
    int                       id, slot, serial, dispatched, upload_done, response_headers;
    int                       received_complete, sent_complete, failed, expected_error, wants, peer_done;
    int                       peer_headers, peer_probe, peer_host, peer_trailer, peer_date;
    size_t                    size, local_received, peer_received, upload_staged;
    size_t                    peer_available, peer_sent, response_staged;
    int                       peer_eof, peer_trailers_sent, upload_allowed, response_started;
    char                      uri[64];
};
static struct evpl                  *loop;
static struct evpl_http_agent       *agent;
static struct evpl_http_conn        *client_conn;
static struct evpl_http_server      *server;
static struct evpl_listener         *listener;
static struct evpl_listener_binding *binding;
static struct evpl_endpoint         *endpoint;
static struct evpl_bind             *peer_bind;
static nghttp2_session              *peer;
static struct stream                 records[MAX_RECORDS], *slots[3];
static int                           nrecords, client_role, peer_connected, settings_ack, fragmented, blocked;
static int                           port = 27000;
static size_t                        step_index, wire_length, wire_sent;
static unsigned char                 wire[WIRE_CAPACITY];

static void check_ng(int rc) { evpl_test_abort_if(rc < 0, "HTTP/2 step %zu: %s", step_index, nghttp2_strerror(rc)); }
static uint64_t
now_ms(void)
{
    struct timespec ts;

    evpl_clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
} /* now_ms */
static unsigned char
octet(
    struct stream *r,
    size_t         offset,
    int            response)
{
    return (unsigned char) (r->serial * 29 + offset * 17 + (response ? 101 : 3));
} /* octet */
static void
check_bytes(
    struct stream       *r,
    const unsigned char *data,
    size_t               length,
    size_t              *received,
    int                  response)
{
    evpl_test_abort_if(*received + length > r->size, "step %zu stream %d: excess body", step_index, r->serial);
    for (size_t i = 0; i < length; i++) {
        evpl_test_abort_if(data[i] != octet(r, *received + i, response),
                           "step %zu stream %d byte %zu: body mismatch", step_index, r->serial, *received + i);
    }
    *received += length;
} /* check_bytes */
static void
add_body(
    struct stream *r,
    size_t         offset,
    size_t         length,
    int            response)
{
    /* Unequal views cross DATA-frame boundaries and exercise both whole-iovec
     * transfer and partial-iovec cloning in the zero-copy send callback. */
    while (length) {
        struct evpl_iovec iov;
        size_t            n = length > 33001 ? 33001 : length;
        if (offset == 0 && n > 13) {
            n = 13;
        }
        evpl_test_abort_if(evpl_iovec_alloc(loop, n, 0, 1, 0, &iov) != 1 || iov.length != n, "short body allocation");
        for (size_t i = 0; i < n; i++) {
            ((unsigned char *) iov.data)[i] = octet(r, offset + i, response);
        }
        iov.length = n;
        evpl_http_request_add_datav(r->request, &iov, 1);
        offset += n; length -= n;
    }
} /* add_body */
static void
supply_upload(struct stream *r)
{
    size_t n = r->size - r->upload_staged;

    if (n > 5003) {
        n = 5003;
    }
    add_body(r, r->upload_staged, n, 0);
    r->upload_staged += n;
    if (r->upload_staged == r->size) {
        evpl_http_request_add_datav(r->request, NULL, 0);
    }
} /* supply_upload */
static void
local_notify(
    struct evpl                *evpl,
    struct evpl_http_agent     *a,
    struct evpl_http_request   *request,
    enum evpl_http_notify_type  type,
    enum evpl_http_request_type method,
    const char                 *uri,
    void                       *data,
    void                       *private_data)
{
    struct stream *r = data;

    evpl_test_abort_if(!r || r->failed, "step %zu: callback after failure", step_index);
    evpl_test_abort_if(type != EVPL_HTTP_NOTIFY_FAILED && evpl_http_request_protocol(request) !=
                       EVPL_HTTP_PROTOCOL_HTTP2,
                       "step %zu: HTTP/2 request fell back to HTTP/1", step_index);
    switch (type) {
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS: {
            int status = evpl_http_request_status(request);
            evpl_test_abort_if(!client_role || (status != 103 && status != 200), "unexpected response status %d", status
                               );
            r->response_headers++;
            if (status == 200) {
                const char *value = evpl_http_response_header(request, "X-Probe");
                evpl_test_abort_if(!value || strcmp(value, "probe"), "final header lost or treated as trailer");
                evpl_test_abort_if(evpl_http_request_trailer(request, "X-Probe"), "final header became trailer");
            }
            break;
        }
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA: {
            struct evpl_iovec iov[257];
            if (client_role) {
                evpl_test_abort_if(!r->response_headers, "DATA before response headers");
            }
            while (evpl_http_request_get_data_avail(request)) {
                int avail = evpl_http_request_get_data_avail(request);
                int n     = evpl_http_request_get_datav(evpl, request, iov, avail > 257 ? 257 : avail);
                evpl_test_abort_if(n <= 0, "receive ring made no progress");
                for (int i = 0; i < n; i++) {
                    check_bytes(r, iov[i].data, iov[i].length, &r->local_received, client_role);
                    evpl_iovec_release(evpl, &iov[i]);
                }
            }
            break;
        }
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE: {
            const char *trailer = evpl_http_request_trailer(request, "X-Trailer");
            evpl_test_abort_if(r->local_received != r->size, "stream %d: truncated body %zu/%zu", r->serial, r->
                               local_received, r->size);
            evpl_test_abort_if(r->model.trailers ? (!trailer || strcmp(trailer, "finished")) : trailer != NULL,
                               "stream %d: missing or unexpected trailer", r->serial);
            evpl_test_abort_if(++r->received_complete != 1, "duplicate receive completion");
            if (!client_role) {
                r->upload_done = 1;
            } else {
                r->request = NULL;
            }
            break;
        }
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            evpl_test_abort_if(++r->sent_complete != 1, "duplicate send completion");
            if (!client_role) {
                r->request = NULL;
            }
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
            r->wants++;
            if (client_role && r->upload_allowed && r->upload_staged < r->size) {
                supply_upload(r);
            }
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            evpl_test_abort_if((client_role ? r->received_complete : r->sent_complete) || evpl_http_request_status(
                                   request) >= 0,
                               "failure after successful completion or without error status");
            evpl_test_abort_if(r->expected_error && evpl_http_request_status(request) != r->expected_error,
                               "step %zu: failure status %d, expected %d", step_index,
                               evpl_http_request_status(request), r->expected_error);
            r->failed++; r->request = NULL;
            break;
    } /* switch */
} /* local_notify */
static struct stream *
find_uri(
    const uint8_t *uri,
    size_t         length)
{
    for (int i = 0; i < nrecords; i++) {
        if (strlen(records[i].uri) == length && !memcmp(records[i].uri, uri, length)) {
            return &records[i];
        }
    }
    evpl_test_abort("unknown stream URI");
    return NULL;
} /* find_uri */
static void
local_dispatch(
    struct evpl                 *evpl,
    struct evpl_http_agent      *a,
    struct evpl_http_request    *request,
    evpl_http_notify_callback_t *notify,
    void                       **data,
    void                        *private_data)
{
    int            length;
    const char    *uri   = evpl_http_request_url(request, &length);
    struct stream *r     = find_uri((const uint8_t *) uri, length);
    const char    *host  = evpl_http_request_header(request, "Host");
    const char    *probe = evpl_http_request_header(request, "X-Probe");

    evpl_test_abort_if(r->dispatched++ || !host || strcmp(host, "mbt.test") || !probe || strcmp(probe, "probe"),
                       "request dispatch/header mapping mismatch");
    evpl_test_abort_if(evpl_http_request_type(request) != (r->size ? EVPL_HTTP_REQUEST_TYPE_POST :
                                                           EVPL_HTTP_REQUEST_TYPE_GET),
                       "request method mismatch");
    r->request = request; *notify = local_notify; *data = r;
} /* local_dispatch */
static nghttp2_nv
nv(
    const char *name,
    const char *value)
{
    nghttp2_nv entry = { (uint8_t *) name, (uint8_t *) value, strlen(name), strlen(value), NGHTTP2_NV_FLAG_NONE };

    return entry;
} /* nv */
static ssize_t
peer_send(
    nghttp2_session *session,
    const uint8_t   *data,
    size_t           length,
    int              flags,
    void            *user)
{
    evpl_test_abort_if(wire_length + length > sizeof(wire), "peer wire queue overflow");
    memcpy(wire + wire_length, data, length); wire_length += length;
    return length;
} /* peer_send */
static ssize_t
peer_read(
    nghttp2_session     *session,
    int32_t              id,
    uint8_t             *data,
    size_t               length,
    uint32_t            *flags,
    nghttp2_data_source *source,
    void                *user)
{
    struct stream *r = source->ptr;
    size_t         n = r->peer_available - r->peer_sent;

    if (!n && !r->peer_eof) {
        return NGHTTP2_ERR_DEFERRED;
    }
    if (n > length) {
        n = length;
    }
    for (size_t i = 0; i < n; i++) {
        data[i] = octet(r, r->peer_sent + i, client_role);
    }
    r->peer_sent += n;
    if (r->peer_eof && r->peer_sent == r->peer_available) {
        *flags |= NGHTTP2_DATA_FLAG_EOF;
        if (r->model.trailers && !r->peer_trailers_sent) {
            nghttp2_nv trailer = nv("x-trailer", "finished");
            *flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
            check_ng(nghttp2_submit_trailer(session, id, &trailer, 1));
            r->peer_trailers_sent = 1;
        }
    }
    return n;
} /* peer_read */
static int
peer_header(
    nghttp2_session     *session,
    const nghttp2_frame *frame,
    const uint8_t       *name,
    size_t               namelen,
    const uint8_t       *value,
    size_t               valuelen,
    uint8_t              flags,
    void                *user)
{
    struct stream *r = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    if (namelen == 5 && !memcmp(name, ":path", 5)) {
        r = find_uri(value, valuelen); r->id = frame->hd.stream_id;
        check_ng(nghttp2_session_set_stream_user_data(session, r->id, r));
    }
    if (!r) {
        return 0;
    }
    for (size_t i = 0; i < namelen; i++) {
        evpl_test_abort_if(name[i] >= 'A' && name[i] <= 'Z', "outbound header was not lowercased");
    }
    const char *forbidden[] = { "connection", "keep-alive", "proxy-connection", "transfer-encoding", "upgrade" };
    for (size_t i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); i++) {
        evpl_test_abort_if(namelen == strlen(forbidden[i]) && !memcmp(name, forbidden[i], namelen),
                           "hop-by-hop header escaped");
    }
    if (namelen == 7 && !memcmp(name, "x-probe", 7)) {
        r->peer_probe++;
    }
    if (namelen == 10 && !memcmp(name, ":authority", 10)) {
        evpl_test_abort_if(valuelen != 8 || memcmp(value, "mbt.test", 8), "Host to authority mapping failed");
        r->peer_host++;
    }
    if (namelen == 9 && !memcmp(name, "x-trailer", 9)) {
        evpl_test_abort_if(valuelen != 8 || memcmp(value, "finished", 8), "trailer mismatch");
        r->peer_trailer++;
    }
    if (namelen == 4 && !memcmp(name, "date", 4)) {
        r->peer_date++;
    }
    return 0;
} /* peer_header */
static int
peer_data(
    nghttp2_session *session,
    uint8_t          flags,
    int32_t          id,
    const uint8_t   *data,
    size_t           length,
    void            *user)
{
    struct stream *r = nghttp2_session_get_stream_user_data(session, id);

    evpl_test_abort_if(!r, "DATA on unknown stream");
    check_bytes(r, data, length, &r->peer_received, !client_role);
    return 0;
} /* peer_data */
static int
peer_frame(
    nghttp2_session     *session,
    const nghttp2_frame *frame,
    void                *user)
{
    struct stream *r = nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    if (frame->hd.type == NGHTTP2_SETTINGS && (frame->hd.flags & NGHTTP2_FLAG_ACK)) {
        settings_ack = 1;
    }
    if (!r) {
        return 0;
    }
    if (frame->hd.type == NGHTTP2_HEADERS && frame->headers.cat != NGHTTP2_HCAT_HEADERS) {
        r->peer_headers++;
    }
    if ((frame->hd.type == NGHTTP2_HEADERS || frame->hd.type == NGHTTP2_DATA) && (frame->hd.flags &
                                                                                  NGHTTP2_FLAG_END_STREAM)) {
        evpl_test_abort_if(r->peer_received != r->size || r->peer_probe != 1 || r->peer_trailer != r->model.trailers,
                           "step %zu stream %d: peer message body/header/trailer mismatch (%zu/%zu, %d, %d/%d)",
                           step_index, r->serial, r->peer_received, r->size, r->peer_probe, r->peer_trailer, r->model.
                           trailers);
        evpl_test_abort_if(client_role ? r->peer_host != 1 : r->peer_date != 1, "authority/date mismatch");
        evpl_test_abort_if(++r->peer_done != 1, "duplicate peer message completion");
        if (client_role) {
            r->upload_done = 1;
        }
    }
    return 0;
} /* peer_frame */
static void
peer_notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *data)
{
    if (notify->notify_type == EVPL_NOTIFY_CONNECTED) {
        peer_connected = 1;
    } else if (notify->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        peer_connected = 0; peer_bind = NULL;
    } else if (notify->notify_type == EVPL_NOTIFY_RECV_DATA) {
        unsigned char buffer[65536];
        int           n;
        while ((n = evpl_recv(evpl, bind, buffer, sizeof(buffer), 0)) > 0) {
            ssize_t used = nghttp2_session_mem_recv(peer, buffer, n);
            evpl_test_abort_if(used != n, "peer receive failed: %s", nghttp2_strerror(used));
        }
    }
} /* peer_notify */
static void
peer_accept(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify,
    evpl_segment_callback_t *segment,
    void                   **data,
    void                    *arg)
{
    evpl_test_abort_if(peer_bind, "unexpected second connection");
    peer_bind = bind; *notify = peer_notify; *segment = NULL; *data = NULL;
} /* peer_accept */
static void
pump(void)
{
    evpl_continue(loop);
    if (peer && peer_connected) {
        check_ng(nghttp2_session_send(peer));
        if (wire_length) {
            size_t n = wire_length;
            if (fragmented) {
                size_t cap = wire_sent < 64 ? 7 : 4093;
                if (n > cap) {
                    n = cap;
                }
            }
            evpl_send(loop, peer_bind, wire, n);
            memmove(wire, wire + n, wire_length - n);
            wire_length -= n; wire_sent += n;
        }
    }
} /* pump */
static void
settle(void)
{
    for (int i = 0; i < 32; i++) {
        pump(); evpl_sleep_us(50);
    }
} /* settle */
static int terminal(struct stream *r) { return r->failed + (client_role ? r->received_complete : r->sent_complete); }
static size_t response_received(struct stream *r) { return client_role ? r->local_received : r->peer_received; }
static void
wait_value(
    int        *value,
    int         wanted,
    const char *what)
{
    uint64_t deadline = now_ms() + 5000;

    while (*value < wanted && now_ms() < deadline) {
        pump(); evpl_sleep_us(50);
    }
    evpl_test_abort_if(*value != wanted, "HTTP/2 step %zu: %s %d, expected %d", step_index, what, *value, wanted);
} /* wait_value */
static void
wait_body(
    struct stream *r,
    size_t         wanted)
{
    uint64_t deadline = now_ms() + 5000;

    while (response_received(r) < wanted && now_ms() < deadline) {
        pump(); evpl_sleep_us(50);
    }
    settle();
    evpl_test_abort_if(response_received(r) != wanted, "step %zu stream %d: body %zu, expected %zu", step_index, r->
                       serial, response_received(r), wanted);
} /* wait_body */
static void
wait_complete(struct stream *r)
{
    wait_value(client_role ? &r->received_complete : &r->sent_complete, 1, "terminal completion");
    wait_body(r, r->size);
    if (!client_role) {
        wait_value(&r->peer_done, 1, "peer completion");
    }
    evpl_test_abort_if(r->failed || terminal(r) != 1, "incorrect terminal callback count");
} /* wait_complete */
static void
add_headers(struct stream *r)
{
    const char *names[] = { "X-Probe", "Connection", "Keep-Alive", "Proxy-Connection", "Transfer-Encoding", "Upgrade" };

    for (size_t i = 0; i < sizeof(names) / sizeof(names[0]); i++) {
        evpl_test_abort_if(evpl_http_request_add_header(r->request, names[i], i ? "ignored" : "probe"),
                           "cannot stage header");
    }
    if (client_role) {
        evpl_test_abort_if(evpl_http_request_add_header(r->request, "Host", "mbt.test"), "cannot stage Host");
    } else if (r->model.trailers) {
        evpl_test_abort_if(evpl_http_request_add_header(r->request, "Date", "Wed, 23 Sep 2026 00:00:00 GMT"),
                           "cannot stage Date");
    }
    if (r->model.trailers) {
        evpl_test_abort_if(evpl_http_request_add_trailer(r->request, "X-Trailer", "finished"), "cannot stage trailer");
    }
} /* add_headers */
static void
cleanup(void)
{
    if (!loop) {
        return;
    }
    if (client_conn) {
        evpl_http_client_close(agent, client_conn); client_conn = NULL;
    }
    if (peer_bind) {
        evpl_close(loop, peer_bind);
    }
    settle();
    if (server) {
        evpl_http_server_destroy(agent, server);
    }
    if (binding) {
        evpl_listener_detach(loop, binding);
    }
    server                          = NULL; binding = NULL;
    evpl_http_destroy(agent); agent = NULL;
    if (listener) {
        evpl_listener_destroy(listener);
    }
    if (endpoint) {
        evpl_endpoint_close(endpoint);
    }
    listener                 = NULL; endpoint = NULL;
    evpl_destroy(loop); loop = NULL;
    if (peer) {
        nghttp2_session_del(peer);
    }
    peer = NULL; peer_bind = NULL;
} /* cleanup */
static void
connect_case(const struct h2_step *step)
{
    cleanup();
    memset(records, 0, sizeof(records)); memset(slots, 0, sizeof(slots)); nrecords = 0;
    client_role                                                                    = step->client; fragmented = step->
        fragmented; blocked                                                        = step->blocked;
    peer_connected                                                                 = settings_ack = 0; wire_length =
        wire_sent                                                                  = 0;
    struct evpl_thread_config *cfg = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(cfg, 0); loop = evpl_create(cfg); agent = evpl_http_init(loop);
    nghttp2_session_callbacks *callbacks;
    check_ng(nghttp2_session_callbacks_new(&callbacks));
    nghttp2_session_callbacks_set_send_callback(callbacks, peer_send);
    nghttp2_session_callbacks_set_on_header_callback(callbacks, peer_header);
    nghttp2_session_callbacks_set_on_frame_recv_callback(callbacks, peer_frame);
    nghttp2_session_callbacks_set_on_data_chunk_recv_callback(callbacks, peer_data);
    if (client_role) {
        check_ng(nghttp2_session_server_new(&peer, callbacks, NULL));
    } else {
        check_ng(nghttp2_session_client_new(&peer, callbacks, NULL));
    }
    nghttp2_session_callbacks_del(callbacks);
    nghttp2_settings_entry window = { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, blocked ? 0 : 65535 };
    check_ng(nghttp2_submit_settings(peer, NGHTTP2_FLAG_NONE, &window, 1));
    endpoint = evpl_endpoint_create("127.0.0.1", port++); listener = evpl_listener_create();
    if (client_role) {
        binding = evpl_listener_attach(loop, listener, peer_accept, NULL);
    } else {
        server = evpl_http_attach(agent, listener, local_dispatch, NULL);
    }
    evpl_test_abort_if(evpl_listen(listener, test_mbt_stream_protocol(), endpoint), "listen failed");
    if (client_role) {
        client_conn = evpl_http_client_connect(agent, test_mbt_stream_protocol(), endpoint, EVPL_HTTP_VERSION_HTTP2,
                                               NULL);
    } else {
        peer_bind = evpl_connect(loop, test_mbt_stream_protocol(), NULL, endpoint, peer_notify, NULL, NULL);
    }
} /* connect_case */
static void
open_stream(const struct h2_step *step)
{
    evpl_test_abort_if(nrecords >= MAX_RECORDS, "too many stream records");
    struct stream *r = &records[nrecords++];
    r->model                  = step->streams[step->slot]; r->slot =
        step->slot; r->serial = nrecords;
    r->size                   = r->model.shape == 0 ? 0 : r->model.shape
        == 1 ? 37 : 131089;
    snprintf(r->uri, sizeof(r->uri), "/stream/%d", r->serial); slots[r->slot] = r;
    if (client_role) {
        r->request = evpl_http_request_create(client_conn, r->size ? EVPL_HTTP_REQUEST_TYPE_POST :
                                              EVPL_HTTP_REQUEST_TYPE_GET, r->uri);
        evpl_test_abort_if(!r->request, "request create failed");
        add_headers(r);
        if (r->model.streaming) {
            evpl_http_client_set_request_chunked(r->request);
        } else {
            evpl_http_client_set_request_length(r->request, r->size);
        }
        if (!r->model.streaming) {
            add_body(r, 0, r->size, 0); r->upload_staged = r->size;
        }
        if (!r->size) {
            evpl_http_request_add_datav(r->request, NULL, 0);
        }
        evpl_http_request_dispatch(r->request, local_notify, r);
    } else {
        char                  length[32]; snprintf(length, sizeof(length), "%zu", r->size);
        nghttp2_nv            headers[] = { nv(":method",
                                               r->size ? "POST" :
                                               "GET"),
                                            nv(":scheme",
                                               "http"),
                                            nv(":path",
                                               r->uri),
                                            nv(":authority",
                                               "mbt.test"),
                                            nv("x-probe",
                                               "probe"),
                                            nv("content-length", length) };
        nghttp2_data_provider provider = { { .ptr = r }, peer_read };
        r->peer_available = r->size; r->peer_eof = 1;
        r->id             = nghttp2_submit_request(peer, NULL, headers, 6, (r->size || r->model.trailers) ? &provider :
                                                   NULL, r);
        check_ng(r->id);
    }
} /* open_stream */
static void
respond(struct stream *r)
{
    r->response_started = 1;
    if (client_role) {
        char                  length[32]; snprintf(length, sizeof(length), "%zu", r->size);
        nghttp2_nv            headers[] = { nv(":status", "200"), nv("x-probe", "probe"), nv("content-length", length) }
        ;
        nghttp2_data_provider provider = { { .ptr = r }, peer_read };
        check_ng(nghttp2_submit_response(peer, r->id, headers, 3, (r->size || r->model.trailers) ? &provider : NULL));
    } else {
        add_headers(r);
        if (r->model.streaming) {
            evpl_http_server_set_response_chunked(r->request);
        } else {
            evpl_http_server_set_response_length(r->request, r->size);
        }
        evpl_http_server_dispatch_default(r->request, 200);
    }
} /* respond */
static void
produce(
    struct stream *r,
    size_t         end,
    int            finish)
{
    if (client_role) {
        r->peer_available = end; r->peer_eof = finish;
        if (!r->response_started) {
            respond(r);
        } else {
            check_ng(nghttp2_session_resume_data(peer, r->id));
        }
    } else {
        if (!r->response_started) {
            respond(r);
        }
        add_body(r, r->response_staged, end - r->response_staged, 1);
        if (finish && r->model.streaming) {
            evpl_http_request_add_datav(r->request, NULL, 0);
        }
    }
    r->response_staged = end;
} /* produce */
int
main(void)
{
    struct evpl_global_config *config = evpl_global_config_init();

    test_evpl_set_core_mech(config); test_mbt_tls_config(config);
    evpl_global_config_set_buffer_size(config, 65536); evpl_init(config);
#ifdef HAVE_TLS
    const char                *alpn[] = { "h2" }; evpl_tls_set_alpn_protocols(alpn, 1);
#endif /* ifdef HAVE_TLS */
    for (step_index = 0; step_index < sizeof(h2_steps) / sizeof(h2_steps[0]); step_index++) {
        const struct h2_step *s = &h2_steps[step_index];
        struct stream        *r = slots[s->slot];
        switch (s->op) {
            case h2_Reset: cleanup(); break;
            case h2_Connect: connect_case(s); break;
            case h2_Open: open_stream(s); break;
            case h2_Upload:
                r->upload_allowed = 1;
                if (client_role && r->wants && r->upload_staged < r->size) {
                    supply_upload(r);
                }
                wait_value(&r->upload_done, 1, "request body completion");
                wait_value(&settings_ack, 1, "SETTINGS acknowledgement");
                break;
            case h2_Interim: {
                nghttp2_nv headers[] = { nv(":status", "103"), nv("x-interim", "hint") };
                check_ng(nghttp2_submit_headers(peer, NGHTTP2_FLAG_NONE, r->id, NULL, headers, 2, NULL));
                wait_value(&r->response_headers, 1, "interim response"); break;
            }
            case h2_Respond:
                /* Empty messages are dispatched at Finish: their HEADERS may
                 * themselves carry END_STREAM, so there is no partial body. */
                if (r->size) {
                    respond(r);
                    wait_value(client_role ? &r->response_headers : &r->peer_headers, s->streams[s->slot].interim ? 2 :
                               1, "response headers");
                }
                break;
            case h2_Partial:
                produce(r, r->size / 2, 0); wait_body(r, blocked ? 0 : r->size / 2); break;
            case h2_Finish:
                produce(r, r->size, 1);
                if (!blocked || !r->size) {
                    wait_complete(r);
                } else {
                    settle(); evpl_test_abort_if(terminal(r) || response_received(r), "flow-control window ignored");
                }
                break;
            case h2_Cancel:
                r->expected_error = EVPL_HTTP_ERROR_STREAM_RESET;
                check_ng(nghttp2_submit_rst_stream(peer, NGHTTP2_FLAG_NONE, r->id, NGHTTP2_CANCEL));
                wait_value(&r->failed, 1, "stream-reset failure"); settle(); break;
            case h2_Release: {
                nghttp2_settings_entry window = { NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE, 262144 };
                check_ng(nghttp2_submit_settings(peer, NGHTTP2_FLAG_NONE, &window, 1)); blocked = 0;
                for (int i = 0; i < 3; i++) {
                    if (s->streams[i].phase == 5) {
                        wait_complete(slots[i]);
                    } else if (s->streams[i].phase == 4) {
                        wait_body(slots[i], slots[i]->size / 2);
                    }
                }
                break;
            }
            case h2_Close:
            case h2_Goaway:
                for (int i = 0; i < 3; i++) {
                    if (slots[i] && !terminal(slots[i])) {
                        slots[i]->expected_error =
                            s->op == h2_Goaway ? EVPL_HTTP_ERROR_STREAM_RESET : EVPL_HTTP_ERROR_CONN_LOST;
                    }
                }
                if (s->op == h2_Goaway) {
                    check_ng(nghttp2_submit_goaway(peer, NGHTTP2_FLAG_NONE, 0, NGHTTP2_NO_ERROR, NULL, 0));
                } else if (client_role && !peer_connected) {
                    evpl_http_client_close(agent, client_conn); client_conn = NULL;
                } else if (peer_bind) {
                    evpl_close(loop, peer_bind);
                }
                for (int i = 0; i < 3; i++) {
                    if (slots[i] && s->streams[i].phase == 6 && (client_role || slots[i]->dispatched)) {
                        wait_value(&slots[i]->failed, 1, "connection failure");
                    }
                }
                settle(); break;
            default: abort();
        } /* switch */
    }
    cleanup(); evpl_cleanup();
    return 0;
} /* main */
