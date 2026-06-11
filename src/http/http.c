// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "http_internal.h"
#include "core/tls/tls.h"

static const char *http_version_string[] = {
    "HTTP/1.0",
    "HTTP/1.1",
};

static const char *
evpl_http_response_status_string(int status)
{
    switch (status) {
        case 100:
            return "Continue";
        case 101:
            return "Switching Protocols";
        case 200:
            return "OK";
        case 201:
            return "Created";
        case 202:
            return "Accepted";
        case 203:
            return "Non-Authoritative Information";
        case 204:
            return "No Content";
        case 205:
            return "Reset Content";
        case 206:
            return "Partial Content";
        case 300:
            return "Multiple Choices";
        case 301:
            return "Moved Permanently";
        case 302:
            return "Found";
        case 303:
            return "See Other";
        case 304:
            return "Not Modified";
        case 305:
            return "Use Proxy";
        case 307:
            return "Temporary Redirect";
        case 400:
            return "Bad Request";
        case 401:
            return "Unauthorized";
        case 402:
            return "Payment Required";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 405:
            return "Method Not Allowed";
        case 406:
            return "Not Acceptable";
        case 407:
            return "Proxy Authentication Required";
        case 408:
            return "Request Timeout";
        case 409:
            return "Conflict";
        case 410:
            return "Gone";
        case 411:
            return "Length Required";
        case 412:
            return "Precondition Failed";
        case 413:
            return "Payload Too Large";
        case 414:
            return "URI Too Long";
        case 415:
            return "Unsupported Media Type";
        case 416:
            return "Range Not Satisfiable";
        case 417:
            return "Expectation Failed";
        case 426:
            return "Upgrade Required";
        case 500:
            return "Internal Server Error";
        case 501:
            return "Not Implemented";
        case 502:
            return "Bad Gateway";
        case 503:
            return "Service Unavailable";
        case 504:
            return "Gateway Timeout";
        case 505:
            return "HTTP Version Not Supported";
        default:
            return "Unknown";
    } /* switch */
} /* evpl_http_response_status_string */

SYMBOL_EXPORT struct evpl_http_agent *
evpl_http_init(struct evpl *evpl)
{
    struct evpl_http_agent *agent;

    agent = evpl_zalloc(sizeof(*agent));

    agent->evpl = evpl;

    return agent;
} /* evpl_http_init */

SYMBOL_EXPORT void
evpl_http_destroy(struct evpl_http_agent *agent)
{
    struct evpl_http_request        *request;
    struct evpl_http_request_header *header;

    while (agent->free_headers) {
        header = agent->free_headers;
        LL_DELETE(agent->free_headers, header);
        evpl_free(header);
    }

    while (agent->free_requests) {
        request = agent->free_requests;
        LL_DELETE(agent->free_requests, request);
        evpl_iovec_ring_free(&request->send_ring);
        evpl_iovec_ring_free(&request->recv_ring);
        evpl_free(request);
    }

    evpl_free(agent);
} /* evpl_http_destroy */

static inline int
evpl_http_parse_line(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    char             *line,
    int               maxline)
{
    struct evpl_iovec iov[8];
    int               niov, i, j;
    const char       *c;
    char             *lc = line;

    niov = evpl_peekv(evpl, bind, iov, 8, maxline + 2);

    if (niov <= 0) {
        return -1;
    }

    for (i = 0; i < niov; i++) {
        c = iov[i].data;

        for (j = 0; j < iov[i].length; j++) {

            if (unlikely(lc - line >= maxline - 1)) {
                return -2;
            }

            if (*c == '\n') {

                if (unlikely(lc == line || *(lc - 1) != '\r')) {
                    return -2;
                }

                *(lc - 1) = '\0';
                evpl_consume(evpl, bind, (lc - line) + 1);
                return 0;
            }

            *lc++ = *c++;
        }
    }

    return -1;
} /* evpl_http_parse_line */

/*
 * Parse a body (Content-Length or chunked) from the wire into request->recv_ring
 * and emit RECEIVE_DATA / RECEIVE_COMPLETE notifications.  Shared by the server
 * (request body) and client (response body) HTTP/1.x paths: the only
 * differences are which list the request lives on when complete (the caller
 * handles that via the COMPLETE transition) and the private data passed to the
 * callback.  Returns 0 on success, -1 if the connection was closed.
 */
static int
evpl_http_handle_body(
    struct evpl_http_conn    *conn,
    struct evpl_http_request *request)
{
    struct evpl_http_agent *agent = conn->agent;
    struct evpl            *evpl  = agent->evpl;
    struct evpl_bind       *bind  = conn->bind;
    void                   *priv  = evpl_http_priv(conn);
    int                     rc;
    char                    line[4096];

    if (request->request_transfer_encoding == EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT) {
        int               niov;
        struct evpl_iovec iov;

        while (!evpl_iovec_ring_is_full(&request->recv_ring) && request->request_left > 0) {
            niov = evpl_recvv(evpl, bind, &iov, 1, request->request_left, NULL);

            if (niov == 0) {
                break;
            }

            request->request_left -= iov.length;

            evpl_iovec_ring_add(&request->recv_ring, &iov);
        }

        if (request->notify_callback && evpl_iovec_ring_elements(&request->recv_ring) > 0) {
            request->notify_callback(evpl, agent, request,
                                     EVPL_HTTP_NOTIFY_RECEIVE_DATA,
                                     request->request_type, request->uri,
                                     request->notify_data, priv);
        }

        if (request->request_left == 0) {
            request->request_state = EVPL_HTTP_REQUEST_STATE_COMPLETE;
        }
    } else {
        int               niov;
        uint64_t          received = 0;
        struct evpl_iovec iov;

        while (!evpl_iovec_ring_is_full(&request->recv_ring)) {

            if (request->request_chunk_left > 0) {
                niov = evpl_recvv(evpl, bind, &iov, 1, request->request_chunk_left, NULL);

                if (niov == 0) {
                    break;
                }

                request->request_chunk_left -= iov.length;
                received                    += iov.length;

                evpl_iovec_ring_add(&request->recv_ring, &iov);

            } else {

                rc = evpl_http_parse_line(evpl, bind, line, sizeof(line));

                if (unlikely(rc == -2)) {
                    evpl_close(evpl, bind);
                    return -1;
                }

                if (rc == -1) {
                    break;
                }

                if (request->request_flags & EVPL_HTTP_REQUEST_EXPECT_CHUNK_NL) {
                    if (line[0] != '\0') {
                        evpl_close(evpl, bind);
                        return -1;
                    }
                    request->request_flags &= ~EVPL_HTTP_REQUEST_EXPECT_CHUNK_NL;
                    continue;
                }

                request->request_chunk_left = strtoul(line, NULL, 16);
                request->request_flags     |= EVPL_HTTP_REQUEST_EXPECT_CHUNK_NL;

                if (request->request_chunk_left == 0) {
                    request->request_state = EVPL_HTTP_REQUEST_STATE_COMPLETE;
                    break;
                }
            }
        }

        if (request->notify_callback && received &&
            request->request_state != EVPL_HTTP_REQUEST_STATE_COMPLETE) {
            request->notify_callback(evpl, agent, request,
                                     EVPL_HTTP_NOTIFY_RECEIVE_DATA,
                                     request->request_type, request->uri,
                                     request->notify_data, priv);
        }
    }

    return 0;
} /* evpl_http_handle_body */

static void
evpl_http_server_handle_data(struct evpl_http_conn *conn)
{
    struct evpl_http_server         *server = conn->server;
    struct evpl_http_agent          *agent  = conn->agent;
    struct evpl_bind                *bind   = conn->bind;
    struct evpl_http_request        *request;
    struct evpl_http_request_header *header;
    struct evpl                     *evpl = agent->evpl;
    char                             line[4096];
    int                              rc;
    char                            *token, *saveptr;

    if (!conn->current_request) {
        conn->current_request       = evpl_http_request_alloc(agent);
        conn->current_request->conn = conn;
    }

    request = conn->current_request;

 again:

    if (request->request_state == EVPL_HTTP_REQUEST_STATE_INIT) {
        rc = evpl_http_parse_line(evpl, conn->bind, line, sizeof(line));

        if (unlikely(rc == -2)) {
            evpl_close(evpl, bind);
            return;
        }

        if (rc == -1) {
            return;
        }

        token = strtok_r(line, " \t", &saveptr);

        if (!token) {
            evpl_http_debug("missing request type");
            evpl_close(evpl, bind);
            return;
        }

        request->request_type = evpl_http_method_from_string(token);

        if (request->request_type == EVPL_HTTP_REQUEST_TYPE_UNKNOWN) {
            evpl_http_debug("unsupported request type: %s", token);
            evpl_close(evpl, bind);
            return;
        }

        token = strtok_r(NULL, " \t", &saveptr);
        if (!token) {
            evpl_http_debug("missing uri");
            evpl_close(evpl, bind);
            return;
        }

        request->uri_len = evpl_copy_string(request->uri, token, sizeof(request->uri));

        token = strtok_r(NULL, " \t", &saveptr);

        if (!token) {
            evpl_http_debug("missing http version");
            evpl_close(evpl, bind);
            return;
        }

        if (strncmp(token, "HTTP/1.1", 8) == 0) {
            request->http_version = EVPL_HTTP_REQUEST_HTTP_VERSION_1_1;
        } else if (strncmp(token, "HTTP/1.0", 8) == 0) {
            request->http_version = EVPL_HTTP_REQUEST_HTTP_VERSION_1_0;
        } else {
            evpl_http_debug("unsupported http version: %s", token);
            evpl_close(evpl, bind);
            return;
        }

        request->request_state = EVPL_HTTP_REQUEST_STATE_HEADERS;

        goto again;

    } else if (request->request_state == EVPL_HTTP_REQUEST_STATE_HEADERS) {
        rc = evpl_http_parse_line(evpl, bind, line, sizeof(line));

        if (unlikely(rc == -2)) {
            evpl_close(evpl, bind);
            return;
        }

        if (rc == -1) {
            return;
        }

        if (line[0] == '\0') {
            request->request_state = EVPL_HTTP_REQUEST_STATE_BODY;

            if (request->request_flags & EVPL_HTTP_REQUEST_WANTS_CONTINUE) {
                evpl_send(evpl, bind, "HTTP/1.1 100 Continue\r\n\r\n", 25);
            }

            server->dispatch_callback(evpl, agent, request,
                                      &request->notify_callback,
                                      &request->notify_data,
                                      server->private_data);
        } else {
            header = evpl_http_request_header_alloc(agent);

            token = strtok_r(line, ":", &saveptr);

            if (!token) {
                evpl_http_debug("malformed header line");
                evpl_close(evpl, bind);
                return;
            }

            strncpy(header->name, token, sizeof(header->name) - 1);

            token = strtok_r(NULL, "", &saveptr);

            if (!token) {
                evpl_http_debug("missing header value");
                evpl_close(evpl, bind);
                return;
            }

            while (*token == ' ') {
                token++;
            }
            strncpy(header->value, token, sizeof(header->value) - 1);

            DL_APPEND(request->request_headers, header);

            if (strncasecmp(header->name, "Content-Length", 15) == 0) {
                request->request_length = strtoul(header->value, NULL, 10);
                request->request_left   = request->request_length;
            } else if (strncasecmp(header->name, "Expect", 6) == 0) {
                if (strncasecmp(header->value, "100-continue", 13) == 0) {
                    request->request_flags |= EVPL_HTTP_REQUEST_WANTS_CONTINUE;
                }
            } else if (strncasecmp(header->name, "Transfer-Encoding", 18) == 0) {
                if (strncasecmp(header->value, "chunked", 6) == 0) {
                    request->request_transfer_encoding = EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED;
                } else {
                    evpl_http_debug("unsupported transfer encoding: '%s", header->value);
                    evpl_close(evpl, bind);
                    return;
                }
            }
        }

        goto again;

    } else if (request->request_state == EVPL_HTTP_REQUEST_STATE_BODY) {

        if (evpl_http_handle_body(conn, request) < 0) {
            return;
        }

        if (request->request_state == EVPL_HTTP_REQUEST_STATE_COMPLETE) {
            DL_APPEND(conn->pending_requests, request);
            conn->current_request = NULL;

            if (request->notify_callback) {
                request->notify_callback(evpl, agent, request,
                                         EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE,
                                         request->request_type, request->uri,
                                         request->notify_data,
                                         server->private_data);
            }
        }
    } else {
        abort();
    }
} /* evpl_http_server_handle_data */

static void
evpl_http_client_handle_data(struct evpl_http_conn *conn)
{
    struct evpl_http_agent          *agent = conn->agent;
    struct evpl                     *evpl  = agent->evpl;
    struct evpl_bind                *bind  = conn->bind;
    struct evpl_http_request        *request;
    struct evpl_http_request_header *header;
    char                             line[4096];
    int                              rc;
    char                            *token, *saveptr;

    if (!conn->current_request) {
        if (!conn->pending_requests) {
            evpl_http_debug("response data with no pending request");
            evpl_close(evpl, bind);
            return;
        }
        /* HTTP/1.x responses arrive in request order: the head of the queue. */
        conn->current_request = conn->pending_requests;
    }

    request = conn->current_request;

 again:

    if (request->request_state == EVPL_HTTP_REQUEST_STATE_INIT) {
        rc = evpl_http_parse_line(evpl, bind, line, sizeof(line));

        if (unlikely(rc == -2)) {
            evpl_close(evpl, bind);
            return;
        }

        if (rc == -1) {
            return;
        }

        token = strtok_r(line, " \t", &saveptr);

        if (!token) {
            evpl_http_debug("missing status line version");
            evpl_close(evpl, bind);
            return;
        }

        if (strncmp(token, "HTTP/1.1", 8) == 0) {
            request->http_version = EVPL_HTTP_REQUEST_HTTP_VERSION_1_1;
        } else if (strncmp(token, "HTTP/1.0", 8) == 0) {
            request->http_version = EVPL_HTTP_REQUEST_HTTP_VERSION_1_0;
        } else {
            evpl_http_debug("unsupported http version: %s", token);
            evpl_close(evpl, bind);
            return;
        }

        token = strtok_r(NULL, " \t", &saveptr);

        if (!token) {
            evpl_http_debug("missing status code");
            evpl_close(evpl, bind);
            return;
        }

        request->status        = atoi(token);
        request->request_state = EVPL_HTTP_REQUEST_STATE_HEADERS;

        goto again;

    } else if (request->request_state == EVPL_HTTP_REQUEST_STATE_HEADERS) {
        rc = evpl_http_parse_line(evpl, bind, line, sizeof(line));

        if (unlikely(rc == -2)) {
            evpl_close(evpl, bind);
            return;
        }

        if (rc == -1) {
            return;
        }

        if (line[0] == '\0') {
            request->request_state = EVPL_HTTP_REQUEST_STATE_BODY;

            if (request->notify_callback) {
                request->notify_callback(evpl, agent, request,
                                         EVPL_HTTP_NOTIFY_RESPONSE_HEADERS,
                                         request->request_type, request->uri,
                                         request->notify_data,
                                         conn->private_data);
            }

            goto again;
        } else {
            header = evpl_http_request_header_alloc(agent);

            token = strtok_r(line, ":", &saveptr);

            if (!token) {
                evpl_http_debug("malformed header line");
                evpl_close(evpl, bind);
                return;
            }

            strncpy(header->name, token, sizeof(header->name) - 1);

            token = strtok_r(NULL, "", &saveptr);

            if (!token) {
                evpl_http_debug("missing header value");
                evpl_close(evpl, bind);
                return;
            }

            while (*token == ' ') {
                token++;
            }
            strncpy(header->value, token, sizeof(header->value) - 1);

            DL_APPEND(request->response_headers, header);

            if (strncasecmp(header->name, "Content-Length", 15) == 0) {
                request->request_length = strtoul(header->value, NULL, 10);
                request->request_left   = request->request_length;
            } else if (strncasecmp(header->name, "Transfer-Encoding", 18) == 0) {
                if (strncasecmp(header->value, "chunked", 6) == 0) {
                    request->request_transfer_encoding = EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED;
                }
            }
        }

        goto again;

    } else if (request->request_state == EVPL_HTTP_REQUEST_STATE_BODY) {

        if (evpl_http_handle_body(conn, request) < 0) {
            return;
        }

        if (request->request_state == EVPL_HTTP_REQUEST_STATE_COMPLETE) {
            DL_DELETE(conn->pending_requests, request);
            conn->current_request = NULL;

            if (request->notify_callback) {
                request->notify_callback(evpl, agent, request,
                                         EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE,
                                         request->request_type, request->uri,
                                         request->notify_data,
                                         conn->private_data);
            }

            evpl_http_request_free(agent, request);
        }
    } else {
        abort();
    }
} /* evpl_http_client_handle_data */

static void
evpl_http_conn_connected(struct evpl_http_conn *conn)
{
    struct evpl          *evpl = conn->agent->evpl;
    enum evpl_protocol_id pid  = evpl_bind_get_protocol(conn->bind);

    conn->connected = 1;

    if (conn->proto == EVPL_HTTP_PROTO_UNKNOWN) {
        if (pid == EVPL_STREAM_SOCKET_TLS) {
            char alpn[16];

            evpl_tls_get_alpn(conn->bind, alpn, sizeof(alpn));

#ifdef HAVE_NGHTTP2
            if (strcmp(alpn, "h2") == 0) {
                conn->proto = EVPL_HTTP_PROTO_H2;
            } else {
                conn->proto = EVPL_HTTP_PROTO_H1;
            }
#else  /* ifdef HAVE_NGHTTP2 */
            conn->proto = EVPL_HTTP_PROTO_H1;
#endif /* ifdef HAVE_NGHTTP2 */
        } else if (!conn->is_server) {
            /* Plain TCP client: prior-knowledge selection from requested version */
#ifdef HAVE_NGHTTP2
            if (conn->version == EVPL_HTTP_VERSION_HTTP2) {
                conn->proto = EVPL_HTTP_PROTO_H2;
            } else {
                conn->proto = EVPL_HTTP_PROTO_H1;
            }
#else  /* ifdef HAVE_NGHTTP2 */
            conn->proto = EVPL_HTTP_PROTO_H1;
#endif /* ifdef HAVE_NGHTTP2 */
        }
        /* Plain TCP server: leave UNKNOWN, decided by preface sniff on first read */
    }

#ifdef HAVE_NGHTTP2
    if (conn->proto == EVPL_HTTP_PROTO_H2) {
        struct evpl_http_request *request;

        evpl_http2_conn_init(conn);

        /* Submit any requests the client queued before the connection
         * completed. */
        while ((request = conn->pending_requests) != NULL) {
            DL_DELETE(conn->pending_requests, request);
            evpl_http2_dispatch(request);
        }

        evpl_defer(evpl, &conn->flush);
        return;
    }
#endif /* ifdef HAVE_NGHTTP2 */

    if (!conn->is_server && conn->pending_requests) {
        evpl_defer(evpl, &conn->flush);
    }
} /* evpl_http_conn_connected */

#ifdef HAVE_NGHTTP2
/*
 * Detect the HTTP/2 client connection preface ("PRI * HTTP/2.0\r\n...") on a
 * plain-TCP server connection without consuming it.  Returns 1 if it is h2c, 0
 * if it is HTTP/1.x, and -1 if not enough bytes have arrived to decide yet.
 */
static int
evpl_http_sniff_h2c(struct evpl_http_conn *conn)
{
    static const char preface[] = "PRI * HTTP/2.0\r\n";
    char              buf[16];
    int               n;

    n = evpl_peek(conn->agent->evpl, conn->bind, buf, (int) sizeof(buf));

    if (n <= 0) {
        return -1;
    }

    if (memcmp(buf, preface, n < (int) sizeof(buf) ? n : (int) sizeof(buf)) != 0) {
        return 0;
    }

    if (n < (int) sizeof(buf)) {
        return -1;
    }

    return 1;
} /* evpl_http_sniff_h2c */
#endif /* ifdef HAVE_NGHTTP2 */

static void
evpl_http_event(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct evpl_http_conn *http_conn = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            evpl_http_conn_connected(http_conn);
            break;
        case EVPL_NOTIFY_DISCONNECTED:
        {
            struct evpl_http_request *request, *next;

#ifdef HAVE_NGHTTP2
            if (http_conn->proto == EVPL_HTTP_PROTO_H2) {
                evpl_http2_conn_destroy(http_conn);
            }
#endif /* ifdef HAVE_NGHTTP2 */

            /* Release any request still in flight on this connection: a
             * partially-parsed request (current_request, e.g. one allocated on
             * a final read that returned EOF) and any received requests whose
             * response has not yet completed (pending_requests). Otherwise
             * tearing down the connection leaks them. */
            if (http_conn->current_request) {
                evpl_http_request_free(http_conn->agent,
                                       http_conn->current_request);
                http_conn->current_request = NULL;
            }

            /* Walk and free the whole list directly rather than DL_DELETE per
             * element: there is no need to keep the list consistent while
             * draining it, and it avoids DL_DELETE's (head)->prev access that
             * the static analyzer cannot prove is non-NULL. */
            request                     = http_conn->pending_requests;
            http_conn->pending_requests = NULL;
            while (request) {
                next = request->next;
                evpl_http_request_free(http_conn->agent, request);
                request = next;
            }

            evpl_free(http_conn);
        }
        break;
        case EVPL_NOTIFY_RECV_DATA:

#ifdef HAVE_NGHTTP2
            if (http_conn->is_server &&
                http_conn->proto == EVPL_HTTP_PROTO_UNKNOWN) {
                int r = evpl_http_sniff_h2c(http_conn);

                if (r < 0) {
                    return; /* need more bytes to decide */
                }

                if (r) {
                    http_conn->proto     = EVPL_HTTP_PROTO_H2;
                    http_conn->connected = 1;
                    evpl_http2_conn_init(http_conn);
                } else {
                    http_conn->proto = EVPL_HTTP_PROTO_H1;
                }
            }

            if (http_conn->proto == EVPL_HTTP_PROTO_H2) {
                evpl_http2_recv(http_conn);
                break;
            }
#endif /* ifdef HAVE_NGHTTP2 */

            if (http_conn->is_server) {
                evpl_http_server_handle_data(http_conn);
            } else {
                evpl_http_client_handle_data(http_conn);
            }
            break;
        default:
            evpl_http_error("http unhandled event");
            abort();
    } /* switch */

} /* evpl_http_event */

static void
evpl_http_server_send_headers(
    struct evpl              *evpl,
    struct evpl_http_request *request)
{
    struct evpl_http_conn           *conn = request->conn;
    struct evpl_bind                *bind = conn->bind;
    struct evpl_http_request_header *header;
    struct evpl_iovec                iov;
    int                              niov;
    char                            *rsp_base, *rsp;

    niov = evpl_iovec_alloc(evpl, 4096, 4096, 1, 0, &iov);

    evpl_http_abort_if(niov < 0, "failed to allocate iovec");

    rsp_base = iov.data;
    rsp      = rsp_base;

    rsp += snprintf(rsp, 4096, "%s %d %s\r\n",
                    http_version_string[request->http_version],
                    request->status,
                    evpl_http_response_status_string(request->status));

    DL_FOREACH(request->response_headers, header)
    {
        rsp += snprintf(rsp, 4096 - (rsp - rsp_base), "%s: %s\r\n", header->name, header->value);
    }

    if (request->response_transfer_encoding == EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT) {
        rsp += snprintf(rsp, 4096 - (rsp - rsp_base), "Content-Length: %lu\r\n", request->response_length);
    } else {
        rsp += snprintf(rsp, 4096 - (rsp - rsp_base), "Transfer-Encoding: chunked\r\n");
    }

    rsp +=  snprintf(rsp, 4096 - (rsp - rsp_base), "\r\n");

    iov.length = rsp - rsp_base;

    evpl_sendv(evpl, bind, &iov, 1, iov.length, EVPL_SEND_FLAG_TAKE_REF);
} /* evpl_http_server_send_headers */

static void
evpl_http_client_send_headers(
    struct evpl              *evpl,
    struct evpl_http_request *request)
{
    struct evpl_http_conn           *conn = request->conn;
    struct evpl_bind                *bind = conn->bind;
    struct evpl_http_request_header *header;
    struct evpl_iovec                iov;
    int                              niov;
    char                            *rsp_base, *rsp;

    niov = evpl_iovec_alloc(evpl, 4096, 4096, 1, 0, &iov);

    evpl_http_abort_if(niov < 0, "failed to allocate iovec");

    rsp_base = iov.data;
    rsp      = rsp_base;

    rsp += snprintf(rsp, 4096, "%s %s HTTP/1.1\r\n",
                    evpl_http_method_to_wire(request->request_type),
                    request->uri);

    DL_FOREACH(request->request_headers, header)
    {
        rsp += snprintf(rsp, 4096 - (rsp - rsp_base), "%s: %s\r\n", header->name, header->value);
    }

    if (request->response_transfer_encoding == EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED) {
        rsp += snprintf(rsp, 4096 - (rsp - rsp_base), "Transfer-Encoding: chunked\r\n");
    } else {
        rsp += snprintf(rsp, 4096 - (rsp - rsp_base), "Content-Length: %lu\r\n", request->response_length);
    }

    rsp += snprintf(rsp, 4096 - (rsp - rsp_base), "\r\n");

    iov.length = rsp - rsp_base;

    evpl_sendv(evpl, bind, &iov, 1, iov.length, EVPL_SEND_FLAG_TAKE_REF);
} /* evpl_http_client_send_headers */

/*
 * Send the body staged in request->send_ring to the wire, honoring the
 * configured transfer encoding.  Shared by the server (response body) and
 * client (request body) HTTP/1.x paths.  Returns 1 if the body has been fully
 * sent, 0 if more data is needed (a WANT_DATA notification was emitted).
 */
static int
evpl_http_send_body(
    struct evpl              *evpl,
    struct evpl_http_request *request)
{
    struct evpl_http_conn *conn = request->conn;
    struct evpl_bind      *bind = conn->bind;
    struct evpl_iovec     *iovp;
    struct evpl_iovec      iov;
    uint64_t               chunk_length;
    int                    chunk_hdr_len, niov;

    if (request->response_transfer_encoding == EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT) {

        while (request->response_left && !evpl_iovec_ring_is_empty(&request->send_ring)) {
            iovp = evpl_iovec_ring_tail(&request->send_ring);
            evpl_sendv(evpl, bind, iovp, 1, iovp->length, EVPL_SEND_FLAG_TAKE_REF);

            request->response_left -= iovp->length;
            evpl_iovec_ring_remove(&request->send_ring);
        }

        return request->response_left == 0;
    } else {

        chunk_length = evpl_iovec_ring_bytes(&request->send_ring);

        if (chunk_length) {

            niov = evpl_iovec_alloc(evpl, 64, 0, 1, 0, &iov);

            chunk_hdr_len = snprintf(iov.data, 64, "%lx\r\n", chunk_length);

            evpl_http_abort_if(niov < 0, "failed to allocate iovec");

            evpl_sendv(evpl, bind, &iov, 1, chunk_hdr_len, EVPL_SEND_FLAG_TAKE_REF);

            while (!evpl_iovec_ring_is_empty(&request->send_ring)) {
                iovp = evpl_iovec_ring_tail(&request->send_ring);
                evpl_sendv(evpl, bind, iovp, 1, iovp->length, EVPL_SEND_FLAG_TAKE_REF);
                evpl_iovec_ring_remove(&request->send_ring);
            }

            niov = evpl_iovec_alloc(evpl, 2, 0, 1, 0, &iov);

            evpl_http_abort_if(niov < 0, "failed to allocate iovec");

            ((char *) iov.data)[0] = '\r';
            ((char *) iov.data)[1] = '\n';

            evpl_sendv(evpl, bind, &iov, 1, 2, EVPL_SEND_FLAG_TAKE_REF);
        }

        if (request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_FINISHED) {
            niov = evpl_iovec_alloc(evpl, 5, 0, 1, 0, &iov);

            evpl_http_abort_if(niov < 0, "failed to allocate iovec");

            ((char *) iov.data)[0] = '0';
            ((char *) iov.data)[1] = '\r';
            ((char *) iov.data)[2] = '\n';
            ((char *) iov.data)[3] = '\r';
            ((char *) iov.data)[4] = '\n';

            evpl_sendv(evpl, bind, &iov, 1, 5, EVPL_SEND_FLAG_TAKE_REF);

            return 1;
        }

        return 0;
    }
} /* evpl_http_send_body */

static void
evpl_http_server_flush(
    struct evpl           *evpl,
    struct evpl_http_conn *conn)
{
    struct evpl_http_agent   *agent  = conn->agent;
    struct evpl_http_server  *server = conn->server;
    struct evpl_http_request *request, *tmp;
    int                       done;

    DL_FOREACH_SAFE(conn->pending_requests, request, tmp)
    {

        if (!(request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_READY)) {
            break;
        }

        if (!(request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_HDR_SENT)) {
            evpl_http_server_send_headers(evpl, request);
            request->request_flags |= EVPL_HTTP_REQUEST_RESPONSE_HDR_SENT;
        }

        done = evpl_http_send_body(evpl, request);

        if (done) {
            request->notify_callback(evpl, agent, request,
                                     EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE,
                                     request->request_type, request->uri,
                                     request->notify_data, server->private_data);
#ifdef __clang_analyzer__
            /* DL_DELETE asserts head != NULL but NDEBUG strips it
             * in Release builds; guide the analyzer explicitly */
            if (!conn->pending_requests) {
                return;
            }
#endif /* ifdef __clang_analyzer__ */
            DL_DELETE(conn->pending_requests, request);
            evpl_http_request_free(conn->agent, request);
        } else {
            request->notify_callback(evpl, agent, request,
                                     EVPL_HTTP_NOTIFY_WANT_DATA,
                                     request->request_type, request->uri,
                                     request->notify_data, server->private_data);
            break;
        }
    }
} /* evpl_http_server_flush */

static void
evpl_http_client_flush(
    struct evpl           *evpl,
    struct evpl_http_conn *conn)
{
    struct evpl_http_agent   *agent = conn->agent;
    struct evpl_http_request *request, *tmp;
    int                       done;

    if (!conn->connected) {
        return;
    }

    DL_FOREACH_SAFE(conn->pending_requests, request, tmp)
    {

        if (request->request_flags & EVPL_HTTP_REQUEST_REQUEST_SENT) {
            continue;
        }

        if (!(request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_READY)) {
            break;
        }

        if (!(request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_HDR_SENT)) {
            evpl_http_client_send_headers(evpl, request);
            request->request_flags |= EVPL_HTTP_REQUEST_RESPONSE_HDR_SENT;
        }

        done = evpl_http_send_body(evpl, request);

        if (done) {
            request->request_flags |= EVPL_HTTP_REQUEST_REQUEST_SENT;

            if (request->notify_callback) {
                request->notify_callback(evpl, agent, request,
                                         EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE,
                                         request->request_type, request->uri,
                                         request->notify_data, conn->private_data);
            }
            /* Stays on pending_requests as the await-response FIFO. */
        } else {
            if (request->notify_callback) {
                request->notify_callback(evpl, agent, request,
                                         EVPL_HTTP_NOTIFY_WANT_DATA,
                                         request->request_type, request->uri,
                                         request->notify_data, conn->private_data);
            }
            break;
        }
    }
} /* evpl_http_client_flush */

void
evpl_http_flush(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_http_conn *conn = arg;

#ifdef HAVE_NGHTTP2
    if (conn->proto == EVPL_HTTP_PROTO_H2) {
        evpl_http2_flush(evpl, conn);
        return;
    }
#endif /* ifdef HAVE_NGHTTP2 */

    if (conn->is_server) {
        evpl_http_server_flush(evpl, conn);
    } else {
        evpl_http_client_flush(evpl, conn);
    }
} /* evpl_http_flush */

static void
evpl_http_accept(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    struct evpl_http_server *server = private_data;
    struct evpl_http_conn   *http_conn;

    http_conn            = evpl_zalloc(sizeof(*http_conn));
    http_conn->server    = server;
    http_conn->is_server = 1;
    http_conn->proto     = EVPL_HTTP_PROTO_UNKNOWN;
    http_conn->connected = 1;
    http_conn->agent     = server->agent;
    http_conn->bind      = bind;
    *notify_callback     = evpl_http_event;
    *segment_callback    = NULL;
    *conn_private_data   = http_conn;

    evpl_deferral_init(&http_conn->flush, evpl_http_flush, http_conn);


} /* evpl_http_accept */

SYMBOL_EXPORT struct evpl_http_server *
evpl_http_attach(
    struct evpl_http_agent       *agent,
    struct evpl_listener         *listener,
    evpl_http_dispatch_callback_t dispatch_callback,
    void                         *private_data)
{
    struct evpl_http_server *server;

#ifdef HAVE_NGHTTP2
    /* Advertise ALPN so a TLS listener can negotiate "h2"; harmless for a
     * plain-TCP listener (no TLS context is created). */
    static const char *const protos[] = { "h2", "http/1.1" };
    evpl_tls_set_alpn_protocols(protos, 2);
#endif /* ifdef HAVE_NGHTTP2 */

    server = evpl_zalloc(sizeof(*server));

    server->agent             = agent;
    server->listener          = listener;
    server->private_data      = private_data;
    server->dispatch_callback = dispatch_callback;

    server->binding = evpl_listener_attach(agent->evpl, listener, evpl_http_accept, server);

    return server;
} /* evpl_http_listen */

SYMBOL_EXPORT void
evpl_http_server_destroy(
    struct evpl_http_agent  *agent,
    struct evpl_http_server *server)
{
    evpl_listener_detach(agent->evpl, server->binding);
    evpl_free(server);
} /* evpl_http_server_destroy */

SYMBOL_EXPORT struct evpl_http_conn *
evpl_http_client_connect(
    struct evpl_http_agent *agent,
    enum evpl_protocol_id   protocol_id,
    struct evpl_endpoint   *endpoint,
    enum evpl_http_version  version,
    void                   *private_data)
{
    struct evpl_http_conn *conn;

#ifdef HAVE_NGHTTP2
    /* Advertise ALPN so an h2-over-TLS connection can be negotiated. */
    if (protocol_id == EVPL_STREAM_SOCKET_TLS) {
        if (version == EVPL_HTTP_VERSION_HTTP2) {
            static const char *const protos[] = { "h2" };
            evpl_tls_set_alpn_protocols(protos, 1);
        } else if (version == EVPL_HTTP_VERSION_AUTO) {
            static const char *const protos[] = { "h2", "http/1.1" };
            evpl_tls_set_alpn_protocols(protos, 2);
        }
    }
#endif /* ifdef HAVE_NGHTTP2 */

    conn               = evpl_zalloc(sizeof(*conn));
    conn->is_server    = 0;
    conn->proto        = EVPL_HTTP_PROTO_UNKNOWN;
    conn->version      = version;
    conn->connected    = 0;
    conn->agent        = agent;
    conn->private_data = private_data;

    evpl_deferral_init(&conn->flush, evpl_http_flush, conn);

    conn->bind = evpl_connect(agent->evpl, protocol_id, NULL, endpoint,
                              evpl_http_event, NULL, conn);

    return conn;
} /* evpl_http_client_connect */

SYMBOL_EXPORT void
evpl_http_client_close(
    struct evpl_http_agent *agent,
    struct evpl_http_conn  *conn)
{
    evpl_close(agent->evpl, conn->bind);
} /* evpl_http_client_close */

SYMBOL_EXPORT struct evpl_http_request *
evpl_http_request_create(
    struct evpl_http_conn      *conn,
    enum evpl_http_request_type method,
    const char                 *url)
{
    struct evpl_http_request *request;

    request               = evpl_http_request_alloc(conn->agent);
    request->conn         = conn;
    request->request_type = method;
    request->uri_len      = evpl_copy_string(request->uri, url, sizeof(request->uri));

    return request;
} /* evpl_http_request_create */

SYMBOL_EXPORT void
evpl_http_client_set_request_length(
    struct evpl_http_request *request,
    uint64_t                  content_length)
{
    request->response_length = content_length;
    request->response_left   = content_length;
} /* evpl_http_client_set_request_length */

SYMBOL_EXPORT void
evpl_http_client_set_request_chunked(struct evpl_http_request *request)
{
    request->response_transfer_encoding = EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED;
} /* evpl_http_client_set_request_chunked */

SYMBOL_EXPORT void
evpl_http_request_dispatch(
    struct evpl_http_request   *request,
    evpl_http_notify_callback_t notify_callback,
    void                       *notify_data)
{
    struct evpl_http_conn *conn = request->conn;
    struct evpl           *evpl = conn->agent->evpl;

    request->notify_callback = notify_callback;
    request->notify_data     = notify_data;
    request->request_flags  |= EVPL_HTTP_REQUEST_RESPONSE_READY;

#ifdef HAVE_NGHTTP2
    if (conn->proto == EVPL_HTTP_PROTO_H2) {
        evpl_http2_dispatch(request);
        return;
    }
#endif /* ifdef HAVE_NGHTTP2 */

    /* Queue in request order; flushed now if connected, otherwise once the
     * connection completes (or the h2c/h1 protocol is decided). */
    DL_APPEND(conn->pending_requests, request);

    if (conn->connected) {
        evpl_defer(evpl, &conn->flush);
    }
} /* evpl_http_request_dispatch */

SYMBOL_EXPORT int
evpl_http_request_status(struct evpl_http_request *request)
{
    return request->status;
} /* evpl_http_request_status */

SYMBOL_EXPORT enum evpl_http_request_type
evpl_http_request_type(struct evpl_http_request *request)
{
    return request->request_type;
} /* evpl_http_request_type */

SYMBOL_EXPORT void
evpl_http_request_add_header(
    struct evpl_http_request *request,
    const char               *name,
    const char               *value)
{
    struct evpl_http_conn           *conn = request->conn;
    struct evpl_http_request_header *header;

    header = evpl_http_request_header_alloc(conn->agent);

    strncpy(header->name, name, sizeof(header->name) - 1);
    strncpy(header->value, value, sizeof(header->value) - 1);

    if (conn->is_server) {
        DL_APPEND(request->response_headers, header);
    } else {
        DL_APPEND(request->request_headers, header);
    }


} /* evpl_http_request_add_header */

SYMBOL_EXPORT void
evpl_http_request_add_datav(
    struct evpl_http_request *request,
    struct evpl_iovec        *iov,
    int                       niov)
{
    int i;

    evpl_http_abort_if(request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_FINISHED, "request already finished");

    if (niov == 0) {
        request->request_flags |= EVPL_HTTP_REQUEST_RESPONSE_FINISHED;

#ifdef HAVE_NGHTTP2
        if (request->conn->proto == EVPL_HTTP_PROTO_H2) {
            request->h2.eof = 1;
            evpl_http2_submit(request);
        }
#endif /* ifdef HAVE_NGHTTP2 */
        return;
    }

    for (i = 0; i < niov; i++) {
        evpl_iovec_ring_add(&request->send_ring, &iov[i]);
    }

#ifdef HAVE_NGHTTP2
    if (request->conn->proto == EVPL_HTTP_PROTO_H2) {
        evpl_http2_submit(request);
        return;
    }
#endif /* ifdef HAVE_NGHTTP2 */

    if (request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_READY) {
        evpl_defer(request->conn->agent->evpl, &request->conn->flush);
    }
} /* evpl_http_request_add_datav */

SYMBOL_EXPORT void
evpl_http_server_set_response_length(
    struct evpl_http_request *request,
    uint64_t                  content_length)
{
    request->response_length = content_length;

    if (request->request_type == EVPL_HTTP_REQUEST_TYPE_HEAD) {
        request->response_left = 0;
    } else {
        request->response_left = content_length;
    }
} /* evpl_http_server_set_response_length */

SYMBOL_EXPORT void
evpl_http_server_set_response_chunked(struct evpl_http_request *request)
{
    request->response_transfer_encoding = EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED;
} /* evpl_http_server_set_response_chunked */

SYMBOL_EXPORT void
evpl_http_server_dispatch_default(
    struct evpl_http_request *request,
    int                       status)
{
    struct evpl_http_conn *conn = request->conn;
    struct evpl           *evpl = conn->agent->evpl;

    request->status         = status;
    request->request_flags |= EVPL_HTTP_REQUEST_RESPONSE_READY;

#ifdef HAVE_NGHTTP2
    if (conn->proto == EVPL_HTTP_PROTO_H2) {
        /* HTTP/2 carries no hop-by-hop Connection header and frames its own
         * body, so the response is submitted directly to the session. */
        evpl_http2_dispatch(request);
        return;
    }
#endif /* ifdef HAVE_NGHTTP2 */

    evpl_http_request_add_header(request, "Connection", "keep-alive");

    evpl_defer(evpl, &conn->flush);
} /* evpl_http_server_complete_request */

SYMBOL_EXPORT const char *
evpl_http_request_type_to_string(struct evpl_http_request *request)
{
    switch (request->request_type) {
        case EVPL_HTTP_REQUEST_TYPE_GET:
            return "Get";
        case EVPL_HTTP_REQUEST_TYPE_POST:
            return "Post";
        case EVPL_HTTP_REQUEST_TYPE_PUT:
            return "Put";
        case EVPL_HTTP_REQUEST_TYPE_DELETE:
            return "Delete";
        case EVPL_HTTP_REQUEST_TYPE_HEAD:
            return "Head";
        default:
            return "Unknown";
    } /* switch */
} /* evpl_http_request_type_to_string */

SYMBOL_EXPORT const char *
evpl_http_request_url(
    struct evpl_http_request *request,
    int                      *len)
{
    if (len) {
        *len = request->uri_len;
    }

    return request->uri;
} /* evpl_http_request_url */

SYMBOL_EXPORT const char *
evpl_http_request_header(
    struct evpl_http_request *request,
    const char               *name)
{
    struct evpl_http_request_header *header;

    DL_FOREACH(request->request_headers, header)
    {
        if (strncasecmp(header->name, name, sizeof(header->name) - 1) == 0) {
            return header->value;
        }
    }

    return NULL;
} /* evpl_http_request_header */

SYMBOL_EXPORT void
evpl_http_request_header_iterate(
    struct evpl_http_request     *request,
    evpl_http_request_header_cb_t callback,
    void                         *private_data)
{
    struct evpl_http_request_header *header;

    DL_FOREACH(request->request_headers, header)
    {
        callback(header->name, header->value, private_data);
    }
} /* evpl_http_request_header_iterate */

SYMBOL_EXPORT const char *
evpl_http_response_header(
    struct evpl_http_request *request,
    const char               *name)
{
    struct evpl_http_request_header *header;

    DL_FOREACH(request->response_headers, header)
    {
        if (strncasecmp(header->name, name, sizeof(header->name) - 1) == 0) {
            return header->value;
        }
    }

    return NULL;
} /* evpl_http_response_header */

SYMBOL_EXPORT void
evpl_http_response_header_iterate(
    struct evpl_http_request     *request,
    evpl_http_request_header_cb_t callback,
    void                         *private_data)
{
    struct evpl_http_request_header *header;

    DL_FOREACH(request->response_headers, header)
    {
        callback(header->name, header->value, private_data);
    }
} /* evpl_http_response_header_iterate */

SYMBOL_EXPORT uint64_t
evpl_http_request_get_data_avail(struct evpl_http_request *request)
{
    return evpl_iovec_ring_bytes(&request->recv_ring);
} /* evpl_http_request_get_data_avail */

SYMBOL_EXPORT int
evpl_http_request_get_datav(
    struct evpl              *evpl,
    struct evpl_http_request *request,
    struct evpl_iovec        *iov,
    int                       length)
{
    return evpl_iovec_ring_copyv(evpl, iov, &request->recv_ring, length);
} /* evpl_http_request_get_datav */
