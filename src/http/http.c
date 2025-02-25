// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "core/internal.h"
#include "evpl/evpl.h"
#include "core/iovec_ring.h"
#include "http.h"
#include "uthash/utlist.h"

#define evpl_http_debug(...) evpl_debug("http", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_http_info(...)  evpl_info("http", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_http_error(...) evpl_error("http", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_http_fatal(...) evpl_fatal("http", __FILE__, __LINE__, __VA_ARGS__)
#define evpl_http_abort(...) evpl_abort("http", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_http_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "http", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_http_abort_if(cond, ...) \
        evpl_abort_if(cond, "http", __FILE__, __LINE__, __VA_ARGS__)

enum evpl_http_request_type {
    EVPL_HTTP_REQUEST_TYPE_UNKNOWN,
    EVPL_HTTP_REQUEST_TYPE_GET,
    EVPL_HTTP_REQUEST_TYPE_HEAD,
    EVPL_HTTP_REQUEST_TYPE_POST,
    EVPL_HTTP_REQUEST_TYPE_PUT,
    EVPL_HTTP_REQUEST_TYPE_DELETE,

};

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

struct evpl_http_request {
    enum evpl_http_request_type              request_type;
    enum evpl_http_request_state             request_state;
    enum evpl_http_request_http_version      http_version;
    enum evpl_http_request_transfer_encoding request_transfer_encoding;
    enum evpl_http_request_transfer_encoding response_transfer_encoding;
    evpl_http_notify_callback_t              notify_callback;
    uint64_t                                 request_length;
    uint64_t                                 request_left;
    uint64_t                                 request_chunk_left;
    uint64_t                                 response_length;
    uint64_t                                 response_left;
    uint64_t                                 request_flags;
    int                                      status;
    struct evpl_http_conn                   *conn;
    struct evpl_iovec_ring                   send_ring;
    struct evpl_iovec_ring                   recv_ring;
    struct evpl_http_request_header         *request_headers;
    struct evpl_http_request_header         *response_headers;
    struct evpl_http_request                *prev;
    struct evpl_http_request                *next;
    char                                     uri[16384];
};

struct evpl_http_conn {
    int                       is_server;
    struct evpl_http_server  *server;
    struct evpl_http_agent   *agent;
    struct evpl_bind         *bind;
    struct evpl_deferral      flush;
    struct evpl_http_request *current_request;
    struct evpl_http_request *pending_requests;
    void                     *private_data;
};

struct evpl_http_server {
    struct evpl_http_agent       *agent;
    struct evpl_listener         *listener;
    struct evpl_bind             *bind;
    void                         *private_data;
    evpl_http_dispatch_callback_t dispatch_callback;
};

struct evpl_http_agent {
    struct evpl_http_request        *free_requests;
    struct evpl_http_request_header *free_headers;
    struct evpl                     *evpl;
};

static const char *http_version_string[] = {
    "HTTP/1.0",
    "HTTP/1.1",
};

static const char *
evpl_http_response_status_string(int status)
{
    switch (status) {
        case 200:
            return "OK";
        case 404:
            return "Not Found";
        default:
            return "Unknown";
    } /* switch */
} /* evpl_http_response_status_string */

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
    request->request_transfer_encoding  = EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT;
    request->response_transfer_encoding = EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT;
    request->request_length             = 0;
    request->request_left               = 0;
    request->request_chunk_left         = 0;
    request->response_length            = 0;
    request->response_left              = 0;
    request->request_flags              = 0;
    request->notify_callback            = NULL;
    request->request_headers            = NULL;
    request->response_headers           = NULL;
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

struct evpl_http_agent *
evpl_http_init(struct evpl *evpl)
{
    struct evpl_http_agent *agent;

    agent = evpl_zalloc(sizeof(*agent));

    agent->evpl = evpl;

    return agent;
} /* evpl_http_init */

void
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

static void
evpl_http_server_handle_data(struct evpl_http_conn *conn)
{
    struct evpl_http_server         *server = conn->server;
    struct evpl_http_agent          *agent  = conn->agent;
    struct evpl_bind                *bind   = conn->bind;
    struct evpl_http_request        *request;
    struct evpl_http_request_header *header;
    struct evpl                     *evpl = agent->evpl;
    char                             line[256];
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

        if (strncmp(token, "GET", 3) == 0) {
            request->request_type = EVPL_HTTP_REQUEST_TYPE_GET;
        } else if (strncmp(token, "HEAD", 4) == 0) {
            request->request_type = EVPL_HTTP_REQUEST_TYPE_HEAD;
        } else if (strncmp(token, "POST", 4) == 0) {
            request->request_type = EVPL_HTTP_REQUEST_TYPE_POST;
        } else if (strncmp(token, "PUT", 3) == 0) {
            request->request_type = EVPL_HTTP_REQUEST_TYPE_PUT;
        } else if (strncmp(token, "DELETE", 6) == 0) {
            request->request_type = EVPL_HTTP_REQUEST_TYPE_DELETE;
        } else {
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

        strncpy(request->uri, token, sizeof(request->uri) - 1);

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
        if (request->request_transfer_encoding == EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT) {
            int               niov;
            struct evpl_iovec iov;

            while (!evpl_iovec_ring_is_full(&request->recv_ring) && request->request_left > 0) {
                niov = evpl_readv(evpl, bind, &iov, 1, request->request_left);

                if (niov == 0) {
                    break;
                }

                request->request_left -= iov.length;

                evpl_iovec_ring_add(&request->recv_ring, &iov);
            }

            if (request->notify_callback) {
                request->notify_callback(evpl,
                                         agent,
                                         request,
                                         EVPL_HTTP_NOTIFY_RECEIVE_DATA,
                                         server->private_data);
            }

            if (request->request_left == 0) {
                request->request_state = EVPL_HTTP_REQUEST_STATE_COMPLETE;
                DL_APPEND(conn->pending_requests, request);
                conn->current_request = NULL;

                if (request->notify_callback) {
                    request->notify_callback(evpl,
                                             agent,
                                             request,
                                             EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE,
                                             server->private_data);
                }
            }
        } else if (request->request_transfer_encoding == EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED) {
            int               niov;
            uint64_t          received = 0;
            struct evpl_iovec iov;

            while (!evpl_iovec_ring_is_full(&request->recv_ring)) {

                if (request->request_chunk_left > 0) {
                    niov = evpl_readv(evpl, bind, &iov, 1, request->request_chunk_left);

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
                        return;
                    }

                    if (rc == -1) {
                        break;
                    }

                    if (request->request_flags & EVPL_HTTP_REQUEST_EXPECT_CHUNK_NL) {
                        if (line[0] != '\0') {
                            evpl_close(evpl, bind);
                            return;
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

            if (request->notify_callback) {
                if (request->request_state == EVPL_HTTP_REQUEST_STATE_COMPLETE) {
                    DL_APPEND(conn->pending_requests, request);
                    conn->current_request = NULL;

                    request->notify_callback(evpl,
                                             agent,
                                             request,
                                             EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE,
                                             server->private_data);
                } else if (received) {
                    request->notify_callback(evpl,
                                             agent,
                                             request,
                                             EVPL_HTTP_NOTIFY_RECEIVE_DATA,
                                             server->private_data);
                }
            }

        } else {
            abort();
        }
    } else {
        abort();
    }
} /* evpl_http_server_handle_data */

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
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            free(http_conn);
            break;
        case EVPL_NOTIFY_RECV_DATA:
            if (http_conn->is_server) {
                evpl_http_server_handle_data(http_conn);
            } else {
                abort();
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

    niov = evpl_iovec_alloc(evpl, 4096, 4096, 1, &iov);

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

    evpl_sendv(evpl, bind, &iov, 1, iov.length);
} /* evpl_http_server_send_headers */

static void
evpl_http_server_flush(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_http_conn    *conn   = arg;
    struct evpl_http_agent   *agent  = conn->agent;
    struct evpl_http_server  *server = conn->server;
    struct evpl_bind         *bind   = conn->bind;
    struct evpl_http_request *request, *tmp;
    struct evpl_iovec        *iovp;
    uint64_t                  chunk_length;
    int                       chunk_hdr_len, niov;
    struct evpl_iovec         iov;

    DL_FOREACH_SAFE(conn->pending_requests, request, tmp)
    {
        if (!(request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_READY)) {
            break;
        }

        if (!(request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_HDR_SENT)) {
            evpl_http_server_send_headers(evpl, request);
            request->request_flags |= EVPL_HTTP_REQUEST_RESPONSE_HDR_SENT;
        }

        if (request->response_transfer_encoding == EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT) {

            while (request->response_left  && !evpl_iovec_ring_is_empty(&request->send_ring)) {
                iovp = evpl_iovec_ring_tail(&request->send_ring);
                evpl_sendv(evpl, bind, iovp, 1, iovp->length);

                request->response_left -= iovp->length;
                evpl_iovec_ring_remove(&request->send_ring);
            }

            if (request->response_left == 0) {
                DL_DELETE(conn->pending_requests, request);
                evpl_http_request_free(conn->agent, request);
            } else {
                request->notify_callback(evpl,
                                         agent,
                                         request,
                                         EVPL_HTTP_NOTIFY_WANT_DATA,
                                         server->private_data);
                break;
            }

        } else {

            chunk_length = evpl_iovec_ring_bytes(&request->send_ring);

            if (chunk_length) {

                niov = evpl_iovec_alloc(evpl, 64, 0, 1, &iov);

                chunk_hdr_len = snprintf(iov.data, 64, "%lx\r\n", chunk_length);

                evpl_http_abort_if(niov < 0, "failed to allocate iovec");

                evpl_sendv(evpl, bind, &iov, 1, chunk_hdr_len);

                while (!evpl_iovec_ring_is_empty(&request->send_ring)) {
                    iovp = evpl_iovec_ring_tail(&request->send_ring);
                    evpl_sendv(evpl, bind, iovp, 1, iovp->length);
                    evpl_iovec_ring_remove(&request->send_ring);
                }

                niov = evpl_iovec_alloc(evpl, 2, 0, 1, &iov);

                evpl_http_abort_if(niov < 0, "failed to allocate iovec");

                ((char *) iov.data)[0] = '\r';
                ((char *) iov.data)[1] = '\n';

                evpl_sendv(evpl, bind, &iov, 1, 2);
            }

            if (request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_FINISHED) {
                niov = evpl_iovec_alloc(evpl, 5, 0, 1, &iov);

                evpl_http_abort_if(niov < 0, "failed to allocate iovec");

                ((char *) iov.data)[0] = '0';
                ((char *) iov.data)[1] = '\r';
                ((char *) iov.data)[2] = '\n';
                ((char *) iov.data)[3] = '\r';
                ((char *) iov.data)[4] = '\n';

                evpl_sendv(evpl, bind, &iov, 1, 5);

                DL_DELETE(conn->pending_requests, request);
                evpl_http_request_free(conn->agent, request);
            } else {
                request->notify_callback(evpl,
                                         agent,
                                         request,
                                         EVPL_HTTP_NOTIFY_WANT_DATA,
                                         server->private_data);
                break;
            }
        }

    }
} /* evpl_http_server_flush */

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
    http_conn->agent     = server->agent;
    http_conn->bind      = bind;
    *notify_callback     = evpl_http_event;
    *segment_callback    = NULL;
    *conn_private_data   = http_conn;

    evpl_deferral_init(&http_conn->flush, evpl_http_server_flush, http_conn);


} /* evpl_http_accept */

struct evpl_http_server *
evpl_http_listen(
    struct evpl_http_agent       *agent,
    struct evpl_endpoint         *endpoint,
    evpl_http_dispatch_callback_t dispatch_callback,
    void                         *private_data)
{
    struct evpl_http_server *server;

    server = evpl_zalloc(sizeof(*server));

    server->agent             = agent;
    server->private_data      = private_data;
    server->dispatch_callback = dispatch_callback;
    server->listener          = evpl_listener_create();

    evpl_listener_attach(agent->evpl, server->listener, evpl_http_accept, server);

    evpl_listen(
        server->listener,
        EVPL_STREAM_SOCKET_TCP,
        endpoint);

    return server;
} /* evpl_http_listen */

void
evpl_http_server_destroy(
    struct evpl_http_agent  *agent,
    struct evpl_http_server *server)
{
    evpl_free(server);
} /* evpl_http_server_destroy */

void
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

void
evpl_http_request_add_datav(
    struct evpl_http_request *request,
    struct evpl_iovec        *iov,
    size_t                    niov)
{
    int i;

    if (niov == 0) {
        request->request_flags |= EVPL_HTTP_REQUEST_RESPONSE_FINISHED;
        return;
    }

    evpl_http_abort_if(request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_FINISHED, "request already finished");

    for (i = 0; i < niov; i++) {
        evpl_iovec_ring_add(&request->send_ring, &iov[i]);
    }

    if (request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_READY) {
        evpl_defer(request->conn->agent->evpl, &request->conn->flush);
    }
} /* evpl_http_request_add_datav */

void
evpl_http_server_set_response_length(
    struct evpl_http_request *request,
    uint64_t                  content_length)
{
    request->response_length = content_length;
    request->response_left   = content_length;
} /* evpl_http_server_set_response_length */

void
evpl_http_server_set_response_chunked(struct evpl_http_request *request)
{
    request->response_transfer_encoding = EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED;
} /* evpl_http_server_set_response_chunked */

void
evpl_http_server_dispatch_default(
    struct evpl_http_request *request,
    int                       status)
{
    struct evpl_http_conn *conn = request->conn;
    struct evpl           *evpl = conn->agent->evpl;

    request->status         = status;
    request->request_flags |= EVPL_HTTP_REQUEST_RESPONSE_READY;

    evpl_defer(evpl, &conn->flush);
} /* evpl_http_server_complete_request */
