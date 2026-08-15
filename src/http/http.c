// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <inttypes.h>
#include <limits.h>
#include <ctype.h>

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

    /* Floor the configured limit so the fixed parts of a header block
     * (status/request line, framing headers, terminator) always fit. */
    agent->max_header_size = evpl_global_config_get_http_max_header_size();

    if (agent->max_header_size < 512) {
        agent->max_header_size = 512;
    }

    return agent;
} /* evpl_http_init */

SYMBOL_EXPORT void
evpl_http_destroy(struct evpl_http_agent *agent)
{
    struct evpl_http_request        *request;
    struct evpl_http_request_header *header;
    struct evpl_http_conn           *conn;

    /* Close and retire every live connection before freeing the agent.  Conn
     * binds hold notify callbacks that dereference the agent (the h2 receive
     * path reads conn->agent->evpl on every data event), so an agent freed
     * while a bind still has buffered input is a use-after-free as soon as
     * evpl_destroy's close pump delivers that data.  Pump the loop until the
     * disconnect notifications retire each conn (evpl_close is idempotent on
     * a bind already pending close).  Must run on the agent's evpl thread,
     * which every existing caller already does. */
    while (agent->conns) {
        DL_FOREACH(agent->conns, conn)
        {
            evpl_close(agent->evpl, conn->bind);
        }
        evpl_continue(agent->evpl);
    }

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

/* How many iovecs the line scan looks at before falling back to a contiguous
 * copy.  Enough that an ordinary request never needs the fallback. */
#define EVPL_HTTP_PARSE_IOV 8

/*
 * Terminate a line the scan has just found the LF of, and consume it.
 *
 * RFC 1945 section 19.3: "we recommend that applications, when parsing such
 * headers, recognize a single LF as a line terminator and ignore the leading
 * CR" -- so a bare LF ends the line just as CRLF does.  Refusing it buys
 * nothing against a peer that can equally well send CRLF, and costs
 * interoperability with the many that send LF somewhere.  What it does mean
 * is that this parser and a front end that disagrees about bare LF would
 * disagree about where a message ends; the defences against that are
 * elsewhere, in refusing a message whose length is ambiguous.
 */
static inline int
evpl_http_line_terminate(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    char             *line,
    char             *lc)
{
    if (lc > line && *(lc - 1) == '\r') {
        *(lc - 1) = '\0';
    } else {
        *lc = '\0';
    }

    evpl_consume(evpl, bind, (int) (lc - line) + 1);

    return 0;
} /* evpl_http_line_terminate */

/*
 * Copy one line out of the receive stream.  Returns 0 with `line`
 * NUL-terminated and the bytes consumed, -1 if the line has not fully arrived,
 * or -2 if it is longer than the buffer.
 *
 * The scan runs over the peeked iovecs, so a line that arrived contiguously
 * costs no copy beyond the line itself.  evpl_peekv reports at most
 * EVPL_HTTP_PARSE_IOV of them, though, and a peer that dribbles its request
 * produces one iovec per byte -- so exhausting the array does NOT mean the
 * data has not arrived, only that the answer lies further along than the array
 * reaches.  Concluding "need more data" there is how an over-long request line
 * could wedge a connection permanently: the bytes that would have tripped the
 * length check were already buffered, just not visible.  When the array fills,
 * fall back to the bounded contiguous copy, which sees the whole window
 * however finely it is fragmented.
 */
static inline int
evpl_http_parse_line(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    char             *line,
    int               maxline)
{
    struct evpl_iovec iov[EVPL_HTTP_PARSE_IOV];
    int               niov, i, j, n;
    const char       *c;
    char             *lc = line;

    niov = evpl_peekv(evpl, bind, iov, EVPL_HTTP_PARSE_IOV, maxline + 2);

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
                return evpl_http_line_terminate(evpl, bind, line, lc);
            }

            *lc++ = *c++;
        }
    }

    if (likely(niov < EVPL_HTTP_PARSE_IOV)) {
        /* The whole window was scanned and holds no terminator yet. */
        return -1;
    }

    n = evpl_peek(evpl, bind, line, maxline - 1);

    if (n <= 0) {
        return -1;
    }

    for (lc = line; lc < line + n; lc++) {
        if (*lc == '\n') {
            return evpl_http_line_terminate(evpl, bind, line, lc);
        }
    }

    return n >= maxline - 1 ? -2 : -1;
} /* evpl_http_parse_line */

/*
 * How much of a declared body length to ask evpl_recvv() for in one call.
 *
 * The length comes off the wire -- a Content-Length header or a chunk size --
 * and is held as a uint64_t, while evpl_recvv() takes an int.  Handing it
 * across unclamped truncates: a peer sending "Content-Length: -1" makes
 * request_left UINT64_MAX, which arrives as -1, and evpl_recvv() rejects a
 * non-positive length by returning -1 without touching the caller's iovec.
 * The caller then has a stale iovec to add to the ring, which is a double
 * reference and then a use-after-free on an unauthenticated peer's say-so.
 * Clamping keeps the conversion lossless; the callers additionally treat any
 * non-positive return as "no data", so a rejected call can never be mistaken
 * for a filled iovec again.
 */
static inline int
evpl_http_recv_chunk(uint64_t left)
{
    return left > INT_MAX ? INT_MAX : (int) left;
} /* evpl_http_recv_chunk */

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
            niov = evpl_recvv(evpl, bind, &iov, 1,
                              evpl_http_recv_chunk(request->request_left), NULL);

            if (niov <= 0) {
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
                niov = evpl_recvv(evpl, bind, &iov, 1,
                                  evpl_http_recv_chunk(request->request_chunk_left),
                                  NULL);

                if (niov <= 0) {
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

/*
 * Fixed overhead reserved out of max_header_size for the parts of the
 * outbound header block that are not application-added headers: the status
 * line (<= 47 bytes; a client request line is instead counted exactly at
 * request create time), the Content-Length or Transfer-Encoding line
 * (<= 38), the internally added "Connection: keep-alive\r\n" (24) and the
 * terminating "\r\n" (2).  Enforcing the limit minus this reserve at
 * evpl_http_request_add_header() time means emission can never overflow
 * the buffer it allocates.
 */
#define EVPL_HTTP_HEADER_EMIT_RESERVE 128

/*
 * Stage a header for emission.  With enforce_limit set (the public API),
 * refuse a header that would push the block past max_header_size less the
 * emission reserve.  The library's own fixed headers are added with
 * enforce_limit clear: the reserve already accounts for them, so they
 * cannot overflow the block and must not be dropped.  Returns 0 on
 * success, -1 if the header was refused.
 */
static int
evpl_http_request_add_header_common(
    struct evpl_http_request *request,
    const char               *name,
    const char               *value,
    int                       enforce_limit)
{
    struct evpl_http_conn           *conn  = request->conn;
    struct evpl_http_agent          *agent = conn->agent;
    struct evpl_http_request_header *header;
    unsigned int                     line_bytes;

    header = evpl_http_request_header_alloc(agent);

    strncpy(header->name, name, sizeof(header->name) - 1);
    strncpy(header->value, value, sizeof(header->value) - 1);

    /* accounted as emitted: "<name>: <value>\r\n", using the stored
     * (possibly truncated) field lengths */
    line_bytes = strlen(header->name) + strlen(header->value) + 4;

    if (enforce_limit &&
        request->header_bytes + line_bytes + EVPL_HTTP_HEADER_EMIT_RESERVE >
        agent->max_header_size) {
        evpl_http_request_header_free(agent, header);
        return -1;
    }

    request->header_bytes += line_bytes;

    if (conn->is_server) {
        DL_APPEND(request->response_headers, header);
    } else {
        DL_APPEND(request->request_headers, header);
    }

    return 0;
} /* evpl_http_request_add_header_common */

/*
 * Parse an HTTP-Version, which RFC 1945 section 3.1 defines exactly:
 *
 *     HTTP-Version = "HTTP" "/" 1*DIGIT "." 1*DIGIT
 *
 * Returns 0 and fills in the two numbers, or -1 if the token is not one.
 * Hand-rolled rather than matched with strncmp against the two versions the
 * server speaks, because that both accepts too much -- strncmp(token,
 * "HTTP/1.1", 8) matches "HTTP/1.10" -- and rejects too much, since section
 * 3.1 makes the minor number a compatibility statement rather than a name to
 * be matched.
 */
static int
evpl_http_parse_version(
    const char   *token,
    unsigned int *major,
    unsigned int *minor)
{
    const char  *p = token;
    unsigned int i, v;

    if (strncmp(p, "HTTP/", 5) != 0) {
        return -1;
    }

    p += 5;

    for (i = 0; i < 2; i++) {

        if (i && *p++ != '.') {
            return -1;
        }

        if (!isdigit((unsigned char) *p)) {
            return -1;
        }

        v = 0;

        while (isdigit((unsigned char) *p)) {
            v = v * 10 + (unsigned int) (*p++ - '0');

            if (v > 999) {
                return -1;
            }
        }

        if (i) {
            *minor = v;
        } else {
            *major = v;
        }
    }

    return *p ? -1 : 0;
} /* evpl_http_parse_version */

/*
 * Copy into one of the header struct's fixed fields, truncating rather than
 * overrunning and always terminating.  A header comes off the free list
 * without being cleared, so relying on strncpy's zero padding to terminate it
 * only works while every string is shorter than the field.
 */
static inline void
evpl_http_copy_field(
    char       *dst,
    size_t      cap,
    const char *src)
{
    strncpy(dst, src, cap - 1);
    dst[cap - 1] = '\0';
} /* evpl_http_copy_field */

/* Linear white space, RFC 1945 section 2.2. */
static inline int
evpl_http_is_lws(char c)
{
    return c == ' ' || c == '\t';
} /* evpl_http_is_lws */

/*
 * Strip leading and trailing LWS from a NUL-terminated value in place, and
 * return the start of what is left.
 *
 * RFC 1945 section 4.2: "The field-value ... may be preceded by any amount of
 * LWS, though a single SP is preferred", and section 2.2 makes LWS both SP and
 * HT.  None of it is part of the value, so an application comparing a header
 * against a constant must not be handed the padding the peer happened to send.
 */
static char *
evpl_http_trim_lws(char *value)
{
    char *end;

    while (evpl_http_is_lws(*value)) {
        value++;
    }

    end = value + strlen(value);

    while (end > value && evpl_http_is_lws(*(end - 1))) {
        end--;
    }

    *end = '\0';

    return value;
} /* evpl_http_trim_lws */

/*
 * Parse one header field line into `header`.  Returns 0, or -1 if the line is
 * not a field at all.
 *
 * RFC 1945 section 4.2:
 *
 *     HTTP-header = field-name ":" [ field-value ] CRLF
 *     field-name  = token
 *
 * The brackets are the part a strtok_r split gets wrong: a field with no value
 * is legal, and treating the missing token as fatal turns "X-Probe:" -- which
 * client libraries emit without thinking about it -- into a failed request.
 */
static int
evpl_http_parse_header_line(
    char                            *line,
    struct evpl_http_request_header *header)
{
    char *colon = strchr(line, ':');

    if (!colon || colon == line) {
        /* no colon at all, or an empty field-name */
        return -1;
    }

    /* A token contains neither SP nor HT, so whitespace before the colon is
     * not part of the field-name and this line is not a field.  RFC 7230
     * section 3.2.4 later made rejecting it a MUST for a reason worth keeping
     * in mind here: a front end that reads "X-Probe : v" as no header and a
     * back end that reads it as "X-Probe" disagree about what the request
     * contains, and the difference is what gets smuggled. */
    if (evpl_http_is_lws(*(colon - 1))) {
        return -1;
    }

    *colon = '\0';

    evpl_http_copy_field(header->name, sizeof(header->name), line);
    evpl_http_copy_field(header->value, sizeof(header->value),
                         evpl_http_trim_lws(colon + 1));

    return 0;
} /* evpl_http_parse_header_line */

/*
 * Continue `header` with a continuation line (RFC 1945 section 2.2: "Header
 * fields can be extended over multiple lines by preceding each extra line with
 * at least one SP or HT").  All LWS, folding included, has the semantics of a
 * single SP, so that is what the fold becomes.
 */
static void
evpl_http_fold_header_line(
    struct evpl_http_request_header *header,
    char                            *line)
{
    size_t len = strlen(header->value);

    if (len + 2 >= sizeof(header->value)) {
        return;
    }

    header->value[len++] = ' ';

    evpl_http_copy_field(header->value + len, sizeof(header->value) - len,
                         evpl_http_trim_lws(line));
} /* evpl_http_fold_header_line */

/*
 * Parse a Content-Length.  Returns 0 and the value, or -1.
 *
 * RFC 1945 section 10.4 makes it "the length of the message-body ...
 * expressed as a decimal number of octets", so 1*DIGIT and nothing else.
 * strtoul accepts far more than that -- a sign, leading whitespace, any
 * trailing junk -- and reports none of it: "abc" reads as zero, which turns a
 * request WITH an entity into one without and leaves the entity to be parsed
 * as whatever comes next, and "-1" wraps to a length no peer will ever
 * satisfy.  Both are desyncs an attacker chooses.
 */
static int
evpl_http_parse_content_length(
    const char *value,
    uint64_t   *out)
{
    const char *p = value;
    uint64_t    v = 0, digit;

    if (!isdigit((unsigned char) *p)) {
        return -1;
    }

    while (isdigit((unsigned char) *p)) {
        digit = (uint64_t) (*p++ - '0');

        if (v > (UINT64_MAX - digit) / 10) {
            return -1;
        }

        v = v * 10 + digit;
    }

    if (*p) {
        return -1;
    }

    *out = v;

    return 0;
} /* evpl_http_parse_content_length */

/*
 * Whether a comma-separated field value contains `token`.  Connection is such
 * a list ("keep-alive, Upgrade" is ordinary), so comparing the whole value
 * against one name would miss the case that matters.
 */
static int
evpl_http_value_has_token(
    const char *value,
    const char *token)
{
    const char *p = value, *end;
    size_t      len = strlen(token);

    while (*p) {

        while (evpl_http_is_lws(*p) || *p == ',') {
            p++;
        }

        end = p;

        while (*end && *end != ',') {
            end++;
        }

        while (end > p && evpl_http_is_lws(*(end - 1))) {
            end--;
        }

        if ((size_t) (end - p) == len && strncasecmp(p, token, len) == 0) {
            return 1;
        }

        p = end;

        if (*p) {
            p++;
        }
    }

    return 0;
} /* evpl_http_value_has_token */

/*
 * Whether the connection survives this request's response.
 *
 * RFC 1945 section 1.4: "The connection is closed by the server after sending
 * the response."  HTTP/1.0 has no persistent connections of its own; the
 * Keep-Alive extension (RFC 2068 section 19.7.1) is opt-in, and only the
 * client may open the subject.  HTTP/1.1 inverted the default, so there the
 * question is whether the client asked to close (RFC 7230 section 6.1).
 *
 * Either way an explicit "Connection: close" wins, since a peer that has said
 * it is done cannot be argued with.
 */
static int
evpl_http_response_keeps_alive(struct evpl_http_request *request)
{
    if (request->request_flags & EVPL_HTTP_REQUEST_CONN_CLOSE) {
        return 0;
    }

    if (request->http_version == EVPL_HTTP_REQUEST_HTTP_VERSION_1_1) {
        return 1;
    }

    return (request->request_flags & EVPL_HTTP_REQUEST_CONN_KEEPALIVE) != 0;
} /* evpl_http_response_keeps_alive */

/*
 * Parse a Status-Code.  Returns 0 and the value, or -1.
 *
 * RFC 1945 section 6.1.1: "Status-Code = 3DIGIT", and section 6.1.1 assigns
 * meaning by the leading digit, 1 through 5.  atoi accepts a great deal more
 * and reports none of it: "abc" reads as 0, "99" as 99, "700" as 700, and all
 * three used to be handed to the caller as though the peer had said them.  A
 * caller testing `status < 400` treats 0 as a success.
 */
static int
evpl_http_parse_status(
    const char *token,
    int        *out)
{
    if (!isdigit((unsigned char) token[0]) ||
        !isdigit((unsigned char) token[1]) ||
        !isdigit((unsigned char) token[2]) ||
        token[3] != '\0') {
        return -1;
    }

    if (token[0] < '1' || token[0] > '5') {
        return -1;
    }

    *out = (token[0] - '0') * 100 + (token[1] - '0') * 10 + (token[2] - '0');

    return 0;
} /* evpl_http_parse_status */

/*
 * Refuse a request the parser cannot use, and close.
 *
 * RFC 1945 section 9.4.1 (400 Bad Request, "the request could not be
 * understood by the server due to malformed syntax") and section 9.5.2 (501
 * Not Implemented, for a method the server does not support) exist so that a
 * client learns which of the two things went wrong.  Hanging up instead tells
 * it nothing it can act on: a FIN is indistinguishable from a crashed server,
 * a lost route or a middlebox, so the client retries a request that will be
 * refused the same way forever.
 *
 * The response is built by hand rather than through the request, because the
 * request may not have parsed far enough to have a version, a method or a URI
 * -- and because the connection is going away with it either way, which is
 * what "Connection: close" says explicitly for the benefit of a peer that
 * would otherwise try to reuse it.
 */
static void
evpl_http_server_reject(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    int               status,
    const char       *why)
{
    char rsp[128];
    int  len;

    evpl_http_debug("refusing request with %d: %s", status, why);

    len = snprintf(rsp, sizeof(rsp),
                   "HTTP/1.1 %d %s\r\n"
                   "Content-Length: 0\r\n"
                   "Connection: close\r\n"
                   "\r\n",
                   status, evpl_http_response_status_string(status));

    evpl_send(evpl, bind, rsp, len);
    evpl_finish(evpl, bind);
} /* evpl_http_server_reject */

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
    int                              rc, folded;
    unsigned int                     major, minor;
    uint64_t                         length;
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
            evpl_http_server_reject(evpl, bind, 400, "request line too long");
            return;
        }

        if (rc == -1) {
            return;
        }

        /* RFC 1945 section 5.1 is exact -- Method SP Request-URI SP
         * HTTP-Version -- and section 19.3 asks a server to tolerate any
         * amount of SP or HT *between* those fields, which is what strtok_r
         * gives.  What it does not ask for is tolerating a run before the
         * first one: strtok_r skips leading delimiters too, so " /echo
         * HTTP/1.0" would otherwise parse as a request whose method is the
         * URI. */
        if (line[0] == ' ' || line[0] == '\t') {
            evpl_http_server_reject(evpl, bind, 400,
                                    "request line starts with whitespace");
            return;
        }

        token = strtok_r(line, " \t", &saveptr);

        if (!token) {
            evpl_http_server_reject(evpl, bind, 400, "empty request line");
            return;
        }

        request->request_type = evpl_http_method_from_string(token);

        if (request->request_type == EVPL_HTTP_REQUEST_TYPE_UNKNOWN) {
            /* RFC 1945 section 5.1.1: Method is a token, and tokens are
             * case-sensitive, so a lowercased "get" is as unknown as "FROB" --
             * a server that folds case before comparing accepts a request the
             * grammar does not describe. */
            evpl_http_server_reject(evpl, bind, 501, "unsupported method");
            return;
        }

        token = strtok_r(NULL, " \t", &saveptr);
        if (!token) {
            evpl_http_server_reject(evpl, bind, 400, "missing uri");
            return;
        }

        request->uri_len = evpl_copy_string(request->uri, token, sizeof(request->uri));

        token = strtok_r(NULL, " \t", &saveptr);

        if (!token) {
            evpl_http_server_reject(evpl, bind, 400, "missing http version");
            return;
        }

        if (evpl_http_parse_version(token, &major, &minor) < 0 || major != 1) {
            /* RFC 1945 names no code for a version it cannot serve -- 505 is
             * an HTTP/1.1 addition -- so a request line the grammar does not
             * describe is a malformed one. */
            evpl_http_server_reject(evpl, bind, 400, "unsupported http version");
            return;
        }

        /* RFC 2145 section 2.3: answer at the highest version the server
         * speaks whose major matches, so HTTP/1.9 is a request to be served
         * as HTTP/1.1 rather than one to refuse.  Refusing it is what makes
         * the minor number useless for negotiation. */
        request->http_version = minor ? EVPL_HTTP_REQUEST_HTTP_VERSION_1_1
                                      : EVPL_HTTP_REQUEST_HTTP_VERSION_1_0;

        token = strtok_r(NULL, " \t", &saveptr);

        if (token) {
            evpl_http_server_reject(evpl, bind, 400,
                                    "trailing token on the request line");
            return;
        }

        request->request_state = EVPL_HTTP_REQUEST_STATE_HEADERS;

        goto again;

    } else if (request->request_state == EVPL_HTTP_REQUEST_STATE_HEADERS) {
        rc = evpl_http_parse_line(evpl, bind, line, sizeof(line));

        if (unlikely(rc == -2)) {
            evpl_http_server_reject(evpl, bind, 400,
                                    "header line overflowed the parse buffer");
            return;
        }

        if (rc == -1) {
            return;
        }

        if (line[0] == '\0') {

            /* RFC 1945 section 8.3: "A valid Content-Length is required on
             * all HTTP/1.0 POST requests.  An HTTP/1.0 server should respond
             * with a 400 (bad request) message if it cannot determine the
             * length of the request message's content."  HTTP/1.1 gave a
             * request with no length a defined meaning instead -- no body at
             * all (RFC 7230 section 3.3.3) -- so this applies to 1.0 alone. */
            if (request->request_type == EVPL_HTTP_REQUEST_TYPE_POST &&
                request->http_version == EVPL_HTTP_REQUEST_HTTP_VERSION_1_0 &&
                request->request_transfer_encoding ==
                EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT &&
                !(request->request_flags & EVPL_HTTP_REQUEST_HAVE_LENGTH)) {
                evpl_http_server_reject(evpl, bind, 400,
                                        "HTTP/1.0 POST without Content-Length");
                return;
            }

            /* inbound header block complete; reset the accounting for the
             * outbound response block the application builds from here */
            request->header_bytes  = 0;
            request->request_state = EVPL_HTTP_REQUEST_STATE_BODY;

            if (request->request_flags & EVPL_HTTP_REQUEST_WANTS_CONTINUE) {
                evpl_send(evpl, bind, "HTTP/1.1 100 Continue\r\n\r\n", 25);
            }

            server->dispatch_callback(evpl, agent, request,
                                      &request->notify_callback,
                                      &request->notify_data,
                                      server->private_data);
        } else {
            request->header_bytes += strlen(line) + 2;

            if (unlikely(request->header_bytes > agent->max_header_size)) {
                /* As Apache does when its LimitRequestField* limits are
                 * exceeded. */
                evpl_http_server_reject(evpl, bind, 400,
                                        "header block exceeds max_header_size");
                return;
            }

            folded = evpl_http_is_lws(line[0]);

            if (folded) {
                /* A continuation of the field above, not a field of its own.
                 * The special-field handling below then runs again over the
                 * extended value, because a field's meaning follows from the
                 * whole of it: "Content-Length:\r\n 5" is a length of five,
                 * and reading only the first line would make it zero. */
                header = request->request_headers ?
                    request->request_headers->prev : NULL;

                if (!header) {
                    evpl_http_server_reject(evpl, bind, 400,
                                            "continuation line with no field "
                                            "to continue");
                    return;
                }

                evpl_http_fold_header_line(header, line);
            } else {
                header = evpl_http_request_header_alloc(agent);

                if (evpl_http_parse_header_line(line, header) < 0) {
                    /* Not on the request's list yet, so nothing else will ever
                     * reach it: dropping it here strands the header AND the
                     * tail of the free list still hanging off its next
                     * pointer, which a peer sending malformed header lines can
                     * repeat at will. */
                    evpl_http_request_header_free(agent, header);
                    evpl_http_server_reject(evpl, bind, 400,
                                            "malformed header line");
                    return;
                }

                DL_APPEND(request->request_headers, header);
            }

            /* Exact comparisons: the counted forms these replace were prefix
             * matches wherever the count was shorter than the string (an
             * "Expectation" header set WANTS_CONTINUE, a "chunkedy" coding
             * was chunked), and now that the value arrives with its LWS
             * already stripped there is nothing an inexact match buys. */
            if (strcasecmp(header->name, "Content-Length") == 0) {

                if (evpl_http_parse_content_length(header->value, &length) < 0) {
                    evpl_http_server_reject(evpl, bind, 400,
                                            "Content-Length is not a decimal "
                                            "number of octets");
                    return;
                }

                /* Two lengths that disagree leave the message with no single
                 * length, so where the next request starts becomes the
                 * sender's choice rather than the receiver's -- the desync a
                 * request-smuggling attack is built on.  Identical repeats are
                 * harmless and stay allowed.  A fold is not a second field, so
                 * it is exempt: it is this same field getting longer. */
                if (!folded &&
                    (request->request_flags & EVPL_HTTP_REQUEST_HAVE_LENGTH) &&
                    length != request->request_length) {
                    evpl_http_server_reject(evpl, bind, 400,
                                            "conflicting Content-Length");
                    return;
                }

                request->request_flags |= EVPL_HTTP_REQUEST_HAVE_LENGTH;
                request->request_length = length;
                request->request_left   = length;
            } else if (strcasecmp(header->name, "Expect") == 0) {
                if (strcasecmp(header->value, "100-continue") == 0) {
                    request->request_flags |= EVPL_HTTP_REQUEST_WANTS_CONTINUE;
                }
            } else if (strcasecmp(header->name, "Connection") == 0) {
                if (evpl_http_value_has_token(header->value, "close")) {
                    request->request_flags |= EVPL_HTTP_REQUEST_CONN_CLOSE;
                }

                if (evpl_http_value_has_token(header->value, "keep-alive")) {
                    request->request_flags |= EVPL_HTTP_REQUEST_CONN_KEEPALIVE;
                }
            } else if (strcasecmp(header->name, "Transfer-Encoding") == 0) {
                if (strcasecmp(header->value, "chunked") == 0) {
                    request->request_transfer_encoding = EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED;
                } else {
                    /* A transfer coding the server does not implement is
                     * exactly what 501 is for (RFC 1945 section 9.5.2), and
                     * the body cannot be delimited without it. */
                    evpl_http_server_reject(evpl, bind, 501,
                                            "unsupported transfer encoding");
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
    unsigned int                     major, minor;
    uint64_t                         length;
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

        /* Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase (RFC 1945
         * section 6.1), and as on the request line a leading run of LWS is not
         * between fields, so strtok_r must not be allowed to skip it. */
        if (evpl_http_is_lws(line[0])) {
            evpl_http_debug("status line starts with whitespace");
            evpl_close(evpl, bind);
            return;
        }

        token = strtok_r(line, " \t", &saveptr);

        if (!token) {
            evpl_http_debug("missing status line version");
            evpl_close(evpl, bind);
            return;
        }

        if (evpl_http_parse_version(token, &major, &minor) < 0 || major != 1) {
            evpl_http_debug("unsupported http version: %s", token);
            evpl_close(evpl, bind);
            return;
        }

        /* RFC 2145 section 2.3, the mirror of the request-side rule: a higher
         * minor version is a response to be read at the highest 1.x this
         * client speaks, not one to refuse. */
        request->http_version = minor ? EVPL_HTTP_REQUEST_HTTP_VERSION_1_1
                                      : EVPL_HTTP_REQUEST_HTTP_VERSION_1_0;

        token = strtok_r(NULL, " \t", &saveptr);

        if (!token) {
            evpl_http_debug("missing status code");
            evpl_close(evpl, bind);
            return;
        }

        if (evpl_http_parse_status(token, &request->status) < 0) {
            evpl_http_debug("malformed status code: %s", token);
            evpl_close(evpl, bind);
            return;
        }

        /* The Reason-Phrase, if any, is whatever is left.  RFC 1945 section
         * 6.1: "The client is not required to examine or display the
         * Reason-Phrase" -- so a response that omits it is understood, and
         * one that carries anything at all is equally understood. */

        request->request_state = EVPL_HTTP_REQUEST_STATE_HEADERS;

        /* header_bytes counted the outbound request block; reuse it for
         * the inbound response header accounting */
        request->header_bytes = 0;

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
            request->header_bytes += strlen(line) + 2;

            if (unlikely(request->header_bytes > agent->max_header_size)) {
                evpl_http_debug(
                    "inbound response header block exceeds max_header_size");
                evpl_close(evpl, bind);
                return;
            }

            if (evpl_http_is_lws(line[0])) {
                /* A continuation of the field above -- see the request path,
                 * which this mirrors. */
                header = request->response_headers ?
                    request->response_headers->prev : NULL;

                if (!header) {
                    evpl_http_debug("continuation line with no field to "
                                    "continue");
                    evpl_close(evpl, bind);
                    return;
                }

                evpl_http_fold_header_line(header, line);
            } else {
                header = evpl_http_request_header_alloc(agent);

                if (evpl_http_parse_header_line(line, header) < 0) {
                    evpl_http_debug("malformed header line");
                    /* As on the request path: the header is not on any list
                     * yet, so dropping it strands it and the free-list tail
                     * behind it. */
                    evpl_http_request_header_free(agent, header);
                    evpl_close(evpl, bind);
                    return;
                }

                DL_APPEND(request->response_headers, header);
            }

            if (strcasecmp(header->name, "Content-Length") == 0) {
                /* The mirror of the request path, and for the same reason: a
                 * response length that is not a decimal number of octets
                 * cannot delimit the body.  A client has no status to answer
                 * with, so the connection goes. */
                if (evpl_http_parse_content_length(header->value, &length) < 0) {
                    evpl_http_debug("response Content-Length is not a decimal "
                                    "number of octets");
                    evpl_close(evpl, bind);
                    return;
                }

                request->request_length = length;
                request->request_left   = length;
            } else if (strcasecmp(header->name, "Transfer-Encoding") == 0) {
                if (strcasecmp(header->value, "chunked") == 0) {
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
             * tearing down the connection leaks them.
             *
             * On a client connection the two overlap: current_request is set
             * to the head of pending_requests while a response is being parsed
             * and only leaves that list once the response completes, so
             * freeing it here as well would put the same request on the
             * agent's free list twice.  On a server connection they are always
             * disjoint (a request moves to pending_requests exactly when
             * current_request is cleared). */
            if (http_conn->current_request &&
                http_conn->current_request != http_conn->pending_requests) {
                evpl_http_request_free(http_conn->agent,
                                       http_conn->current_request);
            }
            http_conn->current_request = NULL;

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

            DL_DELETE(http_conn->agent->conns, http_conn);
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

/*
 * Append a formatted line into [rsp_base, rsp_base + cap) at *rsp,
 * advancing *rsp only by what vsnprintf actually had room to write, never
 * past the end of the buffer.  The add-time accounting against
 * max_header_size makes truncation unreachable here; this is the backstop
 * that keeps an accounting bug from becoming a heap overflow.
 */
static void
evpl_http_append_line(
    char       *rsp_base,
    size_t      cap,
    char      **rsp,
    const char *fmt,
    ...) __attribute__((format(printf, 4, 5)));

static void
evpl_http_append_line(
    char       *rsp_base,
    size_t      cap,
    char      **rsp,
    const char *fmt,
    ...)
{
    size_t  used = *rsp - rsp_base;
    size_t  remain;
    int     wanted;
    va_list ap;

    if (used >= cap) {
        return;
    }

    remain = cap - used;

    va_start(ap, fmt);
    wanted = vsnprintf(*rsp, remain, fmt, ap);
    va_end(ap);

    if (wanted < 0) {
        return;
    }

    if ((size_t) wanted >= remain) {
        *rsp = rsp_base + cap;
    } else {
        *rsp += wanted;
    }
} /* evpl_http_append_line */

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
    const unsigned int               cap = conn->agent->max_header_size;

    niov = evpl_iovec_alloc(evpl, cap, 4096, 1, 0, &iov);

    evpl_http_abort_if(niov < 0, "failed to allocate iovec");

    rsp_base = iov.data;
    rsp      = rsp_base;

    evpl_http_append_line(rsp_base, cap, &rsp, "%s %d %s\r\n",
                          http_version_string[request->http_version],
                          request->status,
                          evpl_http_response_status_string(request->status));

    DL_FOREACH(request->response_headers, header)
    {
        evpl_http_append_line(rsp_base, cap, &rsp, "%s: %s\r\n", header->name, header->value);
    }

    if (request->response_transfer_encoding == EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT) {
        evpl_http_append_line(rsp_base, cap, &rsp, "Content-Length: %" PRIu64 "\r\n", request->response_length);
    } else {
        evpl_http_append_line(rsp_base, cap, &rsp, "Transfer-Encoding: chunked\r\n");
    }

    evpl_http_append_line(rsp_base, cap, &rsp, "\r\n");

    evpl_http_abort_if((unsigned int) (rsp - rsp_base) >= cap,
                       "http response header block overflowed max_header_size");

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
    const unsigned int               cap = conn->agent->max_header_size;

    niov = evpl_iovec_alloc(evpl, cap, 4096, 1, 0, &iov);

    evpl_http_abort_if(niov < 0, "failed to allocate iovec");

    rsp_base = iov.data;
    rsp      = rsp_base;

    evpl_http_append_line(rsp_base, cap, &rsp, "%s %s HTTP/1.1\r\n",
                          evpl_http_method_to_wire(request->request_type),
                          request->uri);

    DL_FOREACH(request->request_headers, header)
    {
        evpl_http_append_line(rsp_base, cap, &rsp, "%s: %s\r\n", header->name, header->value);
    }

    if (request->response_transfer_encoding == EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED) {
        evpl_http_append_line(rsp_base, cap, &rsp, "Transfer-Encoding: chunked\r\n");
    } else {
        evpl_http_append_line(rsp_base, cap, &rsp, "Content-Length: %" PRIu64 "\r\n", request->response_length);
    }

    evpl_http_append_line(rsp_base, cap, &rsp, "\r\n");

    evpl_http_abort_if((unsigned int) (rsp - rsp_base) >= cap,
                       "http request header block overflowed max_header_size");

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

            chunk_hdr_len = snprintf(iov.data, 64, "%" PRIx64 "\r\n", chunk_length);

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
    int                       done, keep_alive;

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
            /* Read before the request is freed, because the answer belongs to
             * the request that was just answered. */
            keep_alive = evpl_http_response_keeps_alive(request);

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

            if (!keep_alive) {
                /* RFC 1945 section 1.4: an HTTP/1.0 exchange ends with the
                 * connection unless the peer asked for Keep-Alive.  evpl_finish
                 * flushes what is queued before closing, so the response the
                 * loop just produced still reaches the wire.  Nothing further
                 * on this connection can be answered, so the loop ends here
                 * rather than starting on a request the peer will never see. */
                evpl_finish(evpl, conn->bind);
                return;
            }
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

    DL_APPEND(server->agent->conns, http_conn);

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

    DL_APPEND(agent->conns, conn);

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
    struct evpl_http_agent   *agent = conn->agent;

    request               = evpl_http_request_alloc(agent);
    request->conn         = conn;
    request->request_type = method;
    request->uri_len      = evpl_copy_string(request->uri, url, sizeof(request->uri));

    /* seed the outbound accounting with "<METHOD> <uri> HTTP/1.1\r\n" */
    request->header_bytes = strlen(evpl_http_method_to_wire(method)) +
        request->uri_len + 12;

    if (request->header_bytes + EVPL_HTTP_HEADER_EMIT_RESERVE >
        agent->max_header_size) {
        evpl_http_debug("request line exceeds http max_header_size");
        evpl_http_request_free(agent, request);
        return NULL;
    }

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

SYMBOL_EXPORT int
evpl_http_request_add_header(
    struct evpl_http_request *request,
    const char               *name,
    const char               *value)
{
    return evpl_http_request_add_header_common(request, name, value, 1);
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

    /* What the response says about the connection, which is not a free choice:
     * "Connection: keep-alive" is the Keep-Alive extension's acknowledgement
     * (RFC 2068 section 19.7.1.1) and belongs only in a reply to a client that
     * asked for it -- sending it unsolicited to an HTTP/1.0 client that does
     * not implement the extension leaves it waiting on a close that has been
     * announced as not coming.  A server that is about to close says so
     * instead (RFC 7230 section 6.1).  An HTTP/1.1 response that is keeping
     * the connection says nothing at all, because that is already the
     * default. */
    if (!evpl_http_response_keeps_alive(request)) {
        evpl_http_request_add_header_common(request, "Connection", "close", 0);
    } else if (request->http_version == EVPL_HTTP_REQUEST_HTTP_VERSION_1_0) {
        evpl_http_request_add_header_common(request, "Connection", "keep-alive",
                                            0);
    }

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
