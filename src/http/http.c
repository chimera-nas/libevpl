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

/*
 * The Date header field's value for right now.
 *
 * RFC 9110 section 6.6.1: "An origin server with a clock MUST send a Date
 * header field in all [responses other than 1xx and 5xx]" -- everything
 * downstream that reasons about the age of a response starts from it, so a
 * response without one cannot be cached, revalidated, or have its freshness
 * computed at all.
 *
 * The format is IMF-fixdate (section 5.6.7), which is fixed-width, always
 * GMT, and always spelled in English regardless of locale.  That last part is
 * why the names are tables here rather than strftime's %a and %b, which are
 * locale-dependent: a server running under a French locale would otherwise
 * put "lun." on the wire and produce a date no recipient can parse.
 *
 * Recomputed at most once a second and cached on the agent, because it changes
 * that often and is needed on every response.
 */
const char *
evpl_http_date(struct evpl_http_agent *agent)
{
    static const char *const days[] = {
        "Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"
    };
    static const char *const months[] = {
        "Jan", "Feb", "Mar", "Apr", "May", "Jun",
        "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"
    };
    struct tm                tm;
    time_t                   now = time(NULL);

    if (now != agent->date_second) {
        gmtime_r(&now, &tm);

        snprintf(agent->date, sizeof(agent->date),
                 "%s, %02d %s %04d %02d:%02d:%02d GMT",
                 days[tm.tm_wday], tm.tm_mday, months[tm.tm_mon],
                 tm.tm_year + 1900, tm.tm_hour, tm.tm_min, tm.tm_sec);

        agent->date_second = now;
    }

    return agent->date;
} /* evpl_http_date */

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
    struct evpl_http_conn           *conn, *tmp;
    int                              live;

    /* Close and retire every live connection before freeing the agent.  Conn
     * binds hold notify callbacks that dereference the agent (the h2 receive
     * path reads conn->agent->evpl on every data event), so an agent freed
     * while a bind still has buffered input is a use-after-free as soon as
     * evpl_destroy's close pump delivers that data.  Pump the loop until the
     * disconnect notifications retire each conn (evpl_close is idempotent on
     * a bind already pending close).  Must run on the agent's evpl thread,
     * which every existing caller already does.
     *
     * A retired client connection that its owner never released has no bind
     * left to close and no notification left to wait for, so it is freed here
     * directly; waiting for one would not terminate. */
    while (agent->conns) {

        live = 0;

        DL_FOREACH_SAFE(agent->conns, conn, tmp)
        {
            if (conn->bind) {
                evpl_close(agent->evpl, conn->bind);
                live = 1;
            } else {
#ifdef __clang_analyzer__
                /* DL_DELETE asserts head != NULL but NDEBUG strips it in
                 * Release builds; guide the analyzer explicitly, as
                 * evpl_http_server_flush does for the same macro. */
                if (!agent->conns) {
                    break;
                }
#endif /* ifdef __clang_analyzer__ */
                DL_DELETE(agent->conns, conn);
                evpl_free(conn);
            }
        }

        if (live) {
            evpl_continue(agent->evpl);
        }
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

/* Linear white space, RFC 1945 section 2.2. */
static inline int
evpl_http_is_lws(char c)
{
    return c == ' ' || c == '\t';
} /* evpl_http_is_lws */

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
 * Give up on a client connection whose peer's response cannot be parsed.
 *
 * The reason is recorded on the connection so that the disconnect which
 * follows completes each outstanding request with it rather than with the
 * generic CONN_LOST.  "The peer sent something I cannot read" and "the peer
 * went away" ask for different things from a caller, and only one of them is
 * worth retrying against the same peer.
 */
static void
evpl_http_client_abandon(
    struct evpl_http_conn *conn,
    const char            *why)
{
    evpl_http_debug("unusable response: %s", why);

    conn->error = EVPL_HTTP_ERROR_BAD_RESPONSE;

    evpl_close(conn->agent->evpl, conn->bind);
} /* evpl_http_client_abandon */

/*
 * Whether this response carries no message-body, whatever its headers say.
 *
 * RFC 1945 section 8.2: "The HEAD method is identical to GET except that the
 * server must not return a message-body in the response" -- and the header
 * fields it does return are the ones a GET would have, Content-Length
 * included.  Sections 9.2.5 and 9.3.5 say the same of 204 and 304.  So on
 * these the length is a description of a body that is not here, and a client
 * that waits for it waits for bytes the peer will never send.
 */
static inline int
evpl_http_response_has_no_body(struct evpl_http_request *request)
{
    return request->request_type == EVPL_HTTP_REQUEST_TYPE_HEAD ||
           request->status / 100 == 1 ||
           request->status == 204 ||
           request->status == 304;
} /* evpl_http_response_has_no_body */

/*
 * Put a request back to waiting for a status line, having just finished one
 * that turned out not to be the answer.
 *
 * RFC 9110 section 15.2: a 1xx response is interim -- "A client MUST be able
 * to parse one or more 1xx responses received prior to a final response, even
 * if the client does not expect one" -- so it is a complete message that says
 * the real one is still coming.  Everything the header block established about
 * this message goes with it; the request itself is untouched, because it is
 * still outstanding.
 */
static void
evpl_http_request_reset_response(
    struct evpl_http_agent   *agent,
    struct evpl_http_request *request)
{
    struct evpl_http_request_header *header;

    while (request->response_headers) {
        header = request->response_headers;
        DL_DELETE(request->response_headers, header);
        evpl_http_request_header_free(agent, header);
    }

    request->request_state             = EVPL_HTTP_REQUEST_STATE_INIT;
    request->request_transfer_encoding =
        EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT;
    request->request_length     = 0;
    request->request_left       = 0;
    request->request_chunk_left = 0;
    request->header_bytes       = 0;
    request->status             = 0;
    request->request_flags     &= ~(EVPL_HTTP_REQUEST_HAVE_LENGTH |
                                    EVPL_HTTP_REQUEST_CLOSE_DELIMITED |
                                    EVPL_HTTP_REQUEST_EXPECT_CHUNK_NL |
                                    EVPL_HTTP_REQUEST_IN_TRAILER);
} /* evpl_http_request_reset_response */

/* How much to ask for at a time when the body's end is the connection close
 * rather than a length: there is no total to count down, so this is just a
 * read granularity. */
#define EVPL_HTTP_CLOSE_DELIMITED_CHUNK 65536

/*
 * Parse a chunk-size line.  Returns 0 and the size, or -1.
 *
 * RFC 9112 section 7.1:
 *
 *     chunk      = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
 *     chunk-size = 1*HEXDIG
 *     chunk-ext  = *( BWS ";" BWS chunk-ext-name [ BWS "=" BWS chunk-ext-val ] )
 *
 * so the line is hex digits and then either nothing or a semicolon.  strtoul
 * accepts a great deal more than that and reports none of it: a sign, leading
 * whitespace, any trailing junk, and -- the one that matters -- a line with no
 * digits at all, which it reads as zero.  Zero is the last-chunk, so a size
 * the sender spelled "zz" ends the content early and everything after it is
 * read as the start of the next request.  That is the chunked spelling of the
 * Content-Length desync, and it is why this needs a parser rather than a
 * library call that cannot fail.
 *
 * Section 7.1.1 has a recipient "ignore unrecognized chunk extensions", so
 * anything from the semicolon on is skipped without being understood.
 */
static int
evpl_http_parse_chunk_size(
    const char *line,
    uint64_t   *out)
{
    const char *p = line;
    uint64_t    v = 0, digit;

    if (!isxdigit((unsigned char) *p)) {
        return -1;
    }

    while (isxdigit((unsigned char) *p)) {
        digit = (uint64_t) (isdigit((unsigned char) *p) ? *p - '0' :
                            (tolower((unsigned char) *p) - 'a' + 10));
        p++;

        if (v > (UINT64_MAX - digit) / 16) {
            return -1;
        }

        v = v * 16 + digit;
    }

    /* Only a chunk extension may follow, and it may be preceded by bad
     * whitespace (RFC 9112 section 7.1's BWS). */
    while (evpl_http_is_lws(*p)) {
        p++;
    }

    if (*p && *p != ';') {
        return -1;
    }

    *out = v;

    return 0;
} /* evpl_http_parse_chunk_size */

/*
 * Keep one line of an inbound HTTP/1.x trailer section (RFC 9112 section
 * 7.1.2), which has the field-line form of a header.  A line that does not
 * parse as one, or a field past the max_header_size accounting, is consumed
 * without being kept -- see the trailer loop in evpl_http_handle_body for why
 * that is tolerance rather than an error.
 */
static void
evpl_http_store_trailer_line(
    struct evpl_http_request *request,
    char                     *line)
{
    struct evpl_http_agent          *agent = request->conn->agent;
    struct evpl_http_request_header *header;
    char                            *name, *value, *saveptr;
    unsigned int                     line_bytes;

    name = strtok_r(line, ":", &saveptr);

    if (!name) {
        return;
    }

    value = strtok_r(NULL, "", &saveptr);

    if (!value) {
        return;
    }

    while (*value == ' ') {
        value++;
    }

    line_bytes = strlen(name) + strlen(value) + 4;

    if (request->recv_trailer_bytes + line_bytes > agent->max_header_size) {
        return;
    }

    request->recv_trailer_bytes += line_bytes;

    header = evpl_http_request_header_alloc(agent);

    strncpy(header->name, name, sizeof(header->name) - 1);
    strncpy(header->value, value, sizeof(header->value) - 1);

    DL_APPEND(request->recv_trailers, header);
} /* evpl_http_store_trailer_line */

/*
 * Parse content (Content-Length or chunked) from the wire into
 * request->recv_ring and emit RECEIVE_DATA / RECEIVE_COMPLETE notifications.
 * Shared by the server (request content) and client (response content)
 * HTTP/1.x paths: the only differences are which list the request lives on
 * when complete (the caller handles that via the COMPLETE transition) and the
 * private data passed to the callback.
 *
 * Returns 0 on success, or -1 if the chunked framing is malformed -- which the
 * caller has to answer, because a server owes the peer a status and a client
 * has nobody to give one to.  *why says which malformation, for the caller's
 * message.
 */
static int
evpl_http_handle_body(
    struct evpl_http_conn    *conn,
    struct evpl_http_request *request,
    const char              **why)
{
    struct evpl_http_agent *agent = conn->agent;
    struct evpl            *evpl  = agent->evpl;
    struct evpl_bind       *bind  = conn->bind;
    void                   *priv  = evpl_http_priv(conn);
    int                     rc;
    char                    line[4096];

#ifdef __clang_analyzer__
    /*
     * evpl_http_parse_line always NUL-terminates this buffer before returning
     * 0, but it does so through a pointer the analyzer can only bound relative
     * to the buffer rather than pin to an index -- so it loses the terminating
     * store, and then explores a path where evpl_http_parse_chunk_size walks
     * off the end of a line that was never written.  Neither restructuring the
     * termination as an indexed store nor terminating the buffer up front
     * changes that: the copy loop's stores are what it cannot follow.
     *
     * Zeroing under the analyzer removes the false path and costs nothing in
     * a real build, where this is four kilobytes of stack per body chunk
     * parsed.
     */
    memset(line, 0, sizeof(line));
#endif /* ifdef __clang_analyzer__ */

    if (request->request_transfer_encoding == EVPL_HTTP_REQUEST_TRANSFER_ENCODING_DEFAULT) {
        int               niov;
        int               close_delimited = (request->request_flags &
                                             EVPL_HTTP_REQUEST_CLOSE_DELIMITED) != 0;
        struct evpl_iovec iov;

        while (!evpl_iovec_ring_is_full(&request->recv_ring) &&
               (close_delimited || request->request_left > 0)) {
            niov = evpl_recvv(evpl, bind, &iov, 1,
                              close_delimited ?
                              EVPL_HTTP_CLOSE_DELIMITED_CHUNK :
                              evpl_http_recv_chunk(request->request_left), NULL);

            if (niov <= 0) {
                break;
            }

            if (!close_delimited) {
                request->request_left -= iov.length;
            }

            evpl_iovec_ring_add(&request->recv_ring, &iov);
        }

        if (request->notify_callback && evpl_iovec_ring_elements(&request->recv_ring) > 0) {
            request->notify_callback(evpl, agent, request,
                                     EVPL_HTTP_NOTIFY_RECEIVE_DATA,
                                     request->request_type, request->uri,
                                     request->notify_data, priv);
        }

        /* A close-delimited body has no length to count down: it ends when the
         * connection does, which the disconnect path turns into the
         * completion. */
        if (!close_delimited && request->request_left == 0) {
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
                    *why = "chunked framing line too long";
                    return -1;
                }

                if (rc == -1) {
                    break;
                }

                if (request->request_flags & EVPL_HTTP_REQUEST_EXPECT_CHUNK_NL) {
                    /* The CRLF that closes a chunk's data.  Anything else and
                     * the declared size did not describe the data, so the next
                     * size line would be read from inside the content. */
                    if (line[0] != '\0') {
                        *why = "chunk data is not followed by CRLF";
                        return -1;
                    }
                    request->request_flags &= ~EVPL_HTTP_REQUEST_EXPECT_CHUNK_NL;
                    continue;
                }

                if (request->request_flags & EVPL_HTTP_REQUEST_IN_TRAILER) {
                    /* RFC 9112 section 7.1.2's trailer section: zero or more
                     * field lines, then the empty one that ends the coding.
                     * Consuming it is not optional even where nothing reads
                     * it -- a trailer left in the stream is read as the
                     * start of the next request on a connection HTTP/1.1
                     * keeps open by default.
                     *
                     * Fields that parse are kept, for the application to read
                     * back through evpl_http_request_trailer once receive
                     * completes.  Lines that are not field lines are consumed
                     * without becoming fields, as are fields past the
                     * accounting limit: section 6.5 allows a recipient to
                     * discard trailers, and a malformed line here -- unlike
                     * one in the header block -- delimits nothing, so
                     * tolerating it loses only the field it failed to be. */
                    if (line[0] == '\0') {
                        request->request_state = EVPL_HTTP_REQUEST_STATE_COMPLETE;
                        break;
                    }

                    evpl_http_store_trailer_line(request, line);
                    continue;
                }

                if (evpl_http_parse_chunk_size(line,
                                               &request->request_chunk_left) < 0) {
                    *why = "chunk size is not a hexadecimal number of octets";
                    return -1;
                }

                if (request->request_chunk_left == 0) {
                    /* The last-chunk carries no data and so no CRLF of its
                     * own: what follows is the trailer section. */
                    request->request_flags |= EVPL_HTTP_REQUEST_IN_TRAILER;
                    continue;
                }

                request->request_flags |= EVPL_HTTP_REQUEST_EXPECT_CHUNK_NL;
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
 * outbound header block that are not application-added headers.  A response
 * carries the status line (<= 47 bytes), the Content-Length or
 * Transfer-Encoding line (<= 38), the "Date: <IMF-fixdate>\r\n" (37), the
 * internally added "Connection: keep-alive\r\n" (24) and the terminating
 * "\r\n" (2); a request carries the framing line, a generated "Host: ...\r\n"
 * (<= 136, the conn's host buffer plus the field name) and the terminator,
 * with its request line instead counted exactly at create time.  The reserve
 * covers the larger of the two.  Enforcing the limit minus it at
 * evpl_http_request_add_header() time means emission can never overflow the
 * buffer it allocates.
 */
#define EVPL_HTTP_HEADER_EMIT_RESERVE 256

/*
 * Whether a field name is a token, which RFC 9110 section 5.1 requires:
 *
 *     field-name = token
 *     token      = 1*tchar
 *     tchar      = "!" / "#" / "$" / "%" / "&" / "'" / "*" / "+" / "-" / "."
 *                / "^" / "_" / "`" / "|" / "~" / DIGIT / ALPHA
 *
 * A name that is not one cannot be emitted as a field: a space or a colon in
 * it makes the receiver read a different field, or none.
 */
static int
evpl_http_field_name_is_token(const char *name)
{
    const char *p = name;

    if (!*p) {
        return 0;
    }

    for (; *p; p++) {
        if (isalnum((unsigned char) *p) || strchr("!#$%&'*+-.^_`|~", *p)) {
            continue;
        }

        return 0;
    }

    return 1;
} /* evpl_http_field_name_is_token */

/*
 * Whether a field value can be emitted as written.
 *
 * RFC 9110 section 5.5 puts CR and LF outside the field-value grammar --
 * field-vchar is VCHAR or obs-text, and neither includes a CTL -- and says of
 * them: "Field values containing CR, LF, or NUL characters are invalid and
 * dangerous, due to the varying ways that implementations might parse and
 * interpret those characters; a recipient of CR, LF, or NUL within a field
 * value MUST either reject the message or replace each of those characters
 * with SP before further processing or forwarding of that message."
 *
 * What makes them dangerous is what happens where a recipient does neither: a
 * CRLF inside a value ends the field, so everything after it is read as
 * further fields -- and after a second CRLF, as the message content.  That is
 * response splitting, and the application supplying the value is usually not
 * the component that chose it: it is a header echoed from a request, a
 * redirect target built from a query parameter, a name out of a database.  A
 * library that emits it anyway turns every such place into an injection point.
 *
 * NUL needs no test of its own -- the value arrives as a C string, so it ends
 * there.
 */
static int
evpl_http_field_value_is_safe(const char *value)
{
    const char *p;

    for (p = value; *p; p++) {
        if (*p == '\r' || *p == '\n') {
            return 0;
        }
    }

    return 1;
} /* evpl_http_field_value_is_safe */

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

    /* Checked before anything is allocated, and on the library's own headers
     * as well as the application's: the cost is a pass over two short strings,
     * and the alternative is a rule that holds only where someone remembered
     * to apply it. */
    if (unlikely(!evpl_http_field_name_is_token(name) ||
                 !evpl_http_field_value_is_safe(value))) {
        evpl_http_error("refusing to emit header '%s': "
                        "not a field name and value", name);
        return -1;
    }

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
 * Step over one element of a comma-separated field value (RFC 9110 section
 * 5.6.1's "#rule"), advancing *pp past it.  Returns the element with its
 * surrounding whitespace stripped and its length through *len, or NULL once
 * the list is exhausted.  Empty elements are legal in a #rule and are skipped
 * rather than reported.
 */
static const char *
evpl_http_next_element(
    const char **pp,
    size_t      *len)
{
    const char *p = *pp, *start, *end;

    while (evpl_http_is_lws(*p) || *p == ',') {
        p++;
    }

    if (!*p) {
        *pp = p;
        return NULL;
    }

    start = end = p;

    while (*end && *end != ',') {
        end++;
    }

    *pp = *end ? end + 1 : end;

    while (end > start && evpl_http_is_lws(*(end - 1))) {
        end--;
    }

    *len = (size_t) (end - start);

    return start;
} /* evpl_http_next_element */

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
    const char *p = value, *element;
    size_t      len, want = strlen(token);

    while ((element = evpl_http_next_element(&p, &len)) != NULL) {
        if (len == want && strncasecmp(element, token, want) == 0) {
            return 1;
        }
    }

    return 0;
} /* evpl_http_value_has_token */

/* Whether a list element is the chunked transfer coding. */
static inline int
evpl_http_element_is_chunked(
    const char *element,
    size_t      len)
{
    return len == 7 && strncasecmp(element, "chunked", 7) == 0;
} /* evpl_http_element_is_chunked */

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

/* What the transfer codings on a message add up to. */
enum evpl_http_coding {
    EVPL_HTTP_CODING_NONE,     /* no Transfer-Encoding field at all      */
    EVPL_HTTP_CODING_CHUNKED,  /* chunked, and chunked alone, is final   */
    EVPL_HTTP_CODING_OTHER,    /* a coding this end does not implement,
                                * or chunked somewhere other than last   */
};

/*
 * Which transfer coding delimits a response's content.
 *
 * The response half of the request-side rule, and simpler because a client has
 * nobody to complain to: RFC 9112 section 6.3 item 5 makes a coding that is
 * not chunked, or a chunked that is not final, mean "read until the connection
 * closes" rather than an error.  So the only distinction that matters here is
 * chunked-and-nothing-else against everything else.
 */
static enum evpl_http_coding
evpl_http_response_coding(struct evpl_http_request *request)
{
    struct evpl_http_request_header *header;
    const char *p, *element;
    size_t len;
    enum evpl_http_coding            coding = EVPL_HTTP_CODING_NONE;

    DL_FOREACH(request->response_headers, header)
    {
        if (strcasecmp(header->name, "Transfer-Encoding") != 0) {
            continue;
        }

        p = header->value;

        while ((element = evpl_http_next_element(&p, &len)) != NULL) {
            coding = evpl_http_element_is_chunked(element, len) ?
                EVPL_HTTP_CODING_CHUNKED : EVPL_HTTP_CODING_OTHER;
        }

        if (coding == EVPL_HTTP_CODING_NONE) {
            /* The field was there but named no coding at all. */
            coding = EVPL_HTTP_CODING_OTHER;
        }
    }

    return coding;
} /* evpl_http_response_coding */

/*
 * Decide how the request's content is delimited, once the whole header block
 * has arrived.
 *
 * Every rule here is about the block as a whole -- how many Host fields it
 * carried, which transfer codings it named and in what order, whether both
 * ways of delimiting content appear -- so it runs once at the end rather than
 * field by field as they arrive.  Doing it incrementally gets the ordering
 * questions wrong: a Content-Length that follows a Transfer-Encoding is the
 * same defect as one that precedes it, and whether the chunked coding is final
 * is not knowable until the list is finished.
 *
 * Returns 0, having set request_transfer_encoding, or the status to refuse the
 * request with and *why filled in.
 */
static int
evpl_http_request_framing(
    struct evpl_http_request *request,
    const char              **why)
{
    struct evpl_http_request_header *header;
    const char                      *p, *element;
    size_t                           len;
    int                              hosts = 0, coded = 0;
    int                              chunked_last = 0, extra = 0, not_final = 0;

    DL_FOREACH(request->request_headers, header)
    {
        if (strcasecmp(header->name, "Host") == 0) {
            hosts++;
            continue;
        }

        if (strcasecmp(header->name, "Transfer-Encoding") != 0) {
            continue;
        }

        coded = 1;
        p     = header->value;

        /* A transfer coding list may be split across several fields, so the
         * codings are walked in the order they appear across all of them:
         * "Transfer-Encoding: gzip" followed by "Transfer-Encoding: chunked"
         * says the same thing as one field naming both. */
        while ((element = evpl_http_next_element(&p, &len)) != NULL) {

            if (chunked_last) {
                /* Something follows a chunked, so chunked was not final. */
                not_final = 1;
            }

            if (evpl_http_element_is_chunked(element, len)) {
                chunked_last = 1;
            } else {
                chunked_last = 0;
                extra        = 1;
            }
        }
    }

    /* RFC 9112 section 3.2: "A server MUST respond with a 400 (Bad Request)
     * status code to any HTTP/1.1 request message that lacks a Host header
     * field and to any request message that contains more than one Host header
     * field."  The routing decision depends on it, and a request that leaves
     * it ambiguous is one a front end and a back end can route differently.
     * HTTP/1.0 has no Host at all, so the same bytes are a perfectly good
     * HTTP/1.0 request. */
    if (request->http_version == EVPL_HTTP_REQUEST_HTTP_VERSION_1_1 &&
        hosts != 1) {
        *why = hosts ? "more than one Host field on an HTTP/1.1 request"
                     : "HTTP/1.1 request with no Host field";
        return 400;
    }

    if (!coded) {
        /* RFC 1945 section 8.3: "A valid Content-Length is required on all
         * HTTP/1.0 POST requests.  An HTTP/1.0 server should respond with a
         * 400 (bad request) message if it cannot determine the length of the
         * request message's content."  HTTP/1.1 gave a request with no length
         * a defined meaning instead -- no content at all (RFC 9112 section
         * 6.3) -- so this applies to 1.0 alone. */
        if (request->request_type == EVPL_HTTP_REQUEST_TYPE_POST &&
            request->http_version == EVPL_HTTP_REQUEST_HTTP_VERSION_1_0 &&
            !(request->request_flags & EVPL_HTTP_REQUEST_HAVE_LENGTH)) {
            *why = "HTTP/1.0 POST without Content-Length";
            return 400;
        }

        return 0;
    }

    /* RFC 9112 section 6.1: "A client MUST NOT send a request containing
     * Transfer-Encoding unless it knows the server will handle HTTP/1.1 (or
     * later) requests."  HTTP/1.0 has no transfer codings, so a request that
     * claims HTTP/1.0 and then uses one has no framing the two ends can agree
     * on -- and a front end that reads the version while a back end reads the
     * coding disagree about where the message ends, which is the whole of a
     * request-smuggling attack. */
    if (request->http_version == EVPL_HTTP_REQUEST_HTTP_VERSION_1_0) {
        *why = "Transfer-Encoding on an HTTP/1.0 request";
        return 400;
    }

    /* RFC 9112 section 6.3, rule 3: a message carrying both "might indicate an
     * attempt to perform request smuggling ... or response splitting ... and
     * ought to be handled as an error" -- and RFC 9110 section 8.6 makes
     * sending the pair a MUST NOT in the first place.  Two framings that
     * disagree is the same defect as two Content-Lengths that disagree, and
     * gets the same answer. */
    if (request->request_flags & EVPL_HTTP_REQUEST_HAVE_LENGTH) {
        *why = "both Content-Length and Transfer-Encoding";
        return 400;
    }

    /* Section 6.3, rule 4: "If a Transfer-Encoding header field is present in
     * a request and the chunked transfer coding is not the final encoding, the
     * message body length cannot be determined reliably; the server MUST
     * respond with the 400 (Bad Request) status code and then close the
     * connection." */
    if (!chunked_last || not_final) {
        *why = "the chunked coding is not the final transfer coding";
        return 400;
    }

    /* Chunked is final, so the message can be delimited -- but a coding inside
     * it that the server does not implement leaves it unable to do anything
     * with the content.  Section 6.1: "A server that receives a request
     * message with a transfer coding it does not understand SHOULD respond
     * with 501 (Not Implemented)." */
    if (extra) {
        *why = "unsupported transfer coding";
        return 501;
    }

    request->request_transfer_encoding =
        EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED;

    return 0;
} /* evpl_http_request_framing */

/*
 * How many requests the server will read ahead of the responses it has sent.
 *
 * Pipelining is worth supporting -- RFC 9112 section 9.3.2 permits a client to
 * send the next request without waiting, and requires the responses in order
 * -- but each request read ahead is a request struct held for however long the
 * peer chooses to take, so an unbounded read-ahead lets a peer turn one large
 * write into an allocation per request in it.  Small on purpose: pipelining
 * exists to hide round-trip latency, and a handful in flight does that.
 */
#define EVPL_HTTP_MAX_PIPELINE 8

static int
evpl_http_pipeline_depth(struct evpl_http_conn *conn)
{
    struct evpl_http_request *request;
    int                       depth = 0;

    DL_FOREACH(conn->pending_requests, request)
    {
        depth++;
    }

    return depth;
} /* evpl_http_pipeline_depth */

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
    struct evpl_http_conn *conn,
    int                    status,
    const char            *why)
{
    struct evpl_http_agent *agent = conn->agent;
    struct evpl            *evpl  = agent->evpl;
    struct evpl_bind       *bind  = conn->bind;
    char                    rsp[256];
    int                     len;

    evpl_http_debug("refusing request with %d: %s", status, why);

    len = snprintf(rsp, sizeof(rsp),
                   "HTTP/1.1 %d %s\r\n"
                   "Date: %s\r\n"
                   "Content-Length: 0\r\n"
                   "Connection: close\r\n"
                   "\r\n",
                   status, evpl_http_response_status_string(status),
                   evpl_http_date(agent));

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
    const char                      *why;
    char                             line[4096];
    int                              rc, folded, status;
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
            evpl_http_server_reject(conn,
                                    400, "request line too long");
            return;
        }

        if (rc == -1) {
            return;
        }

        /* RFC 9112 section 2.2: "In the interest of robustness, a server that
         * is expecting to receive and parse a request-line SHOULD ignore at
         * least one empty line (CRLF) received prior to the request-line."
         * That empty line is what a client leaves behind when it miscounts a
         * previous request's content, and answering 400 to the request that
         * follows makes one client's arithmetic error look like a rejection of
         * a request that is otherwise perfectly good.
         *
         * Counted against the header budget rather than skipped forever,
         * because "ignore an empty line" and "read empty lines from this peer
         * indefinitely" are not the same offer. */
        if (line[0] == '\0') {
            request->header_bytes += 2;

            if (unlikely(request->header_bytes > agent->max_header_size)) {
                evpl_http_server_reject(conn, 400,
                                        "empty lines before the request line "
                                        "exceed max_header_size");
                return;
            }

            goto again;
        }

        /* RFC 1945 section 5.1 is exact -- Method SP Request-URI SP
         * HTTP-Version -- and section 19.3 asks a server to tolerate any
         * amount of SP or HT *between* those fields, which is what strtok_r
         * gives.  What it does not ask for is tolerating a run before the
         * first one: strtok_r skips leading delimiters too, so " /echo
         * HTTP/1.0" would otherwise parse as a request whose method is the
         * URI. */
        if (line[0] == ' ' || line[0] == '\t') {
            evpl_http_server_reject(conn,
                                    400,
                                    "request line starts with whitespace");
            return;
        }

        token = strtok_r(line, " \t", &saveptr);

        if (!token) {
            evpl_http_server_reject(conn,
                                    400, "empty request line");
            return;
        }

        request->request_type = evpl_http_method_from_string(token);

        if (request->request_type == EVPL_HTTP_REQUEST_TYPE_UNKNOWN) {
            /* RFC 1945 section 5.1.1: Method is a token, and tokens are
             * case-sensitive, so a lowercased "get" is as unknown as "FROB" --
             * a server that folds case before comparing accepts a request the
             * grammar does not describe. */
            evpl_http_server_reject(conn,
                                    501, "unsupported method");
            return;
        }

        token = strtok_r(NULL, " \t", &saveptr);
        if (!token) {
            evpl_http_server_reject(conn,
                                    400, "missing uri");
            return;
        }

        request->uri_len = evpl_copy_string(request->uri, token, sizeof(request->uri));

        token = strtok_r(NULL, " \t", &saveptr);

        if (!token) {
            evpl_http_server_reject(conn,
                                    400, "missing http version");
            return;
        }

        if (evpl_http_parse_version(token, &major, &minor) < 0 || major != 1) {
            /* RFC 1945 names no code for a version it cannot serve -- 505 is
             * an HTTP/1.1 addition -- so a request line the grammar does not
             * describe is a malformed one. */
            evpl_http_server_reject(conn,
                                    400, "unsupported http version");
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
            evpl_http_server_reject(conn,
                                    400,
                                    "trailing token on the request line");
            return;
        }

        request->request_state = EVPL_HTTP_REQUEST_STATE_HEADERS;

        goto again;

    } else if (request->request_state == EVPL_HTTP_REQUEST_STATE_HEADERS) {
        rc = evpl_http_parse_line(evpl, bind, line, sizeof(line));

        if (unlikely(rc == -2)) {
            evpl_http_server_reject(conn,
                                    400,
                                    "header line overflowed the parse buffer");
            return;
        }

        if (rc == -1) {
            return;
        }

        if (line[0] == '\0') {

            /* The block is complete, so the framing rules that are about the
             * block as a whole can be applied. */
            status = evpl_http_request_framing(request, &why);

            if (status) {
                evpl_http_server_reject(conn, status, why);
                return;
            }

            /* inbound header block complete; reset the accounting for the
             * outbound response block the application builds from here */
            request->header_bytes  = 0;
            request->request_state = EVPL_HTTP_REQUEST_STATE_BODY;

            /* RFC 9110 section 10.1.1: "A server that receives a 100-continue
             * expectation in an HTTP/1.0 request MUST ignore that
             * expectation."  An HTTP/1.0 client has no way to tell an interim
             * response from the answer -- 1xx is an HTTP/1.1 concept -- so it
             * reads the 100 as the response to its request and everything
             * after it as content. */
            if ((request->request_flags & EVPL_HTTP_REQUEST_WANTS_CONTINUE) &&
                request->http_version == EVPL_HTTP_REQUEST_HTTP_VERSION_1_1) {
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
                evpl_http_server_reject(conn,
                                        400,
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
                    evpl_http_server_reject(conn,
                                            400,
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
                    evpl_http_server_reject(conn,
                                            400,
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
                    evpl_http_server_reject(conn,
                                            400,
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
                    evpl_http_server_reject(conn,
                                            400,
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
            }

            /* Host and Transfer-Encoding are deliberately NOT handled here:
             * what they mean depends on the whole header block rather than on
             * one field, so evpl_http_request_framing decides both once the
             * block is complete. */
        }

        goto again;

    } else if (request->request_state == EVPL_HTTP_REQUEST_STATE_BODY) {

        if (evpl_http_handle_body(conn, request, &why) < 0) {
            /* A malformed chunked framing is a request the server cannot find
             * the end of, which is a 400 like any other syntax it cannot parse
             * -- and closing without a status leaves the client unable to tell
             * a refused request from a broken server. */
            evpl_http_server_reject(conn, 400, why);
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

            /*
             * Keep parsing.  RFC 9112 section 9.3.2 lets a client send its
             * next request without waiting for this response, and requires the
             * server to answer "in the same order that the requests were
             * received" -- but before ordering can mean anything the server
             * has to notice the second request at all, and stopping here would
             * leave it in a buffer with no read event left to announce it.  A
             * client that pipelined two requests in one write would then wait
             * for a response the server has decided not to look for.
             *
             * Bounded, because every request read ahead is a request struct
             * held for as long as the peer chooses: a megabyte of pipelined
             * requests in a single write must not turn into a request per
             * request.  Parsing resumes as the responses drain, which
             * evpl_http_server_flush arranges.
             */
            if (evpl_http_pipeline_depth(conn) < EVPL_HTTP_MAX_PIPELINE) {
                conn->current_request       = evpl_http_request_alloc(agent);
                conn->current_request->conn = conn;
                request                     = conn->current_request;
                goto again;
            }
        }
    } else {
        abort();
    }
} /* evpl_http_server_handle_data */

/*
 * The pipeline read-ahead cap stopped parsing and a response has since
 * drained, so there may be a request waiting in a buffer that no read event
 * will announce again.  Deferred rather than called from the flush path
 * directly, so that parsing a request never runs inside the loop writing a
 * response.
 */
static void
evpl_http_parse_deferred(
    struct evpl *evpl,
    void        *arg)
{
    struct evpl_http_conn *conn = arg;

    if (conn->bind && conn->is_server) {
        evpl_http_server_handle_data(conn);
    }
} /* evpl_http_parse_deferred */

static void
evpl_http_client_handle_data(struct evpl_http_conn *conn)
{
    struct evpl_http_agent          *agent = conn->agent;
    struct evpl                     *evpl  = agent->evpl;
    struct evpl_bind                *bind  = conn->bind;
    struct evpl_http_request        *request;
    struct evpl_http_request_header *header;
    const char                      *why;
    enum evpl_http_coding            coding;
    char                             line[4096];
    int                              rc, folded;
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
            evpl_http_client_abandon(conn, "status line too long");
            return;
        }

        if (rc == -1) {
            return;
        }

        /* Status-Line = HTTP-Version SP Status-Code SP Reason-Phrase (RFC 1945
         * section 6.1), and as on the request line a leading run of LWS is not
         * between fields, so strtok_r must not be allowed to skip it. */
        if (evpl_http_is_lws(line[0])) {
            evpl_http_client_abandon(conn, "status line starts with whitespace");
            return;
        }

        token = strtok_r(line, " \t", &saveptr);

        if (!token) {
            evpl_http_client_abandon(conn, "missing status line version");
            return;
        }

        if (evpl_http_parse_version(token, &major, &minor) < 0 || major != 1) {
            evpl_http_client_abandon(conn, "unsupported http version");
            return;
        }

        /* RFC 2145 section 2.3, the mirror of the request-side rule: a higher
         * minor version is a response to be read at the highest 1.x this
         * client speaks, not one to refuse. */
        request->http_version = minor ? EVPL_HTTP_REQUEST_HTTP_VERSION_1_1
                                      : EVPL_HTTP_REQUEST_HTTP_VERSION_1_0;

        token = strtok_r(NULL, " \t", &saveptr);

        if (!token) {
            evpl_http_client_abandon(conn, "missing status code");
            return;
        }

        if (evpl_http_parse_status(token, &request->status) < 0) {
            evpl_http_client_abandon(conn, "malformed status code");
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
            evpl_http_client_abandon(conn, "header line too long");
            return;
        }

        if (rc == -1) {
            return;
        }

        if (line[0] == '\0') {

            /* An interim response is not the answer.  RFC 9110 section 15.2
             * makes 1xx "an interim response for communicating connection
             * status or request progress prior to completing the requested
             * action and sending a final response", and lets a user agent
             * ignore one it did not ask for -- but not mistake it for the
             * result.  Reporting it as one loses the real response, which then
             * arrives on a connection the client believes is idle.  The
             * message ends with its header block, so what follows is the next
             * status line for this same request. */
            if (request->status / 100 == 1) {
                evpl_http_debug("skipping interim %d response",
                                request->status);
                evpl_http_request_reset_response(agent, request);
                goto again;
            }

            /* The header block is complete, so the content's framing is now
             * decided.  RFC 9112 section 6.3 lists the ways in order of
             * precedence, and this is that list.
             *
             * First: RFC 1945 sections 8.2/9.2.5/9.3.5 and RFC 9112 section
             * 6.3, a response to HEAD and the 1xx, 204 and 304 statuses are
             * "always terminated by the first empty line after the header
             * fields, regardless of the header fields present in the message"
             * -- so a Content-Length on one of them describes the content a
             * GET would have returned, and waiting for those bytes waits
             * forever. */
            if (evpl_http_response_has_no_body(request)) {
                request->request_length = 0;
                request->request_left   = 0;
            } else {
                coding = evpl_http_response_coding(request);

                /* Section 6.1: both framings at once "might indicate an
                 * attempt to perform ... response splitting ... and ought to
                 * be handled as an error".  Where this response ends, and
                 * anything after it begins, would otherwise be the peer's
                 * choice rather than the client's. */
                if (coding != EVPL_HTTP_CODING_NONE &&
                    (request->request_flags & EVPL_HTTP_REQUEST_HAVE_LENGTH)) {
                    evpl_http_client_abandon(conn,
                                             "both Content-Length and Transfer-Encoding");
                    return;
                }

                if (coding == EVPL_HTTP_CODING_CHUNKED) {
                    request->request_transfer_encoding =
                        EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED;
                } else if (!(request->request_flags &
                             EVPL_HTTP_REQUEST_HAVE_LENGTH)) {
                    /* Section 6.3 item 5 covers a coding that is not chunked
                     * or not final, and item 7 covers no framing at all; both
                     * end the same way -- "the message body length is
                     * determined by reading the connection until it is closed
                     * by the server".  That is the only framing available for
                     * content whose size the server does not know when it
                     * starts writing, so a client that reads such a response
                     * as empty silently drops every streamed reply it is ever
                     * sent. */
                    request->request_flags |= EVPL_HTTP_REQUEST_CLOSE_DELIMITED;
                }
            }

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
                evpl_http_client_abandon(conn,
                                         "header block exceeds max_header_size");
                return;
            }

            folded = evpl_http_is_lws(line[0]);

            if (folded) {
                /* A continuation of the field above -- see the request path,
                 * which this mirrors. */
                header = request->response_headers ?
                    request->response_headers->prev : NULL;

                if (!header) {
                    evpl_http_client_abandon(conn,
                                             "continuation line with no field");
                    return;
                }

                evpl_http_fold_header_line(header, line);
            } else {
                header = evpl_http_request_header_alloc(agent);

                if (evpl_http_parse_header_line(line, header) < 0) {
                    /* As on the request path: the header is not on any list
                     * yet, so dropping it strands it and the free-list tail
                     * behind it. */
                    evpl_http_request_header_free(agent, header);
                    evpl_http_client_abandon(conn, "malformed header line");
                    return;
                }

                DL_APPEND(request->response_headers, header);
            }

            if (strcasecmp(header->name, "Content-Length") == 0) {
                /* The mirror of the request path, and for the same reasons: a
                 * response length that is not a decimal number of octets
                 * cannot delimit the body, and two that disagree leave it with
                 * no single length -- so where this response ends and anything
                 * after it begins would be the peer's choice.  A client has no
                 * status to answer with, so the connection goes. */
                if (evpl_http_parse_content_length(header->value, &length) < 0) {
                    evpl_http_client_abandon(conn,
                                             "Content-Length is not a decimal number of octets");
                    return;
                }

                if (!folded &&
                    (request->request_flags & EVPL_HTTP_REQUEST_HAVE_LENGTH) &&
                    length != request->request_length) {
                    evpl_http_client_abandon(conn,
                                             "conflicting Content-Length");
                    return;
                }

                request->request_flags |= EVPL_HTTP_REQUEST_HAVE_LENGTH;
                request->request_length = length;
                request->request_left   = length;
            }

            /* Transfer-Encoding is deliberately NOT handled here: which coding
             * is the final one, and whether it collides with a length, are
             * properties of the whole block -- see the block-complete branch
             * above. */
        }

        goto again;

    } else if (request->request_state == EVPL_HTTP_REQUEST_STATE_BODY) {

        if (evpl_http_handle_body(conn, request, &why) < 0) {
            /* A client has no status to answer with, so the connection goes --
             * and the reason travels with it, so the caller learns that the
             * peer sent something unreadable rather than that it went away. */
            evpl_http_client_abandon(conn, why);
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

            /* The next response may already be in the buffer.  A caller that
             * dispatched two requests before either was answered gets both
             * replies in whatever writes the server chose, and quite possibly
             * in one -- at which point the read event that carried the second
             * has already been delivered and no further one is coming.
             * Stopping here would strand the second caller for good. */
            if (conn->pending_requests) {
                conn->current_request = conn->pending_requests;
                request               = conn->current_request;
                goto again;
            }
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

            /* A deferral armed on this connection would otherwise run after it
             * is gone: the array holds the pointer, and nothing else takes it
             * out.  Both are pointless now in any case -- there is no bind
             * left to write a response to or read a request from. */
            evpl_remove_deferral(evpl, &http_conn->flush);
            evpl_remove_deferral(evpl, &http_conn->parse);

#ifdef HAVE_NGHTTP2
            if (http_conn->proto == EVPL_HTTP_PROTO_H2) {
                evpl_http2_conn_destroy(http_conn);
            }
#endif /* ifdef HAVE_NGHTTP2 */

            /* A close-delimited response body ends exactly here: RFC 1945
            * section 7.2.2 makes the connection close the delimiter, so this
            * FIN is the last byte of the message rather than the loss of one.
            * Complete the request before the teardown below frees it --
            * otherwise the whole body is parsed, buffered, and then dropped,
            * which a caller cannot tell from a response that had none. */
            request = http_conn->current_request;

            if (!http_conn->is_server && request &&
                (request->request_flags &
                 EVPL_HTTP_REQUEST_CLOSE_DELIMITED) &&
                request->request_state == EVPL_HTTP_REQUEST_STATE_BODY) {

                request->request_state = EVPL_HTTP_REQUEST_STATE_COMPLETE;

                if (request->notify_callback) {
                    request->notify_callback(evpl, http_conn->agent, request,
                                             EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE,
                                             request->request_type,
                                             request->uri,
                                             request->notify_data,
                                             http_conn->private_data);
                }
            }

            /*
             * Everything still outstanding is over and cannot complete: no
             * response can arrive for a client's requests now, and a server
             * has nowhere left to send the ones it was answering.  Tell each
             * caller so, rather than freeing the request behind its back --
             * a callback that never runs leaves an application waiting on a
             * completion that is already impossible, and still holding
             * whatever it attached to the request.
             *
             * The reason separates a peer that went away from one that sent
             * something unparseable, which the parse paths record on the
             * connection before they close.
             */
            DL_FOREACH_SAFE(http_conn->pending_requests, request, next)
            {
                if (request->request_state ==
                    EVPL_HTTP_REQUEST_STATE_COMPLETE) {
                    /* The close-delimited case just above: answered, not
                     * abandoned. */
                    continue;
                }

                request->status = http_conn->error ? http_conn->error :
                    EVPL_HTTP_ERROR_CONN_LOST;

                if (request->notify_callback) {
                    request->notify_callback(evpl, http_conn->agent, request,
                                             EVPL_HTTP_NOTIFY_FAILED,
                                             request->request_type,
                                             request->uri,
                                             request->notify_data,
                                             evpl_http_priv(http_conn));
                }
            }

            /* A request the server was still parsing has a caller only if it
             * was dispatched, which happens when its header block completes;
             * before that nobody is waiting on it. */
            request = http_conn->current_request;

            if (request && request != http_conn->pending_requests &&
                request->notify_callback) {
                request->status = http_conn->error ? http_conn->error :
                    EVPL_HTTP_ERROR_CONN_LOST;

                request->notify_callback(evpl, http_conn->agent, request,
                                         EVPL_HTTP_NOTIFY_FAILED,
                                         request->request_type, request->uri,
                                         request->notify_data,
                                         evpl_http_priv(http_conn));
            }

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

            /*
             * A server connection was never handed to anyone: the application
             * sees requests, not connections, so nothing outside can be
             * holding a pointer and it is freed here.
             *
             * A client connection is a handle its owner is holding, and the
             * owner has no way to be told that the peer went away -- so
             * freeing it here would leave a pointer that becomes a
             * use-after-free at a moment nothing observable happened.  Retire
             * it instead: the bind is gone, every outstanding request has just
             * been failed, and the struct waits for the
             * evpl_http_client_close() its owner still owes it.
             */
            if (http_conn->is_server || http_conn->released) {
                DL_DELETE(http_conn->agent->conns, http_conn);
                evpl_free(http_conn);
            } else {
                http_conn->bind      = NULL;
                http_conn->connected = 0;
            }
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

    /* RFC 9110 section 6.6.1 requires this on every response outside the 1xx
     * and 5xx classes, where it is merely allowed.  Sent on all of them: there
     * is nothing to gain from withholding it where it is optional.
     *
     * Only when the application did not supply one.  Section 5.3 forbids two
     * field lines with the same name unless the field is a list, and Date is
     * not -- so a server that has its own clock reading, or that has to make
     * the value match something else it has signed, keeps it and this stays
     * out of the way. */
    if (!evpl_http_response_header(request, "Date")) {
        evpl_http_append_line(rsp_base, cap, &rsp, "Date: %s\r\n",
                              evpl_http_date(conn->agent));
    }

    DL_FOREACH(request->response_headers, header)
    {
        evpl_http_append_line(rsp_base, cap, &rsp, "%s: %s\r\n", header->name, header->value);
    }

    switch (request->response_framing) {
        case EVPL_HTTP_FRAMING_LENGTH:
            evpl_http_append_line(rsp_base, cap, &rsp,
                                  "Content-Length: %" PRIu64 "\r\n",
                                  request->response_length);
            break;
        case EVPL_HTTP_FRAMING_CHUNKED:
            evpl_http_append_line(rsp_base, cap, &rsp,
                                  "Transfer-Encoding: chunked\r\n");
            break;
        default:
            /* Neither.  A message with no content at all describes none, and a
             * close-delimited one has nothing to describe it with -- the
             * connection close is the delimiter, which the Connection header
             * has already announced. */
            break;
    } /* switch */

    evpl_http_append_line(rsp_base, cap, &rsp, "\r\n");

    evpl_http_abort_if((unsigned int) (rsp - rsp_base) >= cap,
                       "http response header block overflowed max_header_size");

    iov.length = rsp - rsp_base;

    evpl_sendv(evpl, bind, &iov, 1, iov.length, EVPL_SEND_FLAG_TAKE_REF);
} /* evpl_http_server_send_headers */

/*
 * Record the authority a client connection was opened to, in the form RFC 9110
 * section 7.2 gives Host: "uri-host optionally followed by a colon and port
 * number", with the port left out when it is the default for the scheme.
 *
 * An IPv6 literal is bracketed, because the colons in the address would
 * otherwise be indistinguishable from the one before the port.
 */
static void
evpl_http_conn_set_host(
    struct evpl_http_conn *conn,
    struct evpl_endpoint  *endpoint,
    enum evpl_protocol_id  protocol_id)
{
    const char *address = evpl_endpoint_address(endpoint);
    int         port    = evpl_endpoint_port(endpoint);
    int         tls     = protocol_id == EVPL_STREAM_SOCKET_TLS;
    int         literal;

    if (!address || !*address) {
        /* A local or in-process endpoint names no authority.  Something has to
         * go on the wire, and this is what a peer that does not route by
         * authority will accept. */
        snprintf(conn->host, sizeof(conn->host), "localhost");
        return;
    }

    literal = strchr(address, ':') != NULL;

    if (port == (tls ? 443 : 80)) {
        snprintf(conn->host, sizeof(conn->host), literal ? "[%s]" : "%s",
                 address);
    } else {
        snprintf(conn->host, sizeof(conn->host),
                 literal ? "[%s]:%d" : "%s:%d", address, port);
    }
} /* evpl_http_conn_set_host */

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

    /*
     * RFC 9112 section 3.2: "A client MUST send a Host header field in all
     * HTTP/1.1 request messages" -- and this client sends HTTP/1.1 on the
     * request line above whatever the caller does, so it is the component the
     * obligation falls on.  Section 3.2 also makes a server's answer to a
     * request without one a 400, so a caller that did not know to add one was
     * making requests that a conforming peer must refuse.
     *
     * Only when the caller did not add one: two Host fields are refused by the
     * same rule as none.
     */
    if (!evpl_http_request_header(request, "Host")) {
        evpl_http_append_line(rsp_base, cap, &rsp, "Host: %s\r\n", conn->host);
    }

    DL_FOREACH(request->request_headers, header)
    {
        evpl_http_append_line(rsp_base, cap, &rsp, "%s: %s\r\n", header->name, header->value);
    }

    if (request->response_framing == EVPL_HTTP_FRAMING_CHUNKED) {
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

    if (request->response_framing == EVPL_HTTP_FRAMING_NONE) {
        /* RFC 9112 section 6.3: a 1xx or 204 response "is always terminated by
         * the first empty line after the header fields".  The message is over,
         * so anything the application staged is not part of it -- and putting
         * it on the wire would have the peer read it as the start of the next
         * response.  Which framing a status may use is the library's to know,
         * as the HEAD rule already is. */
        evpl_iovec_ring_clear(evpl, &request->send_ring);
        return 1;
    }

    if (request->response_framing == EVPL_HTTP_FRAMING_CLOSE) {
        /* No length and no coding: the content is whatever reaches the peer
         * before the FIN, so everything staged goes out and the message ends
         * when the application says it has. */
        while (!evpl_iovec_ring_is_empty(&request->send_ring)) {
            iovp = evpl_iovec_ring_tail(&request->send_ring);
            evpl_sendv(evpl, bind, iovp, 1, iovp->length, EVPL_SEND_FLAG_TAKE_REF);
            evpl_iovec_ring_remove(&request->send_ring);
        }

        return (request->request_flags &
                EVPL_HTTP_REQUEST_RESPONSE_FINISHED) != 0;
    }

    if (request->response_framing == EVPL_HTTP_FRAMING_LENGTH) {

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
            /* The last-chunk, then the trailer section if one was staged --
            * RFC 9112 section 7.1.2 puts its field lines between the
            * last-chunk and the CRLF that ends the coding.  The staged
            * fields were validated and accounted (send_trailer_bytes is
            * their exact emitted size) by evpl_http_request_add_trailer. */
            struct evpl_http_request_header *trailer;
            char                            *p;
            unsigned int                     term_bytes;

            term_bytes = 3 + request->send_trailer_bytes + 2;

            niov = evpl_iovec_alloc(evpl, term_bytes, 0, 1, 0, &iov);

            evpl_http_abort_if(niov < 0, "failed to allocate iovec");

            p    = iov.data;
            *p++ = '0';
            *p++ = '\r';
            *p++ = '\n';

            DL_FOREACH(request->send_trailers, trailer)
            {
                p += snprintf(p, term_bytes - (p - (char *) iov.data),
                              "%s: %s\r\n", trailer->name, trailer->value);
            }

            *p++ = '\r';
            *p++ = '\n';

            evpl_http_abort_if((unsigned int) (p - (char *) iov.data) != term_bytes,
                               "chunked terminator accounting mismatch");

            evpl_sendv(evpl, bind, &iov, 1, term_bytes, EVPL_SEND_FLAG_TAKE_REF);

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

            /* A slot in the read-ahead window has just been freed, and the
             * request that would fill it may already be buffered with no read
             * event left to announce it. */
            evpl_defer(evpl, &conn->parse);

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
    evpl_deferral_init(&http_conn->parse, evpl_http_parse_deferred, http_conn);

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

    evpl_http_conn_set_host(conn, endpoint, protocol_id);

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
    /* Mark it released first, so that the disconnect this is about to provoke
     * frees the struct rather than retiring it -- and so that a connection
     * whose peer already went away, which has no bind left to close, is freed
     * here instead. */
    conn->released = 1;

    if (conn->bind) {
        evpl_close(agent->evpl, conn->bind);
    } else {
        DL_DELETE(agent->conns, conn);
        evpl_free(conn);
    }
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

    /* The client speaks HTTP/1.1, so both framings are available to it and the
     * one the caller asked for is the one it gets. */
    request->response_framing = request->response_transfer_encoding ==
        EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED ?
        EVPL_HTTP_FRAMING_CHUNKED : EVPL_HTTP_FRAMING_LENGTH;

    /*
     * A retired connection can carry nothing, and queueing the request on it
     * would leave the caller waiting on a completion that can never arrive --
     * the one thing EVPL_HTTP_NOTIFY_FAILED exists to prevent.  Answer it now
     * instead; the callback runs before this returns, which is documented on
     * evpl_http_client_close().
     */
    if (unlikely(!conn->bind)) {
        request->status = EVPL_HTTP_ERROR_CONN_LOST;

        if (notify_callback) {
            notify_callback(evpl, conn->agent, request,
                            EVPL_HTTP_NOTIFY_FAILED, request->request_type,
                            request->uri, notify_data, evpl_http_priv(conn));
        }

        evpl_http_request_free(conn->agent, request);
        return;
    }

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

SYMBOL_EXPORT int
evpl_http_request_add_trailer(
    struct evpl_http_request *request,
    const char               *name,
    const char               *value)
{
    struct evpl_http_agent          *agent = request->conn->agent;
    struct evpl_http_request_header *header;
    unsigned int                     line_bytes;

    /* The section travels with the last piece of the message, so once the
     * application has said there is nothing more to send there is nothing
     * for a trailer to travel with. */
    if (unlikely(request->request_flags & EVPL_HTTP_REQUEST_RESPONSE_FINISHED)) {
        evpl_http_error("refusing trailer '%s': the message is already finished",
                        name);
        return -1;
    }

    /* The same grammar rules as a header, for the same reason: a field the
     * peer would read as something else is an injection point, and a trailer
     * section is made of field lines like any other. */
    if (unlikely(!evpl_http_field_name_is_token(name) ||
                 !evpl_http_field_value_is_safe(value))) {
        evpl_http_error("refusing to emit trailer '%s': "
                        "not a field name and value", name);
        return -1;
    }

    header = evpl_http_request_header_alloc(agent);

    strncpy(header->name, name, sizeof(header->name) - 1);
    strncpy(header->value, value, sizeof(header->value) - 1);

    /* accounted as emitted: "<name>: <value>\r\n", using the stored
     * (possibly truncated) field lengths */
    line_bytes = strlen(header->name) + strlen(header->value) + 4;

    if (request->send_trailer_bytes + line_bytes > agent->max_header_size) {
        evpl_http_request_header_free(agent, header);
        return -1;
    }

    request->send_trailer_bytes += line_bytes;

    DL_APPEND(request->send_trailers, header);

    return 0;
} /* evpl_http_request_add_trailer */

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

    /*
     * A Status-Code is three digits with a leading 1 through 5 (RFC 1945
     * section 6.1.1), so an application asking for anything else is asking for
     * something that cannot be put on the wire: formatted straight into the
     * status line it produces a response the peer cannot parse at all, and the
     * exchange fails in a way that looks like a transport fault rather than
     * like the caller's mistake.
     *
     * The library owns the outbound framing, so it is the component that has
     * to keep it well formed -- the same reasoning that makes suppressing the
     * body of a HEAD response its job rather than the application's.  A status
     * it cannot send becomes the one that describes the situation: something
     * went wrong inside the server.
     */
    if (unlikely(status < 100 || status > 599)) {
        evpl_http_error("status %d is not a Status-Code; answering 500",
                        status);
        status = 500;
    }

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

    /*
     * How the content will actually be delimited, which is not the same
     * question as which framing the application asked for.
     *
     * RFC 9110 section 8.6: "A server MUST NOT send a Content-Length header
     * field in any response with a status code of 1xx (Informational) or 204
     * (No Content)", and RFC 9112 section 6.1 says the same of a
     * Transfer-Encoding on one -- these carry no content, so a header
     * describing its length is describing something that is not there, and a
     * peer that believes it waits for bytes that are never coming.
     *
     * Section 6.1 also: "A server MUST NOT send a response containing
     * Transfer-Encoding unless the corresponding request indicates HTTP/1.1
     * (or later)."  An
     * HTTP/1.0 client has no chunked coding to decode, so a chunked response
     * to one is a response it cannot read at all -- it takes the chunk sizes
     * for content.  What is left for content whose size the application does
     * not know in advance is the framing HTTP/1.0 does have: the close.  That
     * costs the connection, which is why the request is marked to close and
     * the Connection header below says so.
     */
    if (status / 100 == 1 || status == 204) {
        request->response_framing = EVPL_HTTP_FRAMING_NONE;
    } else if (request->response_transfer_encoding ==
               EVPL_HTTP_REQUEST_TRANSFER_ENCODING_CHUNKED) {
        if (request->http_version == EVPL_HTTP_REQUEST_HTTP_VERSION_1_1) {
            request->response_framing = EVPL_HTTP_FRAMING_CHUNKED;
        } else {
            request->response_framing = EVPL_HTTP_FRAMING_CLOSE;
            request->request_flags   |= EVPL_HTTP_REQUEST_CONN_CLOSE;
        }
    } else {
        request->response_framing = EVPL_HTTP_FRAMING_LENGTH;
    }

    /* RFC 9110 section 9.3.2 and RFC 9112 section 6.3: the response to HEAD,
     * and a 304, carry the header fields a GET would have -- Content-Length
     * included -- and no content.  So the framing header stays and the octets
     * do not, which is the library's call rather than the application's: it is
     * the only component that knows both the request method and what is about
     * to reach the wire. */
    if (request->request_type == EVPL_HTTP_REQUEST_TYPE_HEAD ||
        status == 304) {
        request->response_left = 0;

        if (request->response_framing != EVPL_HTTP_FRAMING_LENGTH) {
            request->response_framing = EVPL_HTTP_FRAMING_NONE;
        }
    }

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

SYMBOL_EXPORT const char *
evpl_http_request_trailer(
    struct evpl_http_request *request,
    const char               *name)
{
    struct evpl_http_request_header *header;

    DL_FOREACH(request->recv_trailers, header)
    {
        if (strncasecmp(header->name, name, sizeof(header->name) - 1) == 0) {
            return header->value;
        }
    }

    return NULL;
} /* evpl_http_request_trailer */

SYMBOL_EXPORT void
evpl_http_request_trailer_iterate(
    struct evpl_http_request     *request,
    evpl_http_request_header_cb_t callback,
    void                         *private_data)
{
    struct evpl_http_request_header *header;

    DL_FOREACH(request->recv_trailers, header)
    {
        callback(header->name, header->value, private_data);
    }
} /* evpl_http_request_trailer_iterate */

SYMBOL_EXPORT enum evpl_http_protocol
evpl_http_request_protocol(struct evpl_http_request *request)
{
    return request->conn->proto == EVPL_HTTP_PROTO_H2 ?
           EVPL_HTTP_PROTOCOL_HTTP2 : EVPL_HTTP_PROTOCOL_HTTP1;
} /* evpl_http_request_protocol */

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
