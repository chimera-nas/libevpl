/*
 * SPDX-FileCopyrightText: 2026 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Model-based HTTP/1.x conformance test, client direction.
 *
 * conformance.c drives libevpl's HTTP *server* from a raw socket.  This is its
 * mirror image: a raw socket pretending to be a server, feeding deliberately
 * defective responses to a real libevpl HTTP client and checking what the
 * client does with them.  The cases come from the http1x_client module of
 * quint/http1x.qnt and are compiled in as part of http_cases.h.
 *
 * conformance.c cannot reach any of this, because the responses it sees come
 * from a real libevpl server and are therefore well formed by construction --
 * the same reason the RPC2 suite needs conformance_client.c alongside
 * conformance.c.
 *
 * The three requirements that carry most of the weight here, because all are
 * easy to violate and none is visible from a well-behaved peer:
 *
 *   1. No request may be abandoned in silence.  A caller that dispatched a
 *      request is owed exactly one answer -- the response, or the news that
 *      there will not be one -- whatever the peer does, including hanging up.
 *      Anything else is a caller blocked forever.
 *
 *   2. A response whose framing is broken is not a result.  A truncated body,
 *      a length that is not a length or a chunk size that is not a size must
 *      not reach the caller as a completed response, because the value it
 *      would hand over is one the peer never sent.
 *
 *   3. An interim response is not the answer.  RFC 9110 section 15.2 requires
 *      a client to parse 1xx responses that precede the final one; reporting
 *      one as the result loses the real response and leaves it arriving on a
 *      connection the client believes is idle.
 *
 * Alongside those, and outside the model because they hold for every case, the
 * hostile server examines the requests it receives: a Host header on each one
 * (RFC 9112 section 3.2 makes it a MUST for HTTP/1.1, which is the version
 * libevpl's client speaks) and, where the caller supplied a body, exactly the
 * octets it handed over under a framing that describes them.
 *
 * As in conformance.c, the model encodes the SPECIFICATION.  Reviewed
 * divergences are listed in known_divergences[] with a note; an unlisted one
 * fails the test.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <pthread.h>
#include <signal.h>
#include <poll.h>
#include <time.h>
#include <sched.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "evpl/evpl.h"
#include "evpl/evpl_http.h"

#include "http_cases.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL      0
#endif /* ifndef MSG_NOSIGNAL */

static int port = 8096;

/* The byte-level spelling of the model's symbolic classes.  Kept identical to
 * conformance.c's where the two overlap, since the header grammar cases are
 * the same grammar seen from the other end. */
#define PROBE_NAME        "X-Probe"
#define PROBE_VALUE       "probe-value"
#define RESPONSE_BODY     "hello from a hostile server"
#define RESPONSE_BODY_HEX "1b"    /* strlen(RESPONSE_BODY), for chunk sizes */
#define REQUEST_URI       "/probe"

/* Mirrors libevpl's default http_max_header_size, which the overlong case has
 * to exceed. */
#define MAX_HEADER_SIZE   8192

/* Wall-clock budget for one exchange.  Loopback responses land in
 * microseconds, so anything approaching this is a client that has stopped
 * making progress -- which is what several cases look for.  Kept small
 * because a few cases are expected to hit it. */
#define CASE_TIMEOUT_MS   400

/* How long the driver keeps pumping after a case has reached a terminal state,
 * which is what proves the SECOND callback does not arrive. */
#define SETTLE_MS         25

/* How long the event loop blocks per turn.  Bounded so the pump keeps ticking
 * while nothing is arriving, which is what lets a case time out rather than
 * hang. */
#define PUMP_WAIT_MS      2

#define SPLIT_DELAY_US    200
#define DRIBBLE_DELAY_US  20
#define DRIBBLE_MAX_BYTES 512

#define BODY_MAX          4096

/*
 * The request body the POST cases carry, and how much of it the caller hands
 * over at a time when it streams.
 *
 * Larger than the streaming chunk on purpose: a body that fits in one piece
 * never leaves libevpl asking for the rest, so it never reaches the WANT_DATA
 * path an application streaming a file of unknown size depends on.
 */
#define REQUEST_BODY_LEN  4000
#define REQUEST_CHUNK     1500

/* At most this many requests on one connection (the pipelined case). */
#define MAX_REQUESTS      2

/* ------------------------------------------------------------------ *
* Outcomes the driver can observe that the model has no name for
* ------------------------------------------------------------------ */

/* The callback fired for the headers and then again for completion: the
 * response was delivered.  Carried as the status itself, 100..599. */
#define ACT_SILENT        1000  /* no callback at all: the caller is stranded */
#define ACT_HEADERS_ONLY  1001  /* the status arrived, the completion never did */
#define ACT_COMPLETE_ONLY 1002  /* completion without the headers that precede it */

#define ASPECT_OUTCOME    0
#define ASPECT_BODY       1
#define ASPECT_PROBE      2
#define ASPECT_ONCE       3     /* exactly one completion, never two */
#define ASPECT_REASON     4     /* which EVPL_HTTP_ERROR_* a failure carried */
#define ASPECT_REQUEST    5     /* the request body the peer actually received */
#define ASPECT_HOST       6     /* the Host header HTTP/1.1 requires           */
#define ASPECT_PIPELINE   7     /* the second of two requests on one connection */

/* ASPECT_BODY / ASPECT_ONCE actuals. */
#define VACT_OK           0
#define VACT_BAD          1

static const char *
aspect_name(int aspect)
{
    switch (aspect) {
        case ASPECT_OUTCOME:  return "outcome";
        case ASPECT_BODY:     return "body";
        case ASPECT_PROBE:    return "probe";
        case ASPECT_ONCE:     return "once";
        case ASPECT_REASON:   return "reason";
        case ASPECT_REQUEST:  return "request";
        case ASPECT_HOST:     return "host";
        case ASPECT_PIPELINE: return "pipeline";
        default:              return "?";
    } /* switch */
} /* aspect_name */

static const char *
outcome_name(int o)
{
    switch (o) {
        case ACT_SILENT:        return "SILENT";
        case ACT_HEADERS_ONLY:  return "HEADERS_ONLY";
        case ACT_COMPLETE_ONLY: return "COMPLETE_ONLY";
        default:                return "status";
    } /* switch */
} /* outcome_name */

/* ------------------------------------------------------------------ *
* Known divergences from the specification
* ------------------------------------------------------------------ */

struct known_divergence {
    int         aspect;
    int         defect;
    int         expect;
    int         actual;
    const char *note;
};

/* A CbFailed expectation is recorded as -1: the model names no status for it,
 * and no status can collide with it. */
#define EXP_FAILED (-1)

static const struct known_divergence known_divergences[] = {
    /* Add an entry here only for a divergence that has been reviewed and
     * consciously deferred, with a note saying why -- an unlisted one fails
     * the test.
     *
     * The unmatchable first row keeps the array non-empty, which is where it
     * stands: every divergence this suite found has been fixed. */
    { .aspect = -1,
      .defect = -1,
      .expect = -1,
      .actual = -1,
      .note   = NULL },
};

static int
is_known_divergence(
    int aspect,
    int defect,
    int expect,
    int actual)
{
    unsigned int i;

    for (i = 0; i < sizeof(known_divergences) / sizeof(known_divergences[0]);
         i++) {
        if (known_divergences[i].aspect == aspect &&
            known_divergences[i].defect == defect &&
            known_divergences[i].expect == expect &&
            known_divergences[i].actual == actual) {
            return 1;
        }
    }

    return 0;
} /* is_known_divergence */

/* ------------------------------------------------------------------ *
* Results
* ------------------------------------------------------------------ */

#define MAX_OBSERVED 64

struct observed {
    int aspect;
    int defect;
    int expect;
    int actual;
    int count;
    int known;
};

static struct observed g_observed[MAX_OBSERVED];
static int             g_num_observed;

static struct {
    int cases_run;
    int checks;
    int failed;
    int known;
    int unexpected;
} g_results;

static void
record(
    int         aspect,
    int         defect,
    int         expect,
    int         actual,
    int         ok,
    const char *detail)
{
    struct observed *o;
    int              known, i;

    g_results.checks++;

    if (ok) {
        return;
    }

    g_results.failed++;

    known = is_known_divergence(aspect, defect, expect, actual);

    if (known) {
        g_results.known++;
    } else {
        g_results.unexpected++;
    }

    for (i = 0; i < g_num_observed; i++) {
        o = &g_observed[i];
        if (o->aspect == aspect && o->defect == defect &&
            o->expect == expect && o->actual == actual) {
            o->count++;
            return;
        }
    }

    if (g_num_observed == MAX_OBSERVED) {
        return;
    }

    o = &g_observed[g_num_observed++];

    o->aspect = aspect;
    o->defect = defect;
    o->expect = expect;
    o->actual = actual;
    o->count  = 1;
    o->known  = known;

    fprintf(stderr, "%s %s/%s: expected %d, got %d%s%s\n",
            known ? "known divergence" : "DIVERGENCE",
            aspect_name(aspect), http_client_defect_name(defect),
            expect, actual, detail ? " -- " : "", detail ? detail : "");
} /* record */

/* ------------------------------------------------------------------ *
* A growable byte buffer for building responses
* ------------------------------------------------------------------ */

struct wirebuf {
    char  *data;
    size_t len;
    size_t cap;
};

static void
wb_init(struct wirebuf *wb)
{
    wb->cap  = 4096;
    wb->len  = 0;
    wb->data = malloc(wb->cap);

    if (!wb->data) {
        fprintf(stderr, "out of memory building a response\n");
        exit(1);
    }
} /* wb_init */

static void
wb_free(struct wirebuf *wb)
{
    free(wb->data);
    wb->data = NULL;
} /* wb_free */

static void
wb_append(
    struct wirebuf *wb,
    const void     *bytes,
    size_t          len)
{
    char *grown;

    while (wb->len + len > wb->cap) {
        wb->cap *= 2;
        grown    = realloc(wb->data, wb->cap);

        if (!grown) {
            fprintf(stderr, "out of memory building a response\n");
            exit(1);
        }

        wb->data = grown;
    }

    memcpy(wb->data + wb->len, bytes, len);
    wb->len += len;
} /* wb_append */

static void
wb_str(
    struct wirebuf *wb,
    const char     *s)
{
    wb_append(wb, s, strlen(s));
} /* wb_str */

static void
wb_fill(
    struct wirebuf *wb,
    char            c,
    int             n)
{
    int i;

    for (i = 0; i < n; i++) {
        wb_append(wb, &c, 1);
    }
} /* wb_fill */

/*
 * Whether the hostile server holds this case's connection open after
 * answering, rather than making the close part of the message.
 *
 * The driver needs the same answer the raw thread does: it may only call
 * evpl_http_client_close() on a connection it knows is still there, since
 * closing one the peer has already dropped is a use-after-free (see
 * run_client_case).
 *
 * Everywhere this returns 1 the connection is deliberately LEFT OPEN, which is
 * what makes a case like RspStatusNoBody mean anything: a client that
 * completes the request without a close has understood the framing, while one
 * that completes only when the connection drops has merely been rescued by it.
 */
static int
case_holds_connection(int defect)
{
    switch (defect) {
        case HCDEF_RSPBODYCLOSEDELIMITED:
        case HCDEF_RSPCLOSEDELIMITEDHTTP11:
        case HCDEF_RSPBODYSHORTOFCONTENTLENGTH:
        case HCDEF_RSPCHUNKEDTRUNCATED:
        case HCDEF_RSPCONNECTIONCLOSE:
        case HCDEF_RSPNOSTATUSLINE:
        case HCDEF_RSPPEERCLOSESWITHOUTRESPONSE:
        case HCDEF_RSPPEERCLOSESMIDSTATUSLINE:
        case HCDEF_RSPPEERCLOSESMIDHEADERS:
            return 0;
        default:
            return 1;
    } /* switch */
} /* case_holds_connection */

/* One ordinary 200 with a declared length, which several cases answer with
 * because the response is not what they are about. */
#define PLAIN_200                       \
        "HTTP/1.1 200 OK\r\n"           \
        PROBE_NAME ": " PROBE_VALUE "\r\n" \
        "Content-Length: 27\r\n\r\n" RESPONSE_BODY

static void
build_response(
    struct wirebuf                *wb,
    const struct http_client_case *c,
    int                           *close_after)
{
    char line[128];
    int  i, off, chunk;

    *close_after = !case_holds_connection(c->defect);

    switch (c->defect) {
        case HCDEF_RSPWELLFORMED:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   PROBE_NAME ": " PROBE_VALUE "\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPHEADEREMPTYVALUE:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   PROBE_NAME ":\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPHEADERFOLDED:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   PROBE_NAME ": probe-\r\n\tvalue\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPHEADERPADDED:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   PROBE_NAME ":  \t" PROBE_VALUE " \t\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPHEADERNOCOLON:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   "ThisIsNotAHeaderField\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPHEADERNAMEEMPTY:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   ": value\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPHEADERSPACEBEFORECOLON:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   PROBE_NAME " : " PROBE_VALUE "\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPHEADERBLOCKOVERLONG:
            wb_str(wb, "HTTP/1.0 200 OK\r\n");

            for (i = 0; i * 128 < MAX_HEADER_SIZE + 512; i++) {
                snprintf(line, sizeof(line), "X-Fill-%03d: ", i);
                wb_str(wb, line);
                wb_fill(wb, 'a', 128 - (int) strlen(line) - 2);
                wb_str(wb, "\r\n");
            }

            wb_str(wb, "\r\n");
            break;

        case HCDEF_RSPNOREASONPHRASE:
            wb_str(wb, "HTTP/1.0 200\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPMINORVERSIONUNKNOWN:
            wb_str(wb, "HTTP/1.9 200 OK\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPVERSIONMALFORMED:
            wb_str(wb, "HTTP/1 200 OK\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPMAJORVERSIONUNSUPPORTED:
            wb_str(wb, "HTTP/2.0 200 OK\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPSTATUSNOTNUMERIC:
            wb_str(wb, "HTTP/1.0 abc OK\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPSTATUSOUTOFRANGE:
            snprintf(line, sizeof(line), "HTTP/1.0 %d Weird\r\n",
                     (int) c->param);
            wb_str(wb, line);
            wb_str(wb, "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPSTATUSMISSING:
            wb_str(wb, "HTTP/1.0\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPNOSTATUSLINE:
            /* An HTTP/0.9 Simple-Response: the body, and nothing else. */
            wb_str(wb, RESPONSE_BODY);
            break;

        case HCDEF_RSPINTERIMCONTINUE:
            /* The interim response, then the answer.  Nothing asked for the
             * 100 -- RFC 9110 section 15.2 requires a client to cope with one
             * "even if the client does not expect one". */
            wb_str(wb, "HTTP/1.1 100 Continue\r\n\r\n" PLAIN_200);
            break;

        case HCDEF_RSPINTERIMREPEATED:
            wb_str(wb, "HTTP/1.1 100 Continue\r\n\r\n"
                   "HTTP/1.1 100 Continue\r\n\r\n" PLAIN_200);
            break;

        case HCDEF_RSPINTERIMEARLYHINTS:
            /* 103 Early Hints (RFC 8297), which carries header fields of its
             * own: an interim response is a complete message, not a bare
             * status line, so a client that skips one has to skip the whole
             * message. */
            wb_str(wb, "HTTP/1.1 103 Early Hints\r\n"
                   "Link: </style.css>; rel=preload; as=style\r\n"
                   "Link: </script.js>; rel=preload; as=script\r\n\r\n"
                   PLAIN_200);
            break;

        case HCDEF_RSPSTATUS:
            snprintf(line, sizeof(line), "HTTP/1.0 %d Something\r\n",
                     (int) c->param);
            wb_str(wb, line);
            wb_str(wb, "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPSTATUSNOBODY:
            /* No Content-Length, and none is needed: these carry no content,
             * so the message ends with the header block. */
            snprintf(line, sizeof(line), "HTTP/1.1 %d No Body\r\n",
                     (int) c->param);
            wb_str(wb, line);
            wb_str(wb, PROBE_NAME ": " PROBE_VALUE "\r\n\r\n");
            break;

        case HCDEF_RSPBODYCLOSEDELIMITED:
            wb_str(wb, "HTTP/1.0 200 OK\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPCLOSEDELIMITEDHTTP11:
            /* RFC 9112 section 6.3 item 7: with no length and no coding the
             * content still runs to the close, at HTTP/1.1 as much as at
             * HTTP/1.0. */
            wb_str(wb, "HTTP/1.1 200 OK\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPCONTENTLENGTHNOTNUMERIC:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   "Content-Length: not-a-number\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPCONTENTLENGTHNEGATIVE:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   "Content-Length: -1\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPCONTENTLENGTHDUPLICATECONFLICTING:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   "Content-Length: 27\r\n"
                   "Content-Length: 11\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPBODYSHORTOFCONTENTLENGTH:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   "Content-Length: 64\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPBODYLONGERTHANCONTENTLENGTH:
            /* Declares eleven octets and sends twenty-seven: the surplus is
             * not part of this response. */
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   "Content-Length: 11\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPHEADWITHCONTENTLENGTH:
            /* The headers a GET would have returned, and no body. */
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   "Content-Length: 27\r\n\r\n");
            break;

        case HCDEF_RSPTRANSFERENCODINGWITHCONTENTLENGTH:
            wb_str(wb, "HTTP/1.1 200 OK\r\n"
                   "Content-Length: 27\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n"
                   RESPONSE_BODY_HEX "\r\n" RESPONSE_BODY "\r\n0\r\n\r\n");
            break;

        case HCDEF_RSPCHUNKED:
            wb_str(wb, "HTTP/1.1 200 OK\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n"
                   RESPONSE_BODY_HEX "\r\n" RESPONSE_BODY "\r\n0\r\n\r\n");
            break;

        case HCDEF_RSPCHUNKEDEXTENSION:
            /* RFC 9112 section 7.1.1: a recipient that does not understand a
             * chunk extension "MUST ignore" it, so the size line still
             * delimits the same chunk. */
            wb_str(wb, "HTTP/1.1 200 OK\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n"
                   RESPONSE_BODY_HEX ";probe=1;flag\r\n" RESPONSE_BODY
                   "\r\n0;done\r\n\r\n");
            break;

        case HCDEF_RSPCHUNKEDTRAILER:
            /* The trailer section (RFC 9112 section 7.1.2).  A decoder can
             * produce the right content without ever consuming it, and then
             * the trailer is left to be read as the start of the next
             * response on a connection HTTP/1.1 keeps open by default. */
            wb_str(wb, "HTTP/1.1 200 OK\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n"
                   RESPONSE_BODY_HEX "\r\n" RESPONSE_BODY "\r\n"
                   "0\r\nX-Trailer: after-the-content\r\n"
                   "X-Trailer-Two: and-another\r\n\r\n");
            break;

        case HCDEF_RSPCHUNKEDMANYCHUNKS:
            wb_str(wb, "HTTP/1.1 200 OK\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n");

            for (off = 0; off < (int) strlen(RESPONSE_BODY); off += chunk) {
                chunk = (int) strlen(RESPONSE_BODY) - off;

                if (chunk > 5) {
                    chunk = 5;
                }

                snprintf(line, sizeof(line), "%x\r\n", chunk);
                wb_str(wb, line);
                wb_append(wb, &RESPONSE_BODY[off], chunk);
                wb_str(wb, "\r\n");
            }

            wb_str(wb, "0\r\n\r\n");
            break;

        case HCDEF_RSPCHUNKSIZENOTHEX:
            wb_str(wb, "HTTP/1.1 200 OK\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n"
                   "zz\r\n" RESPONSE_BODY "\r\n0\r\n\r\n");
            break;

        case HCDEF_RSPCHUNKSIZENEGATIVE:
            wb_str(wb, "HTTP/1.1 200 OK\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n"
                   "-1b\r\n" RESPONSE_BODY "\r\n0\r\n\r\n");
            break;

        case HCDEF_RSPCHUNKBADTERMINATOR:
            /* The CRLF that must follow the chunk data is something else, so
             * the next size line is read from inside the content. */
            wb_str(wb, "HTTP/1.1 200 OK\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n"
                   RESPONSE_BODY_HEX "\r\n" RESPONSE_BODY "XX0\r\n\r\n");
            break;

        case HCDEF_RSPCHUNKEDTRUNCATED:
            /* Chunks, then a close, and never a last-chunk. */
            wb_str(wb, "HTTP/1.1 200 OK\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n"
                   RESPONSE_BODY_HEX "\r\n" RESPONSE_BODY "\r\n");
            break;

        case HCDEF_RSPCONNECTIONCLOSE:
            /* RFC 9112 section 9.6: the announcement, and then the close it
             * announced.  The content is still delimited by its length, so a
             * client that has understood the framing completes the request
             * before the FIN rather than because of it. */
            wb_str(wb, "HTTP/1.1 200 OK\r\n"
                   "Connection: close\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPPIPELINED:
            /* Two responses in one write, for the two requests the driver
             * dispatched before either was answered.  A client that stops
             * parsing when one response is complete never sees the second,
             * because the read event that carried it has already been
             * delivered. */
            wb_str(wb, PLAIN_200);
            wb_str(wb, PLAIN_200);
            break;

        case HCDEF_RSPTOPOSTWITHBODY:
        case HCDEF_RSPTOSTREAMEDPOST:
        case HCDEF_RSPTOCHUNKEDPOST:
            /* An ordinary response.  These three cases are about the request,
             * not the reply -- what is under test is that the body the caller
             * handed over reached the peer intact, which drain_requests checks
             * before this runs. */
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   PROBE_NAME ": " PROBE_VALUE "\r\n"
                   "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPPEERCLOSESWITHOUTRESPONSE:
            break;

        case HCDEF_RSPPEERCLOSESMIDSTATUSLINE:
            wb_str(wb, "HTTP/1.0 20");
            break;

        case HCDEF_RSPPEERCLOSESMIDHEADERS:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   "Content-Length: 27\r\n");
            break;

        default:
            fprintf(stderr, "response defect %d has no wire encoding; add one "
                    "to build_response()\n", c->defect);
            exit(1);
    } /* switch */
} /* build_response */

/* ------------------------------------------------------------------ *
* The hostile server
*
* One accept per case, in lockstep with the driver: the case index is
* published before the client is asked to connect, so the connection the
* thread accepts is always the one it has been told to answer.
* ------------------------------------------------------------------ */

struct raw_server {
    pthread_t    thread;
    int          listen_fd;
    volatile int case_index; /* set by the driver before the client connects */
    volatile int ready;      /* the thread is in accept(), waiting for one    */
    volatile int case_done;  /* set by the driver when it has finished a case */
};

static struct raw_server g_raw;

static int
write_all(
    int         fd,
    const char *buf,
    size_t      len)
{
    ssize_t n;
    size_t  off = 0;

    while (off < len) {
        n = send(fd, buf + off, len - off, MSG_NOSIGNAL);

        if (n <= 0) {
            /* The client hung up mid-response, which is an outcome in itself
             * for several cases; the classifier downstream decides. */
            return -1;
        }

        off += n;
    }

    return 0;
} /* write_all */

static void
deliver(
    int             fd,
    struct wirebuf *wb,
    int             delivery)
{
    size_t half, i, dribble;

    if (wb->len == 0) {
        return;
    }

    switch (delivery) {
        case HDLV_ONEWRITE:
            write_all(fd, wb->data, wb->len);
            break;
        case HDLV_TWOWRITES:
            half = wb->len / 2;

            if (write_all(fd, wb->data, half) == 0) {
                usleep(SPLIT_DELAY_US);
                write_all(fd, wb->data + half, wb->len - half);
            }
            break;
        case HDLV_DRIBBLE:
            dribble = wb->len < DRIBBLE_MAX_BYTES ? wb->len : DRIBBLE_MAX_BYTES;

            for (i = 0; i < dribble; i++) {
                if (write_all(fd, wb->data + i, 1) < 0) {
                    return;
                }
                usleep(DRIBBLE_DELAY_US);
            }

            if (dribble < wb->len) {
                write_all(fd, wb->data + dribble, wb->len - dribble);
            }
            break;
        default:
            write_all(fd, wb->data, wb->len);
            break;
    } /* switch */
} /* deliver */

/*
 * The request body, as a repeating pattern rather than a constant: a client
 * that sends the right number of the wrong octets is caught.
 */
static char         g_request_body[REQUEST_BODY_LEN];

/* What the hostile server made of the requests it was sent, read by the driver
 * after the case completes. */
static volatile int g_request_body_len;
static volatile int g_request_body_ok;
static volatile int g_request_host_ok;
static volatile int g_request_host_count;
static volatile int g_requests_seen;

static void
fill_request_body(void)
{
    int i;

    for (i = 0; i < REQUEST_BODY_LEN; i++) {
        g_request_body[i] = (char) ('A' + (i % 26));
    }
} /* fill_request_body */

/* ------------------------------------------------------------------ *
* Reading what the client actually sent
*
* Two things are under test here, and neither is visible from the response
* side.  RFC 9112 section 3.2 makes a Host header mandatory on every HTTP/1.1
* request, which is the version libevpl's client speaks; and where the caller
* supplied a body, the peer has to receive exactly those octets under a framing
* that describes them -- which is the half of every other case in this suite
* that is taken on trust.
* ------------------------------------------------------------------ */

struct raw_request {
    int  host_count;
    int  chunked;
    int  declared;               /* Content-Length, or -1                */
    int  body_len;
    char body[REQUEST_BODY_LEN + 4096];
};

/* The next CRLF at or after `p`, or NULL. */
static const char *
find_crlf(
    const char *p,
    const char *end)
{
    while (p + 1 < end) {
        if (p[0] == '\r' && p[1] == '\n') {
            return p;
        }
        p++;
    }

    return NULL;
} /* find_crlf */

/*
 * Parse one complete request starting at buf[*off].  Returns 1 and advances
 * *off past it, or 0 if more bytes are needed.
 */
static int
parse_request(
    const char         *buf,
    int                 len,
    int                *off,
    struct raw_request *ri)
{
    const char *base = buf, *end = buf + len;
    const char *line, *eol, *colon, *value;
    char        name[128], val[256];
    int         p, chunk;

    memset(ri, 0, sizeof(*ri));
    ri->declared = -1;

    line = base + *off;

    /* The request line; its contents are conformance.c's business. */
    eol = find_crlf(line, end);

    if (!eol) {
        return 0;
    }

    line = eol + 2;

    for (;;) {
        eol = find_crlf(line, end);

        if (!eol) {
            return 0;
        }

        if (eol == line) {
            line += 2;
            break;
        }

        colon = memchr(line, ':', eol - line);

        if (colon) {
            size_t nlen = colon - line;
            size_t vlen;

            value = colon + 1;

            while (value < eol && (*value == ' ' || *value == '\t')) {
                value++;
            }

            vlen = eol - value;

            if (nlen > sizeof(name) - 1) {
                nlen = sizeof(name) - 1;
            }

            if (vlen > sizeof(val) - 1) {
                vlen = sizeof(val) - 1;
            }

            memcpy(name, line, nlen);
            name[nlen] = '\0';
            memcpy(val, value, vlen);
            val[vlen] = '\0';

            if (strcasecmp(name, "Host") == 0) {
                ri->host_count++;
            } else if (strcasecmp(name, "Content-Length") == 0) {
                ri->declared = atoi(val);
            } else if (strcasecmp(name, "Transfer-Encoding") == 0) {
                ri->chunked = strcasecmp(val, "chunked") == 0;
            }
        }

        line = eol + 2;
    }

    p = (int) (line - base);

    if (ri->chunked) {
        char size[64];

        for (;;) {
            eol = find_crlf(base + p, end);

            if (!eol) {
                return 0;
            }

            {
                size_t n = eol - (base + p);

                if (n > sizeof(size) - 1) {
                    n = sizeof(size) - 1;
                }

                memcpy(size, base + p, n);
                size[n] = '\0';
            }

            chunk = (int) strtol(size, NULL, 16);
            p     = (int) (eol + 2 - base);

            if (chunk == 0) {
                break;
            }

            if (len - p < chunk + 2) {
                return 0;
            }

            if (ri->body_len + chunk <= (int) sizeof(ri->body)) {
                memcpy(ri->body + ri->body_len, base + p, chunk);
                ri->body_len += chunk;
            }

            p += chunk + 2;
        }

        /* The trailer section, then the CRLF that ends the coding. */
        for (;;) {
            eol = find_crlf(base + p, end);

            if (!eol) {
                return 0;
            }

            if (eol == base + p) {
                p += 2;
                break;
            }

            p = (int) (eol + 2 - base);
        }

        *off = p;
        return 1;
    }

    if (ri->declared > 0) {
        if (len - p < ri->declared) {
            return 0;
        }

        if (ri->declared <= (int) sizeof(ri->body)) {
            memcpy(ri->body, base + p, ri->declared);
            ri->body_len = ri->declared;
        }

        p += ri->declared;
    }

    *off = p;

    return 1;
} /* parse_request */

/*
 * Read `count` complete requests off the socket and check what they carried.
 */
static void
drain_requests(
    int fd,
    int expect_body,
    int count)
{
    struct pollfd      pfd;
    struct raw_request ri;
    static char        buf[65536];
    int                len = 0, n, off = 0, seen = 0;
    int64_t            deadline;
    struct timespec    ts;

    g_request_body_len   = 0;
    g_request_body_ok    = 0;
    g_request_host_ok    = 1;
    g_request_host_count = -1;
    g_requests_seen      = 0;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    deadline = (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000 +
        CASE_TIMEOUT_MS;

    while (seen < count) {

        if (parse_request(buf, len, &off, &ri)) {
            seen++;

            if (g_request_host_count < 0 || ri.host_count != 1) {
                g_request_host_count = ri.host_count;
            }

            if (ri.host_count != 1) {
                g_request_host_ok = 0;
            }

            if (expect_body) {
                /* The oracle for the client's own outbound framing: the peer
                 * must receive exactly the octets the caller handed over,
                 * under a framing that describes them. */
                g_request_body_len = ri.body_len;
                g_request_body_ok  = ri.body_len == REQUEST_BODY_LEN &&
                    memcmp(ri.body, g_request_body, REQUEST_BODY_LEN) == 0;
            }

            continue;
        }

        clock_gettime(CLOCK_MONOTONIC, &ts);
        n = (int) (deadline -
                   ((int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000));

        if (n <= 0) {
            break;
        }

        pfd.fd      = fd;
        pfd.events  = POLLIN;
        pfd.revents = 0;

        if (poll(&pfd, 1, n) <= 0) {
            break;
        }

        n = read(fd, buf + len, (int) sizeof(buf) - len);

        if (n <= 0) {
            break;
        }

        len += n;

        if (len == (int) sizeof(buf)) {
            break;
        }
    }

    g_requests_seen = seen;
} /* drain_requests */

static void *
raw_server_function(void *ptr)
{
    struct raw_server *raw = ptr;
    struct wirebuf     wb;
    unsigned int       i;
    int                fd, close_after;

    for (i = 0; i < HTTP_NUM_CLIENT_CASES; i++) {

        raw->ready = 1;
        __sync_synchronize();

        fd = accept(raw->listen_fd, NULL, NULL);

        raw->ready = 0;

        if (fd >= 0) {
            const struct http_client_case *c =
                &http_client_cases[raw->case_index];

            drain_requests(fd, c->supply != HCSUP_SUPPLYNONE,
                           c->requests == HCREQ_TWOPIPELINED ? 2 : 1);

            wb_init(&wb);
            build_response(&wb, c, &close_after);

            deliver(fd, &wb, c->delivery);

            wb_free(&wb);

            if (close_after) {
                close(fd);
                fd = -1;
            }
        }

        /* Cases that do not need a close hold the connection until the driver
         * says it has finished with them, so that a client which completed the
         * request did so from the framing rather than from the FIN.  The
         * driver sets case_done; nothing here can, which is what makes the
         * wait a handshake rather than a deadlock. */
        while (!raw->case_done) {
            usleep(500);
        }

        if (fd >= 0) {
            close(fd);
        }
    }

    return NULL;
} /* raw_server_function */

/* ------------------------------------------------------------------ *
* The libevpl client under test
* ------------------------------------------------------------------ */

struct req_ctx {
    int  supply;         /* HCSUP_*: how the request body is handed over */
    int  sent;           /* how much of it has been handed over so far   */
    int  finished;       /* the end-of-body marker has been handed over  */
    int  n_headers;      /* RESPONSE_HEADERS callbacks                  */
    int  n_complete;     /* RECEIVE_COMPLETE callbacks                  */
    /* EVPL_HTTP_NOTIFY_FAILED callbacks, and the reason the last one
     * carried.  This is what makes a CbFailed expectation satisfiable at
     * all: without it the driver can only observe that nothing happened. */
    int  n_failed;
    int  error;
    int  status;
    int  body_len;
    int  probe_present;
    char probe[512];
    char body[BODY_MAX];
};

/* Collects what the response header block says about the probe, by
 * enumeration rather than by lookup. */
struct probe_scan {
    int  count;
    int  found;
    char value[512];
};

static void
probe_count_cb(
    const char *name,
    const char *value,
    void       *private_data)
{
    struct probe_scan *scan = private_data;

    if (strcasecmp(name, PROBE_NAME) != 0) {
        return;
    }

    if (!scan->found) {
        snprintf(scan->value, sizeof(scan->value), "%s", value);
        scan->found = 1;
    }

    scan->count++;
} /* probe_count_cb */

static void
client_drain(
    struct evpl              *evpl,
    struct evpl_http_request *request,
    struct req_ctx           *ctx)
{
    struct evpl_iovec iov[16];
    uint64_t          avail;
    int               niov, i, want;

    avail = evpl_http_request_get_data_avail(request);

    while (avail > 0) {
        want = avail > 16 ? 16 : (int) avail;
        niov = evpl_http_request_get_datav(evpl, request, iov, want);

        if (niov <= 0) {
            break;
        }

        for (i = 0; i < niov; i++) {
            if (ctx->body_len + (int) iov[i].length <= BODY_MAX) {
                memcpy(ctx->body + ctx->body_len, iov[i].data, iov[i].length);
            }
            ctx->body_len += iov[i].length;
            evpl_iovec_release(evpl, &iov[i]);
        }

        avail = evpl_http_request_get_data_avail(request);
    }
} /* client_drain */

/*
 * Hand libevpl the next piece of the request body.
 *
 * Whole for SupplyWhole, REQUEST_CHUNK at a time for SupplyStreamed and for
 * SupplyChunked.  The first two produce an identical request on the wire --
 * same octets, same Content-Length -- so the model predicts the same response
 * for both; what differs is that the streamed form leaves the send ring partly
 * drained, which is what makes libevpl ask for the rest.
 *
 * SupplyChunked is a different request: no length is declared, so the library
 * has to frame the body with the chunked coding, and it only knows the body has
 * ended when the caller says so.
 */
static void
client_send_body(
    struct evpl              *evpl,
    struct evpl_http_request *request,
    struct req_ctx           *ctx)
{
    struct evpl_iovec iov;
    int               chunk = REQUEST_BODY_LEN - ctx->sent;

    if (ctx->supply == HCSUP_SUPPLYNONE || ctx->finished) {
        return;
    }

    if (chunk > 0) {
        if (ctx->supply != HCSUP_SUPPLYWHOLE && chunk > REQUEST_CHUNK) {
            chunk = REQUEST_CHUNK;
        }

        evpl_iovec_alloc(evpl, chunk, 0, 1, 0, &iov);
        memcpy(iov.data, g_request_body + ctx->sent, chunk);
        iov.length = chunk;

        evpl_http_request_add_datav(request, &iov, 1);

        ctx->sent += chunk;
    }

    /* A chunked body has no declared length, so nothing but the caller can say
     * where it ends: the last-chunk goes out when this is called. */
    if (ctx->supply == HCSUP_SUPPLYCHUNKED &&
        ctx->sent == REQUEST_BODY_LEN) {
        evpl_http_request_add_datav(request, NULL, 0);
        ctx->finished = 1;
    }
} /* client_send_body */

static void
client_notify(
    struct evpl                *evpl,
    struct evpl_http_agent     *agent,
    struct evpl_http_request   *request,
    enum evpl_http_notify_type  notify_type,
    enum evpl_http_request_type request_type,
    const char                 *uri,
    void                       *notify_data,
    void                       *private_data)
{
    struct req_ctx   *ctx = notify_data;
    struct probe_scan scan;
    const char       *probe;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
            ctx->n_headers++;
            ctx->status = evpl_http_request_status(request);

            probe = evpl_http_response_header(request, PROBE_NAME);

            if (probe) {
                ctx->probe_present = 1;
                snprintf(ctx->probe, sizeof(ctx->probe), "%s", probe);
            }

            /* The other route to the same headers.  An application reads one
             * by name and enumerates them to log or forward them, and the two
             * must agree; nothing checked that, and
             * evpl_http_response_header_iterate had no caller at all. */
            memset(&scan, 0, sizeof(scan));
            evpl_http_response_header_iterate(request, probe_count_cb, &scan);

            if ((probe != NULL) != (scan.found != 0) ||
                (probe && strcmp(probe, scan.value) != 0)) {
                fprintf(stderr, "response header lookup and iteration "
                        "disagree ('%.64s' vs '%.64s')\n",
                        probe ? probe : "(absent)",
                        scan.found ? scan.value : "(absent)");
                exit(1);
            }
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            client_drain(evpl, request, ctx);
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            client_drain(evpl, request, ctx);
            ctx->n_complete++;
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            ctx->n_failed++;
            ctx->error = evpl_http_request_status(request);
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
            /* libevpl has taken what it was given and the request body is not
             * finished: hand over the next piece.  Only the streaming cases
             * get here, which is the point of having them -- a body handed
             * over whole completes in one pass and never asks. */
            client_send_body(evpl, request, ctx);
            break;
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            break;
    } /* switch */
} /* client_notify */

static int64_t
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
} /* now_ms */

/*
 * What the client did, in the model's terms where it has a name for it.
 *
 * A dispatched request has exactly two acceptable ends: the response, or the
 * news that there will not be one.  "The caller was told nothing" is reported
 * here as SILENT rather than being folded into either.
 */
static int
classify(const struct req_ctx *ctx)
{
    if (ctx->n_complete && ctx->n_headers) {
        return ctx->status;
    }

    if (ctx->n_complete) {
        return ACT_COMPLETE_ONLY;
    }

    if (ctx->n_headers) {
        return ACT_HEADERS_ONLY;
    }

    return ACT_SILENT;
} /* classify */

/* Whether a request has reached an end the caller can observe. */
static int
ctx_done(const struct req_ctx *ctx)
{
    return ctx->n_complete || ctx->n_failed;
} /* ctx_done */

/* Every ctx outlives its case: libevpl frees the request when the response
 * completes or the connection drops, but a callback that arrives after the
 * driver has moved on would otherwise write into a reused record.  Same
 * lesson the RPC2 client harness learned -- per-call state on the frame of
 * the case that started the call is only safe while abandoned calls never
 * complete. */
static struct req_ctx *g_ctx[4096 * MAX_REQUESTS];
static int             g_num_ctx;

static struct req_ctx *
ctx_alloc(void)
{
    struct req_ctx *ctx = calloc(1, sizeof(*ctx));

    if (!ctx) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }

    g_ctx[g_num_ctx++] = ctx;

    return ctx;
} /* ctx_alloc */

/*
 * Dispatch one request, with whatever body the case says the caller supplies.
 * Returns NULL if the library refused to create it.
 */
static struct evpl_http_request *
dispatch_one(
    struct evpl                   *evpl,
    struct evpl_http_conn         *conn,
    const struct http_client_case *c,
    struct req_ctx                *ctx)
{
    struct evpl_http_request *request;

    request = evpl_http_request_create(conn,
                                       c->method == HCMETH_CHEAD ?
                                       EVPL_HTTP_REQUEST_TYPE_HEAD :
                                       c->method == HCMETH_CPOST ?
                                       EVPL_HTTP_REQUEST_TYPE_POST :
                                       EVPL_HTTP_REQUEST_TYPE_GET,
                                       REQUEST_URI);

    if (!request) {
        return NULL;
    }

    /*
     * No Host header is added here on purpose.  RFC 9112 section 3.2 makes it
     * a MUST on every HTTP/1.1 request, and libevpl's client sends HTTP/1.1
     * unconditionally -- so supplying one from the test would be the harness
     * meeting an obligation that belongs to the library, and would hide
     * whether the library meets it.  The hostile server counts what arrives.
     */

    ctx->supply = c->supply;

    switch (c->supply) {
        case HCSUP_SUPPLYNONE:
            evpl_http_client_set_request_length(request, 0);
            break;
        case HCSUP_SUPPLYCHUNKED:
            /* No length: an application that does not know the size in advance
             * has only the chunked coding to frame the body with. */
            evpl_http_client_set_request_chunked(request);
            break;
        default:
            evpl_http_client_set_request_length(request, REQUEST_BODY_LEN);
            break;
    } /* switch */

    client_send_body(evpl, request, ctx);

    evpl_http_request_dispatch(request, client_notify, ctx);

    return request;
} /* dispatch_one */

/*
 * Check everything about one completed request that the case predicts.  Split
 * out from run_client_case because the pipelined case has two of them, and the
 * second is checked against exactly the same prediction as the first.
 */
static void
check_request(
    const struct http_client_case *c,
    const struct req_ctx          *ctx,
    int                            which)
{
    char detail[512];
    int  actual = classify(ctx);
    int  expect = c->expect == HCOUT_CBCOMPLETE ? c->expect_status : EXP_FAILED;
    int  ok;

    snprintf(detail, sizeof(detail), "%s, %s -> %s%s",
             http_client_defect_name(c->defect),
             http_delivery_name(c->delivery), outcome_name(actual),
             which ? " (second of a pipelined pair)" : "");

    /*
     * The outcome.
     *
     * CbFailed leaves the spelling open but not the substance: the caller has
     * to be told the request is over.  Neither of the other two observable
     * ends says that -- RECEIVE_COMPLETE on its own would say the request
     * SUCCEEDED, RESPONSE_HEADERS on its own says a status arrived and nothing
     * about whether more is coming -- and silence says nothing at all.  So the
     * check is EVPL_HTTP_NOTIFY_FAILED, and the reason it carries is checked
     * separately below.
     */
    if (c->expect == HCOUT_CBCOMPLETE) {
        ok = actual == c->expect_status;
    } else {
        ok = ctx->n_failed > 0;
    }

    record(which ? ASPECT_PIPELINE : ASPECT_OUTCOME, c->defect, expect, actual,
           ok, ok ? NULL : detail);

    /*
     * Outside the model: which failure it was.
     *
     * The model leaves the spelling of CbFailed open, because requiring a
     * particular code would be requiring an API rather than stating a protocol
     * obligation.  Now that there is one, the driver can hold it to account --
     * and the distinction is worth holding, since it is the whole reason for
     * having two codes.  A peer that went away may be worth retrying; a peer
     * whose response cannot be parsed will send the same one next time.
     */
    if (c->expect != HCOUT_CBCOMPLETE && ctx->n_failed) {
        /* CONN_LOST is for the cases where the connection ended before the
         * client had anything complete to judge.  RspNoStatusLine belongs with
         * them rather than with the parse failures, which reads oddly until
         * you look at what an HTTP/0.9 Simple-Response is on the wire: a body,
         * with no line terminator anywhere in it.  The client is still waiting
         * for the end of a status line when the peer hangs up, so it never had
         * one to reject, and "the connection ended before a response arrived"
         * is exactly what happened.  The truncation cases are the same shape
         * one layer down: the framing was fine, the content simply stopped. */
        int want = (c->defect == HCDEF_RSPPEERCLOSESWITHOUTRESPONSE ||
                    c->defect == HCDEF_RSPPEERCLOSESMIDSTATUSLINE ||
                    c->defect == HCDEF_RSPPEERCLOSESMIDHEADERS ||
                    c->defect == HCDEF_RSPBODYSHORTOFCONTENTLENGTH ||
                    c->defect == HCDEF_RSPCHUNKEDTRUNCATED ||
                    c->defect == HCDEF_RSPNOSTATUSLINE) ?
            EVPL_HTTP_ERROR_CONN_LOST : EVPL_HTTP_ERROR_BAD_RESPONSE;

        ok = ctx->error == want;

        snprintf(detail, sizeof(detail), "failed with %d, wanted %d",
                 ctx->error, want);

        record(ASPECT_REASON, c->defect, want, ctx->error, ok,
               ok ? NULL : detail);
    }

    /* Exactly one completion, whatever else happened: a second is a caller
     * whose callback runs twice on state it has already released. */
    ok = ctx->n_complete <= 1 && ctx->n_headers <= 1;

    snprintf(detail, sizeof(detail), "%d header callbacks, %d completions",
             ctx->n_headers, ctx->n_complete);

    record(ASPECT_ONCE, c->defect, VACT_OK, ok ? VACT_OK : VACT_BAD, ok,
           ok ? NULL : detail);

    if (c->expect != HCOUT_CBCOMPLETE || actual != c->expect_status) {
        return;
    }

    switch (c->expect_body) {
        case HCBODY_BODYNONE:
            ok = ctx->body_len == 0;
            break;
        case HCBODY_BODYDELIVERED:
            ok = ctx->body_len == (int) strlen(RESPONSE_BODY) &&
                memcmp(ctx->body, RESPONSE_BODY, ctx->body_len) == 0;

            if (c->defect == HCDEF_RSPBODYLONGERTHANCONTENTLENGTH) {
                /* Eleven octets were declared, so eleven is all that
                 * belongs to this response. */
                ok = ctx->body_len == 11 &&
                    memcmp(ctx->body, RESPONSE_BODY, 11) == 0;
            }
            break;
        default:
            ok = 1;
            break;
    } /* switch */

    snprintf(detail, sizeof(detail), "%d body bytes delivered", ctx->body_len);

    record(ASPECT_BODY, c->defect, c->expect_body,
           ok ? c->expect_body : HCBODY_BODYUNCHECKED, ok,
           ok ? NULL : detail);

    switch (c->expect_probe) {
        case HPROBE_PROBEVALUE:
            ok = ctx->probe_present && strcmp(ctx->probe, PROBE_VALUE) == 0;
            break;
        case HPROBE_PROBEEMPTY:
            ok = ctx->probe_present && ctx->probe[0] == '\0';
            break;
        case HPROBE_PROBEANY:
            ok = ctx->probe_present && ctx->probe[0] != '\0';
            break;
        case HPROBE_PROBEABSENT:
            ok = 1;   /* the case is not about the header block */
            break;
        default:
            ok = 1;
            break;
    } /* switch */

    snprintf(detail, sizeof(detail), "probe reflected as '%.128s'",
             ctx->probe_present ? ctx->probe : "(absent)");

    record(ASPECT_PROBE, c->defect, c->expect_probe,
           ok ? c->expect_probe : HPROBE_PROBEANY, ok, ok ? NULL : detail);
} /* check_request */

static void
run_client_case(
    struct evpl                   *evpl,
    struct evpl_http_agent        *agent,
    struct evpl_endpoint          *endpoint,
    const struct http_client_case *c,
    unsigned int                   index)
{
    struct evpl_http_conn *conn;
    struct req_ctx        *ctx, *ctx2 = NULL;
    char                   detail[512];
    int64_t                deadline;
    int                    two = c->requests == HCREQ_TWOPIPELINED;
    int                    ok;

    ctx = ctx_alloc();

    if (two) {
        ctx2 = ctx_alloc();
    }

    /* Publish the case before the client can connect, so the accept the
     * hostile server is about to take is unambiguously this one's. */
    while (!g_raw.ready) {
        sched_yield();
    }

    g_raw.case_index = (int) index;
    g_raw.case_done  = 0;
    __sync_synchronize();

    conn = evpl_http_client_connect(agent, EVPL_STREAM_SOCKET_TCP, endpoint,
                                    EVPL_HTTP_VERSION_HTTP1, ctx);

    if (!dispatch_one(evpl, conn, c, ctx) ||
        (two && !dispatch_one(evpl, conn, c, ctx2))) {
        fprintf(stderr, "case %s: request_create failed\n",
                http_client_defect_name(c->defect));
        g_results.unexpected++;
        g_raw.case_done = 1;
        __sync_synchronize();
        return;
    }

    g_results.cases_run++;

    deadline = now_ms() + CASE_TIMEOUT_MS;

    while (now_ms() < deadline &&
           (!ctx_done(ctx) || (two && !ctx_done(ctx2)))) {
        evpl_continue(evpl);
    }

    /* Keep pumping for a moment after the case has reached its end: a second
     * callback on a request that is already over is exactly the failure
     * ASPECT_ONCE exists to catch, and it can only be seen by waiting for
     * it. */
    deadline = now_ms() + SETTLE_MS;

    while (now_ms() < deadline) {
        evpl_continue(evpl);
    }

    check_request(c, ctx, 0);

    if (two) {
        check_request(c, ctx2, 1);
    }

    /*
     * Outside the model, and about the request rather than the response: RFC
     * 9112 section 3.2 makes a Host header mandatory on every HTTP/1.1
     * request, and libevpl's client speaks HTTP/1.1 unconditionally.  "A
     * server MUST respond with a 400 (Bad Request) status code to any HTTP/1.1
     * request message that lacks a Host header field", so a client that omits
     * it is a client whose requests a conforming server must refuse.
     */
    if (g_requests_seen > 0) {
        ok = g_request_host_ok;

        snprintf(detail, sizeof(detail),
                 "the peer received %d Host header(s) on an HTTP/1.1 request",
                 g_request_host_count);

        record(ASPECT_HOST, c->defect, 1, g_request_host_count, ok,
               ok ? NULL : detail);
    }

    /*
     * And the request body, which every other case takes on trust: the peer
     * must have received exactly the octets the caller handed over, under a
     * framing that describes them.
     */
    if (c->supply != HCSUP_SUPPLYNONE) {
        ok = g_request_body_ok;

        snprintf(detail, sizeof(detail),
                 "peer received %d request body bytes, sent %d",
                 g_request_body_len, REQUEST_BODY_LEN);

        record(ASPECT_REQUEST, c->defect, REQUEST_BODY_LEN,
               g_request_body_len, ok, ok ? NULL : detail);
    }

    /*
     * Retiring the connection.
     *
     * evpl_http_event frees the evpl_http_conn on EVPL_NOTIFY_DISCONNECTED
     * and there is no notification an application can register for, so the
     * pointer evpl_http_client_connect() returned becomes dangling at a moment
     * its owner cannot observe.  Calling evpl_http_client_close() on it is
     * then a use-after-free, which is what the first run of this harness did.
     *
     * So it is called on exactly the cases where the connection is known to be
     * there: the hostile server is holding its end open for this one, and the
     * response was delivered whole, which means the client had no reason to
     * close either.  Everywhere else the connection is retired by letting the
     * peer drop its end, and evpl_http_destroy sweeps whatever survives to the
     * end of the run.  "Only close one you have just successfully used" is a
     * rule an application can follow, but it should not have to.
     */
    if (case_holds_connection(c->defect) && ctx->n_complete && !ctx->n_failed) {
        evpl_http_client_close(agent, conn);
    }

    g_raw.case_done = 1;
    __sync_synchronize();

    deadline = now_ms() + 20;

    while (now_ms() < deadline) {
        evpl_continue(evpl);
    }
} /* run_client_case */

/* ------------------------------------------------------------------ *
* main
* ------------------------------------------------------------------ */

static void
report(void)
{
    int i;

    fprintf(stderr,
            "\nhttp/1.x client conformance: %d/%u cases (%d checks, %d "
            "failed)\n",
            g_results.cases_run, (unsigned int) HTTP_NUM_CLIENT_CASES,
            g_results.checks, g_results.failed);

    if (g_num_observed) {
        fprintf(stderr, "\ndivergences from RFC 1945 / RFC 9112:\n");
    }

    for (i = 0; i < g_num_observed; i++) {
        fprintf(stderr, "  %-8s %-38s expected %5d, got %5d  x%-4d %s\n",
                aspect_name(g_observed[i].aspect),
                http_client_defect_name(g_observed[i].defect),
                g_observed[i].expect, g_observed[i].actual,
                g_observed[i].count,
                g_observed[i].known ? "(known)" : "");
    }

    fprintf(stderr, "\n%d known divergence(s), %d unexpected\n",
            g_results.known, g_results.unexpected);
} /* report */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl               *evpl;
    struct evpl_http_agent    *agent;
    struct evpl_endpoint      *endpoint;
    struct evpl_thread_config *tconfig;
    struct sockaddr_in         addr;
    unsigned int               i;
    int                        opt, one = 1;

    /* The hostile server hangs up mid-conversation on purpose; a late write
     * must not take the harness down with it. */
    signal(SIGPIPE, SIG_IGN);

    fill_request_body();

    while ((opt = getopt(argc, argv, "p:")) != -1) {
        switch (opt) {
            case 'p':
                port = atoi(optarg);
                break;
            default:
                fprintf(stderr, "usage: %s [-p port]\n", argv[0]);
                return 1;
        } /* switch */
    }

    g_raw.listen_fd = socket(AF_INET, SOCK_STREAM, 0);

    if (g_raw.listen_fd < 0) {
        perror("socket");
        return 1;
    }

    setsockopt(g_raw.listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(port);

    if (bind(g_raw.listen_fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        perror("bind");
        return 1;
    }

    if (listen(g_raw.listen_fd, 16) < 0) {
        perror("listen");
        return 1;
    }

    evpl_init(NULL);

    pthread_create(&g_raw.thread, NULL, raw_server_function, &g_raw);

    /* Bound event waits so the per-case pump keeps ticking while nothing is
     * arriving, which is what lets a case reach its deadline. */
    tconfig = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(tconfig, PUMP_WAIT_MS);
    evpl = evpl_create(tconfig);

    agent    = evpl_http_init(evpl);
    endpoint = evpl_endpoint_create("127.0.0.1", port);

    for (i = 0; i < HTTP_NUM_CLIENT_CASES; i++) {
        run_client_case(evpl, agent, endpoint, &http_client_cases[i], i);
    }

    pthread_join(g_raw.thread, NULL);
    close(g_raw.listen_fd);

    evpl_http_destroy(agent);
    evpl_destroy(evpl);

    for (i = 0; i < (unsigned int) g_num_ctx; i++) {
        free(g_ctx[i]);
    }

    report();

    return g_results.unexpected ? 1 : 0;
} /* main */
