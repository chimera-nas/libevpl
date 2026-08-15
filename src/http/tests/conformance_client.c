/*
 * SPDX-FileCopyrightText: 2026 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Model-based HTTP/1.0 conformance test, client direction.
 *
 * conformance.c drives libevpl's HTTP *server* from a raw socket.  This is its
 * mirror image: a raw socket pretending to be a server, feeding deliberately
 * defective responses to a real libevpl HTTP client and checking what the
 * client does with them.  The cases come from the http10_client module of
 * quint/http10.qnt and are compiled in as part of http_cases.h.
 *
 * conformance.c cannot reach any of this, because the responses it sees come
 * from a real libevpl server and are therefore well formed by construction --
 * the same reason the RPC2 suite needs conformance_client.c alongside
 * conformance.c.
 *
 * The two requirements that carry most of the weight here, because both are
 * easy to violate and neither is visible from a well-behaved peer:
 *
 *   1. No request may be abandoned in silence.  A caller that dispatched a
 *      request is owed exactly one answer -- the response, or the news that
 *      there will not be one -- whatever the peer does, including hanging up.
 *      Anything else is a caller blocked forever.
 *
 *   2. A response whose framing is broken is not a result.  A truncated body
 *      or a length that is not a length must not reach the caller as a
 *      completed response, because the value it would hand over is one the
 *      peer never sent.
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
#define REQUEST_URI       "/probe"

/* Mirrors libevpl's default http_max_header_size, which the overlong case has
 * to exceed. */
#define MAX_HEADER_SIZE   8192

/* Wall-clock budget for one exchange.  Loopback responses land in
 * microseconds, so anything approaching this is a client that has stopped
 * making progress -- which is what several cases look for.  Kept small
 * because a few cases are expected to hit it. */
#define CASE_TIMEOUT_MS   400

/* How long the event loop blocks per turn.  Bounded so the pump keeps ticking
 * while nothing is arriving, which is what lets a case time out rather than
 * hang. */
#define PUMP_WAIT_MS      2

#define SPLIT_DELAY_US    200
#define DRIBBLE_DELAY_US  20
#define DRIBBLE_MAX_BYTES 512

#define BODY_MAX          4096

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

/* ASPECT_BODY / ASPECT_ONCE actuals. */
#define VACT_OK           0
#define VACT_BAD          1

static const char *
aspect_name(int aspect)
{
    switch (aspect) {
        case ASPECT_OUTCOME: return "outcome";
        case ASPECT_BODY:    return "body";
        case ASPECT_PROBE:   return "probe";
        case ASPECT_ONCE:    return "once";
        default:             return "?";
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
     * The unmatchable first row keeps the array non-empty when every real
     * entry has been retired, which is the state to aim for. */
    { .aspect = -1,
      .defect = -1,
      .expect = -1,
      .actual = -1,
      .note   = NULL },

    /* ---------------------------------------------------------------- *
    * A request that will not complete cannot be reported at all.
    *
    * evpl_http_notify_type has five arms and none of them means "this
    * request is over and there is no response".  So when the client
    * correctly refuses a response -- and on most of these it does refuse it,
    * promptly and for the right reason -- it closes the connection, and
    * evpl_http_event's EVPL_NOTIFY_DISCONNECTED arm frees every pending
    * request without invoking one callback.  The caller is left waiting on a
    * completion that can no longer arrive.
    *
    * This is the same defect the RPC2 suite found on its client
    * (EVPL_RPC2_REPLY_CONN_LOST was the fix there), and it needs the same
    * kind of remedy: somewhere for a failure to be delivered.  That is an
    * API addition rather than a bug fix -- a new notify type is a new value
    * in a public enum, which every switch over it has to grow an arm for --
    * so it is recorded here rather than done in passing.
    *
    * Every row below is that one gap.  They are listed per defect rather
    * than collapsed, so that a defect which starts failing a DIFFERENT way
    * still fails the test.
    * ---------------------------------------------------------------- */

    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPPEERCLOSESWITHOUTRESPONSE,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "the peer hung up and the caller was never told" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPPEERCLOSESMIDSTATUSLINE,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "truncated status line: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPPEERCLOSESMIDHEADERS,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "truncated header block: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPNOSTATUSLINE,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "HTTP/0.9 Simple-Response: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPSTATUSMISSING,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "status line with no code: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPVERSIONMALFORMED,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "unparseable version: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPMAJORVERSIONUNSUPPORTED,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "unsupported major version: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPHEADERNOCOLON,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "malformed header field: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPHEADERNAMEEMPTY,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "empty field-name: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPHEADERSPACEBEFORECOLON,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "whitespace before the colon: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPHEADERBLOCKOVERLONG,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "oversized header block: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPCONTENTLENGTHNOTNUMERIC,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "non-numeric Content-Length: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPCONTENTLENGTHNEGATIVE,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "negative Content-Length: refused, not reported" },

    /* Detected but unreportable for the same reason: the status line is now
     * parsed to the grammar (evpl_http_parse_status), so a code that is not
     * three digits in 1xx..5xx is refused rather than delivered -- and the
     * refusal, like the rest of this group, reaches the caller as silence. */
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPSTATUSNOTNUMERIC,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "non-numeric status: refused, not reported" },
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPSTATUSOUTOFRANGE,
      .expect = EXP_FAILED,
      .actual = ACT_SILENT,
      .note   = "status outside 1xx..5xx: refused, not reported" },

    /* The same gap, reached the other way: the status arrived, so the caller
     * has been told a response is coming, and then the body it was promised
     * never does.  Worse than silence, because the caller has evidence that
     * the request is progressing. */
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPBODYSHORTOFCONTENTLENGTH,
      .expect = EXP_FAILED,
      .actual = ACT_HEADERS_ONLY,
      .note   = "truncated body: the status arrived, the completion never did" },

    /* ---------------------------------------------------------------- *
    * Response body framing.
    * ---------------------------------------------------------------- */

    /* RFC 1945 section 7.2.2: with no Content-Length, "the length of that
     * body is determined by ... the server closing the connection".  It is
     * the only framing HTTP/1.0 has for a body whose size the server does not
     * know in advance, and the client reads such a response as EMPTY: the
     * status is delivered, the request completes, and the body is silently
     * dropped.  A caller has no way to tell that from a genuinely empty
     * response. */
    { .aspect = ASPECT_BODY,
      .defect = HCDEF_RSPBODYCLOSEDELIMITED,
      .expect = HCBODY_BODYDELIVERED,
      .actual = HCBODY_BODYUNCHECKED,
      .note   = "a close-delimited body is discarded, not delivered" },

    /* RFC 1945 section 8.2: the response to HEAD carries the headers a GET
     * would have -- Content-Length included -- and no body.  The client takes
     * the length at face value and waits for bytes that are never coming, so
     * every HEAD request hangs until something else tears the connection
     * down. */
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPHEADWITHCONTENTLENGTH,
      .expect = 200,
      .actual = ACT_HEADERS_ONLY,
      .note   = "a HEAD response waits for a body that cannot arrive" },

    /* The request path refuses two Content-Lengths that disagree, because the
     * message then has no single length; the response path still takes the
     * last one and delivers whatever that framing produces. */
    { .aspect = ASPECT_OUTCOME,
      .defect = HCDEF_RSPCONTENTLENGTHDUPLICATECONFLICTING,
      .expect = EXP_FAILED,
      .actual = 200,
      .note   = "conflicting Content-Lengths resolved instead of refused" },
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
 * Build the response for one case.  Sets *close_after when the case needs the
 * connection dropped: a close is itself part of the message for a
 * close-delimited body and for the truncation cases, and it is the whole of
 * the message for the three where the peer simply hangs up.
 *
 * Everywhere else the connection is deliberately LEFT OPEN, which is what
 * makes a case like RspStatusNoBody mean anything: a client that completes
 * the request without a close has understood the framing, while one that
 * completes only when the connection drops has merely been rescued by it.
 */
static void
build_response(
    struct wirebuf                *wb,
    const struct http_client_case *c,
    int                           *close_after)
{
    char line[128];
    int  i;

    *close_after = 0;

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
            *close_after = 1;
            break;

        case HCDEF_RSPSTATUS:
            snprintf(line, sizeof(line), "HTTP/1.0 %d Something\r\n",
                     (int) c->param);
            wb_str(wb, line);
            wb_str(wb, "Content-Length: 27\r\n\r\n" RESPONSE_BODY);
            break;

        case HCDEF_RSPSTATUSNOBODY:
            /* No Content-Length, and none is needed: RFC 1945 says these
             * carry no body, so the message ends with the header block. */
            snprintf(line, sizeof(line), "HTTP/1.0 %d No Body\r\n",
                     (int) c->param);
            wb_str(wb, line);
            wb_str(wb, PROBE_NAME ": " PROBE_VALUE "\r\n\r\n");
            break;

        case HCDEF_RSPBODYCLOSEDELIMITED:
            wb_str(wb, "HTTP/1.0 200 OK\r\n\r\n" RESPONSE_BODY);
            *close_after = 1;
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
            *close_after = 1;
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

        case HCDEF_RSPPEERCLOSESWITHOUTRESPONSE:
            *close_after = 1;
            break;

        case HCDEF_RSPPEERCLOSESMIDSTATUSLINE:
            wb_str(wb, "HTTP/1.0 20");
            *close_after = 1;
            break;

        case HCDEF_RSPPEERCLOSESMIDHEADERS:
            wb_str(wb, "HTTP/1.0 200 OK\r\n"
                   "Content-Length: 27\r\n");
            *close_after = 1;
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

/* Whether the buffer holds a terminated header block yet. */
static int
has_header_terminator(
    const char *buf,
    int         len)
{
    int i;

    for (i = 0; i + 3 < len; i++) {
        if (buf[i] == '\r' && buf[i + 1] == '\n' &&
            buf[i + 2] == '\r' && buf[i + 3] == '\n') {
            return 1;
        }
    }

    return 0;
} /* has_header_terminator */

/*
 * Read the client's request far enough to know it has finished sending one.
 * The request itself is not under test here -- conformance.c is where request
 * bytes are examined -- so this only needs to find the end of the header
 * block before the response goes out.
 */
static void
drain_request(int fd)
{
    struct pollfd   pfd;
    char            buf[8192];
    int             len = 0, n;
    int64_t         deadline;
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    deadline = (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000 +
        CASE_TIMEOUT_MS;

    for (;;) {
        if (has_header_terminator(buf, len)) {
            return;
        }

        clock_gettime(CLOCK_MONOTONIC, &ts);
        n = (int) (deadline -
                   ((int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000));

        if (n <= 0) {
            return;
        }

        pfd.fd      = fd;
        pfd.events  = POLLIN;
        pfd.revents = 0;

        if (poll(&pfd, 1, n) <= 0) {
            return;
        }

        n = read(fd, buf + len, (int) sizeof(buf) - len);

        if (n <= 0) {
            return;
        }

        len += n;

        if (len == (int) sizeof(buf)) {
            return;
        }
    }
} /* drain_request */

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
            drain_request(fd);

            wb_init(&wb);
            build_response(&wb, &http_client_cases[raw->case_index],
                           &close_after);

            deliver(fd, &wb, http_client_cases[raw->case_index].delivery);

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
    int  n_headers;      /* RESPONSE_HEADERS callbacks                  */
    int  n_complete;     /* RECEIVE_COMPLETE callbacks                  */
    /* Callbacks telling the caller the request will not complete.  There is
     * no notify type that means this, so nothing sets it; see the outcome
     * check in run_client_case. */
    int  n_failed;
    int  status;
    int  body_len;
    int  probe_present;
    char probe[512];
    char body[BODY_MAX];
};

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
    struct req_ctx *ctx = notify_data;
    const char     *probe;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
            ctx->n_headers++;
            ctx->status = evpl_http_request_status(request);

            probe = evpl_http_response_header(request, PROBE_NAME);

            if (probe) {
                ctx->probe_present = 1;
                snprintf(ctx->probe, sizeof(ctx->probe), "%s", probe);
            }
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            client_drain(evpl, request, ctx);
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:
            client_drain(evpl, request, ctx);
            ctx->n_complete++;
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
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
 * news that there will not be one.  libevpl's notify callback has no arm for
 * the second, so "the caller was told nothing" is reported here as SILENT
 * rather than being folded into a failure the API cannot express.
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

/* Every ctx outlives its case: libevpl frees the request when the response
 * completes or the connection drops, but a callback that arrives after the
 * driver has moved on would otherwise write into a reused record.  Same
 * lesson the RPC2 client harness learned -- per-call state on the frame of
 * the case that started the call is only safe while abandoned calls never
 * complete. */
static struct req_ctx *g_ctx[4096];

static void
run_client_case(
    struct evpl                   *evpl,
    struct evpl_http_agent        *agent,
    struct evpl_endpoint          *endpoint,
    const struct http_client_case *c,
    unsigned int                   index)
{
    struct evpl_http_conn    *conn;
    struct evpl_http_request *request;
    struct req_ctx           *ctx;
    char                      detail[512];
    int64_t                   deadline;
    int                       actual, ok, expect;

    ctx = calloc(1, sizeof(*ctx));

    if (!ctx) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }

    g_ctx[index] = ctx;

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

    request = evpl_http_request_create(conn,
                                       c->method == HCMETH_CHEAD ?
                                       EVPL_HTTP_REQUEST_TYPE_HEAD :
                                       EVPL_HTTP_REQUEST_TYPE_GET,
                                       REQUEST_URI);

    if (!request) {
        fprintf(stderr, "case %s: request_create failed\n",
                http_client_defect_name(c->defect));
        g_results.unexpected++;
        g_raw.case_done = 1;
        __sync_synchronize();
        return;
    }

    evpl_http_request_add_header(request, "Host", "localhost");
    evpl_http_client_set_request_length(request, 0);

    evpl_http_request_dispatch(request, client_notify, ctx);

    g_results.cases_run++;

    deadline = now_ms() + CASE_TIMEOUT_MS;

    while (now_ms() < deadline && !ctx->n_complete) {
        evpl_continue(evpl);
    }

    actual = classify(ctx);
    expect = c->expect == HCOUT_CBCOMPLETE ? c->expect_status : -1;

    snprintf(detail, sizeof(detail), "%s, %s -> %s",
             http_client_defect_name(c->defect),
             http_delivery_name(c->delivery), outcome_name(actual));

    /*
     * The outcome.
     *
     * CbFailed leaves the spelling open but not the substance: the caller has
     * to be told the request is over.  None of the three things the driver can
     * observe today says that.  RECEIVE_COMPLETE on its own would say the
     * request SUCCEEDED, RESPONSE_HEADERS on its own says a status arrived and
     * nothing about whether more is coming, and silence says nothing at all --
     * in every one of those the caller is still waiting.
     *
     * So the check is ctx->n_failed, which nothing sets, because
     * evpl_http_notify_type has no arm meaning "this request will not
     * complete".  That is the finding rather than a mis-stated expectation,
     * and one line in client_notify makes this live the day the API grows one.
     */
    if (c->expect == HCOUT_CBCOMPLETE) {
        ok = actual == c->expect_status;
    } else {
        ok = ctx->n_failed > 0;
    }

    record(ASPECT_OUTCOME, c->defect, expect, actual, ok, ok ? NULL : detail);

    /* Exactly one completion, whatever else happened: a second is a caller
     * whose callback runs twice on state it has already released. */
    ok = ctx->n_complete <= 1 && ctx->n_headers <= 1;

    snprintf(detail, sizeof(detail), "%d header callbacks, %d completions",
             ctx->n_headers, ctx->n_complete);

    record(ASPECT_ONCE, c->defect, VACT_OK, ok ? VACT_OK : VACT_BAD, ok,
           ok ? NULL : detail);

    if (c->expect == HCOUT_CBCOMPLETE && actual == c->expect_status) {

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

        snprintf(detail, sizeof(detail), "%d body bytes delivered",
                 ctx->body_len);

        record(ASPECT_BODY, c->defect, c->expect_body,
               ok ? c->expect_body : HCBODY_BODYUNCHECKED, ok,
               ok ? NULL : detail);

        switch (c->expect_probe) {
            case HPROBE_PROBEVALUE:
                ok = ctx->probe_present &&
                    strcmp(ctx->probe, PROBE_VALUE) == 0;
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
    }

    /*
     * The connection is retired by letting the hostile server drop its end,
     * not by calling evpl_http_client_close().
     *
     * That is not a stylistic choice.  evpl_http_event frees the
     * evpl_http_conn on EVPL_NOTIFY_DISCONNECTED and there is no notification
     * an application can register for, so the pointer
     * evpl_http_client_connect() returned becomes dangling at a moment the
     * caller cannot observe -- and most of the cases here end with exactly
     * that, since a client that cannot parse a response closes the
     * connection.  Calling close() on it is then a use-after-free, which is
     * what the first run of this harness found.  Until the API grows a way to
     * learn a connection has gone, the only safe thing an application can do
     * is what happens here: never close one it did not just successfully use,
     * and let evpl_http_destroy sweep whatever is still live.
     */
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
            "\nhttp/1.0 client conformance: %d/%u cases (%d checks, %d "
            "failed)\n",
            g_results.cases_run, (unsigned int) HTTP_NUM_CLIENT_CASES,
            g_results.checks, g_results.failed);

    if (g_num_observed) {
        fprintf(stderr, "\ndivergences from RFC 1945:\n");
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

    for (i = 0; i < HTTP_NUM_CLIENT_CASES; i++) {
        free(g_ctx[i]);
    }

    report();

    return g_results.unexpected ? 1 : 0;
} /* main */
