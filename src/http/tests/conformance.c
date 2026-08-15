/*
 * SPDX-FileCopyrightText: 2026 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Model-based HTTP/1.x conformance test, server direction.
 *
 * Four phases, the first three driven by cases generated from the Quint model
 * in quint/http1x.qnt and compiled in as http_cases.h:
 *
 *   1. Requests.  Legal HTTP/1.0 and HTTP/1.1 requests -- every version,
 *      method, URI shape, header grammar, body framing, connection
 *      disposition and delivery the model enumerates -- are written onto a raw
 *      socket, and the response is checked against what the RFCs require.  The
 *      server behind the socket is a real libevpl HTTP server running an echo
 *      application, so the reply carries the method, the URI, the probe header
 *      and the body it parsed: the oracle is what the server understood, not
 *      merely that it answered.
 *
 *   2. Defects.  Deliberately malformed requests, likewise written raw.  Each
 *      response is classified and compared against the status the RFCs
 *      require, at each version where the defect is one.
 *
 *   3. The status line, over every status the server can name, at both
 *      versions and with both response framings.  Outside the model on
 *      purpose; see run_status_phase.
 *
 * Every phase drives a raw socket rather than libevpl's own HTTP client,
 * because that client cannot express any of this: evpl_http_client_send_headers
 * emits a fixed header block at a fixed version, so it can neither send an
 * HTTP/1.0 request nor a malformed one.
 *
 * The model encodes the SPECIFICATION, so a mismatch here is a candidate bug
 * in libevpl rather than a broken test.  Known, reviewed divergences are
 * listed in known_divergences[] with a note; anything not on that list fails
 * the test.  That way the suite stays green while the outstanding gaps stay
 * visible and counted.
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
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include "evpl/evpl.h"
#include "evpl/evpl_http.h"

#include "http_cases.h"

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL        0
#endif /* ifndef MSG_NOSIGNAL */

/* ------------------------------------------------------------------ *
* Wire constants
*
* The byte-level spelling of every symbolic class in the model lives here,
* which is the whole point of the split: http1x.qnt says "a header whose
* value is padded with LWS", this file decides that means a tab.
* ------------------------------------------------------------------ */

static int port = 8095;

#define PROBE_NAME          "X-Probe"
#define PROBE_VALUE         "probe-value"
#define PROBE_SECOND_VALUE  "second-value"

/* The echo application reflects what it parsed through these.  Brackets
 * around the probe value so that "present but empty" is distinguishable from
 * "absent" on the wire, which is exactly the distinction HdrEmpty tests. */
#define ECHO_METHOD         "X-Echo-Method"
#define ECHO_URI            "X-Echo-Uri"
#define ECHO_PROBE          "X-Echo-Probe"
#define ECHO_PROBE_COUNT    "X-Echo-Probe-Count"

/* Asks the echo application to answer with this status rather than 200, and to
 * frame its response with the chunked coding rather than a length.  Used only
 * by the status phase; see run_status_phase. */
#define RESPOND_STATUS      "X-Respond-Status"
#define RESPOND_CHUNKED     "X-Respond-Chunked"
/* Asks the echo application to supply its own Date, which the library must
 * then leave alone rather than adding a second one. */
#define RESPOND_DATE        "X-Respond-Date"
#define RESPOND_DATE_VALUE  "Sun, 06 Nov 1994 08:49:37 GMT"
#define ECHO_ABSENT         "(absent)"

/* Asks the echo application to try to add response headers that are not
 * headers -- a value carrying a CRLF, and a name that is not a token.  See
 * run_injection_case. */
#define INJECT_ASK          "X-Inject"
#define INJECT_RESULT       "X-Inject-Result"
#define INJECT_SMUGGLED     "X-Smuggled"

#define URI_ROOT            "/"
#define URI_PATH            "/echo"
#define URI_QUERY           "/echo?a=1&b=2"
#define URI_ESCAPED         "/echo/a%20b%2Fc"

/* Long enough to prove nothing truncates it, short enough to stay far below
 * both the parser's line buffer and max_header_size -- it has to survive the
 * round trip through a response header too. */
#define URI_LONG_PATH_LEN   512

#define BODY_SMALL_LEN      37    /* deliberately not a multiple of anything */
#define BODY_LARGE_LEN      8000  /* larger than one receive buffer          */

/* The chunked bodies.  One chunk for the shapes that are about the coding's
 * syntax, many for the shape that is about spanning reads. */
#define BODY_CHUNKED_LEN    137
#define CHUNK_SPLIT_LEN     1000

/* Mirrors of libevpl's limits, which the two overflow defects must exceed.
 * Kept as their own constants so that a change to either shows up here as a
 * failing case rather than as a case that quietly stops overflowing. */
#define MAX_HEADER_SIZE     8192  /* evpl_global_config http_max_header_size */
#define MAX_HEADER_LINE     4096  /* the parser's line buffer                */

/* ------------------------------------------------------------------ *
* Timing
*
* Loopback responses land in microseconds, so anything approaching these is a
* server that has stopped making progress -- which is what several defect
* cases look for.  Kept small because a few cases are expected to hit them.
* ------------------------------------------------------------------ */

#define RESPONSE_TIMEOUT_MS 500  /* first response byte, or a stall          */
#define NOBODY_GRACE_MS     30   /* proving a body does NOT arrive           */
#define CLOSE_TIMEOUT_MS    250  /* proving the server closes                */
#define PERSIST_GRACE_MS    120  /* proving the server does NOT close        */

#define SPLIT_DELAY_US      200  /* between the halves of a TwoWrites        */
#define DRIBBLE_DELAY_US    20   /* between the bytes of a Dribble           */

/* A Dribble writes at most this many bytes one at a time and then the
 * remainder in one write.  Every state transition a byte-at-a-time delivery
 * can expose -- the request line, the first header fields, the header
 * terminator on a short request -- is inside the first few hundred bytes;
 * dribbling eight kilobytes of body afterwards costs a syscall and an
 * event-loop turn per byte and proves nothing further. */
#define DRIBBLE_MAX_BYTES   512

/* ------------------------------------------------------------------ *
* Outcomes the driver can observe that the model has no name for
* ------------------------------------------------------------------ */

#define ACT_STALLED         1000 /* no response and no close before the deadline */
#define ACT_NORESPONSE      1001 /* the peer closed having sent nothing      */
#define ACT_MALFORMED       1002 /* bytes that are not a parseable response  */
#define ACT_SIMPLE          1003 /* no status line: an HTTP/0.9 Simple-Response */

/* Aspects of a response that are checked, and diverge, independently.  A
 * single case can fail more than one of them -- a request that is refused
 * outright fails the status check and says nothing about the body -- so each
 * is reported separately rather than collapsed into one verdict per case. */
#define ASPECT_STATUS       0
#define ASPECT_BODY         1
#define ASPECT_PROBE        2
#define ASPECT_PERSIST      3
#define ASPECT_KEEPALIVE    4
#define ASPECT_ECHO_METHOD  5
#define ASPECT_ECHO_URI     6
#define ASPECT_FRAMING      7
#define ASPECT_INTERIM      8   /* a 1xx where the version allows one, or none */
#define ASPECT_REUSE        9   /* a second request on the same connection     */
#define ASPECT_PIPELINE     10  /* two requests in one write, answered in order */

#define PHASE_REQUEST       0
#define PHASE_DEFECT        1
#define PHASE_STATUS        2

/* ASPECT_PERSIST actuals. */
#define PACT_CLOSED         0
#define PACT_OPEN           1

/* ASPECT_KEEPALIVE / ASPECT_ECHO_* / ASPECT_FRAMING / ASPECT_INTERIM /
 * ASPECT_REUSE / ASPECT_PIPELINE actuals: the check either held or it did
 * not, and the report carries the case that failed it. */
#define VACT_OK             0
#define VACT_BAD            1

static const char *
aspect_name(int aspect)
{
    switch (aspect) {
        case ASPECT_STATUS:      return "status";
        case ASPECT_BODY:        return "body";
        case ASPECT_PROBE:       return "probe";
        case ASPECT_PERSIST:     return "persist";
        case ASPECT_KEEPALIVE:   return "keepalive";
        case ASPECT_ECHO_METHOD: return "echo-method";
        case ASPECT_ECHO_URI:    return "echo-uri";
        case ASPECT_FRAMING:     return "framing";
        case ASPECT_INTERIM:     return "interim";
        case ASPECT_REUSE:       return "reuse";
        case ASPECT_PIPELINE:    return "pipeline";
        default:                 return "?";
    } /* switch */
} /* aspect_name */

static const char *
outcome_name(int o)
{
    switch (o) {
        case ACT_STALLED:    return "STALLED";
        case ACT_NORESPONSE: return "NO_RESPONSE";
        case ACT_MALFORMED:  return "MALFORMED";
        case ACT_SIMPLE:     return "SIMPLE_RESPONSE";
        default:             return "status";
    } /* switch */
} /* outcome_name */

/* The subject a divergence is filed under, which is the dimension of the case
 * that identifies it: the defect for phase 2, and for phase 1 the class that
 * the aspect is a property of.  Coarser than the whole case on purpose --
 * "HEAD returns a body" is one fact about the server, not one per URI shape
 * it was asked for.
 *
 * A refused request is filed under its header shape, because that is the only
 * dimension of the positive matrix whose grammar a server can plausibly
 * reject: the methods and URI forms here are the ones the RFCs define, while
 * the header block is where a hand-written parser meets folding, empty values
 * and repeated fields.  The full case is printed alongside, so a refusal that
 * really came from somewhere else is still legible in the log. */
static const char *
subject_name(
    int phase,
    int aspect,
    int subject)
{
    static char code[16];

    if (phase == PHASE_STATUS) {
        /* The subject is the status the application asked for. */
        snprintf(code, sizeof(code), "%d", subject);
        return code;
    }

    if (phase == PHASE_DEFECT) {
        return http_defect_name(subject);
    }

    switch (aspect) {
        case ASPECT_STATUS:
        case ASPECT_PROBE:
            return http_hdr_name(subject);
        case ASPECT_PERSIST:
        case ASPECT_KEEPALIVE:
        case ASPECT_REUSE:
            return http_conn_name(subject);
        case ASPECT_ECHO_URI:
            return http_uri_name(subject);
        case ASPECT_FRAMING:
        case ASPECT_INTERIM:
        case ASPECT_PIPELINE:
            return http_version_name(subject);
        default:
            return http_method_name(subject);
    } /* switch */
} /* subject_name */

/* ------------------------------------------------------------------ *
* Known divergences from the specification
*
* Each entry records a case where libevpl's behaviour differs from what the
* model requires, so the suite can stay green while the gap remains visible.
* Removing an entry turns the corresponding case back into a hard failure,
* which is what should happen once the underlying issue is fixed.
* ------------------------------------------------------------------ */

struct known_divergence {
    int         phase;
    int         aspect;
    int         subject;
    int         expect;
    int         actual;
    const char *note;
};

static const struct known_divergence known_divergences[] = {
    /* Add an entry here only for a divergence that has been reviewed and
     * consciously deferred, with a note saying why -- an unlisted one fails
     * the test, which is what keeps a regression from passing silently.
     *
     * The unmatchable first row keeps the array non-empty when every real
     * entry has been retired, which is the state to aim for. */
    { .phase   = -1,
      .aspect  = -1,
      .subject = -1,
      .expect  = -1,
      .actual  = -1,
      .note    = NULL },

    /* ---------------------------------------------------------------- *
    * HTTP/0.9, deliberately not implemented.
    *
    * A request line with no version is a Simple-Request, and RFC 1945 section
    * 6 pairs it with a Simple-Response: the body alone, with no status line
    * and no headers.  libevpl answers 400 instead, which is the only entry
    * here that is a decision rather than a gap.
    *
    * Supporting it would make the shape of a response depend on how the
    * request was spelled, which is a discontinuity every part of the response
    * path would have to know about -- and it would reintroduce the one
    * message framing in HTTP that carries no length and no status, on a
    * server that has just been taught to refuse messages whose length is
    * ambiguous.  HTTP/1.1 dropped the form entirely (RFC 7230 appendix A.2)
    * and RFC 9112 section 2.1 lets a server answer a request line it does not
    * recognise with 400, which is what happens here.
    *
    * The case stays in the model rather than being deleted from it, because
    * what RFC 1945 requires does not change when an implementation decides
    * not to do it.  This entry is the decision, and it is the honest place
    * for it.
    * ---------------------------------------------------------------- */

    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_REQUESTLINENOVERSION,
      .expect  = -HOUT_SIMPLERESPONSE,
      .actual  = 400,
      .note    = "an HTTP/0.9 Simple-Request is answered 400, not with a body" },
};

static int
is_known_divergence(
    int phase,
    int aspect,
    int subject,
    int expect,
    int actual)
{
    unsigned int i;

    for (i = 0; i < sizeof(known_divergences) / sizeof(known_divergences[0]);
         i++) {
        if (known_divergences[i].phase == phase &&
            known_divergences[i].aspect == aspect &&
            known_divergences[i].subject == subject &&
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
    int phase;
    int aspect;
    int subject;
    int expect;
    int actual;
    int count;
    int known;
};

static struct observed g_observed[MAX_OBSERVED];
static int             g_num_observed;

static struct {
    int request_run;
    int request_checks;
    int request_failed;
    int defect_run;
    int defect_checks;
    int defect_failed;
    int status_run;
    int status_checks;
    int status_failed;
    int unexpected;
    int known;
} g_results;

/*
 * Record one aspect of one case.  `ok` is the driver's own comparison; the
 * bookkeeping here is only about how a failure is reported, so that a
 * divergence that has been reviewed is counted rather than fatal.
 */
static void
record(
    int         phase,
    int         aspect,
    int         subject,
    int         expect,
    int         actual,
    int         ok,
    const char *detail)
{
    struct observed *o;
    int              known, i;

    switch (phase) {
        case PHASE_REQUEST:
            g_results.request_checks++;
            break;
        case PHASE_DEFECT:
            g_results.defect_checks++;
            break;
        default:
            g_results.status_checks++;
            break;
    } /* switch */

    if (ok) {
        return;
    }

    switch (phase) {
        case PHASE_REQUEST:
            g_results.request_failed++;
            break;
        case PHASE_DEFECT:
            g_results.defect_failed++;
            break;
        default:
            g_results.status_failed++;
            break;
    } /* switch */

    known = is_known_divergence(phase, aspect, subject, expect, actual);

    if (known) {
        g_results.known++;
    } else {
        g_results.unexpected++;
    }

    for (i = 0; i < g_num_observed; i++) {
        o = &g_observed[i];
        if (o->phase == phase && o->aspect == aspect && o->subject == subject &&
            o->expect == expect && o->actual == actual) {
            o->count++;
            return;
        }
    }

    if (g_num_observed == MAX_OBSERVED) {
        return;
    }

    o = &g_observed[g_num_observed++];

    o->phase   = phase;
    o->aspect  = aspect;
    o->subject = subject;
    o->expect  = expect;
    o->actual  = actual;
    o->count   = 1;
    o->known   = known;

    /* First occurrence only: a divergence that shows up in two hundred cases
     * should be one line in the log, not two hundred. */
    fprintf(stderr, "%s %s/%s: expected %d, got %d%s%s\n",
            known ? "known divergence" : "DIVERGENCE",
            aspect_name(aspect), subject_name(phase, aspect, subject),
            expect, actual, detail ? " -- " : "", detail ? detail : "");
} /* record */

/* ------------------------------------------------------------------ *
* The echo server
*
* A real libevpl HTTP server whose application reflects what the parser
* produced: the method, the URI, the probe header and the request body all
* come back in the response.  That makes the oracle "what did the server
* understand" rather than "did the server answer", which is the difference
* between testing a parser and testing a socket.
* ------------------------------------------------------------------ */

struct test_server {
    pthread_t            thread;
    volatile int         run;
    struct evpl_doorbell doorbell;
};

struct probe_scan {
    int  count;
    char value[512];
    int  found;
};

/* How many iovecs the echo application drains at a time. */
#define ECHO_DRAIN_IOV    64

/*
 * How much of the response the echo application hands over at a time when it
 * streams.
 *
 * Handing the whole body over at once is the easy shape, and the one every
 * other test here used, so evpl_http_send_body's partial-drain loop and the
 * WANT_DATA notification that drives it were never executed.  Streaming is a
 * property of the application rather than of the protocol -- the bytes on the
 * wire are identical either way -- so this is invisible to the model, which
 * still expects exactly the same response.
 */
#define ECHO_STREAM_CHUNK 1500

/*
 * Per-request state for the echo application, allocated when the request is
 * dispatched and released when it ends.
 *
 * "When it ends" is the point: a connection dropped mid-response ends it just
 * as much as a completed response does, and before EVPL_HTTP_NOTIFY_FAILED
 * existed there was nowhere to release this from.  One of these would have
 * leaked per request the defect phase abandoned, which it does constantly.
 */
struct echo_state {
    int  len;       /* bytes of body echoed back                      */
    int  sent;      /* how much has been handed to libevpl so far     */
    int  streamed;  /* handing it over in pieces rather than at once  */
    char body[BODY_LARGE_LEN + 64];
};

static void
server_wake(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
} /* server_wake */

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

/*
 * Hand libevpl the next piece of the echoed body.
 *
 * Whole when it fits, ECHO_STREAM_CHUNK at a time when it does not.  The bytes
 * on the wire are the same either way -- what differs is that the streamed
 * form leaves evpl_http_send_body with a partly-drained send ring, which is
 * what makes it return "not done" and fire WANT_DATA.
 */
static void
echo_send_next(
    struct evpl              *evpl,
    struct evpl_http_request *request,
    struct echo_state        *st)
{
    struct evpl_iovec rsp;
    int               chunk = st->len - st->sent;

    if (chunk <= 0) {
        return;
    }

    if (st->streamed && chunk > ECHO_STREAM_CHUNK) {
        chunk = ECHO_STREAM_CHUNK;
    }

    evpl_iovec_alloc(evpl, chunk, 0, 1, 0, &rsp);
    memcpy(rsp.data, st->body + st->sent, chunk);
    rsp.length = chunk;

    evpl_http_request_add_datav(request, &rsp, 1);

    st->sent += chunk;
} /* echo_send_next */

static void
server_notify(
    struct evpl                *evpl,
    struct evpl_http_agent     *agent,
    struct evpl_http_request   *request,
    enum evpl_http_notify_type  notify_type,
    enum evpl_http_request_type request_type,
    const char                 *uri,
    void                       *notify_data,
    void                       *private_data)
{
    struct echo_state *st = notify_data;
    struct evpl_iovec  iov[ECHO_DRAIN_IOV];
    struct probe_scan  scan;
    const char        *probe, *uri_echo;
    char               echo[1024];
    char               count[16];
    uint64_t           avail;
    int                niov, i, want, chunked, uri_len;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            /* The body is drained once, at completion, so that the echo is a
             * single contiguous comparison.  Nothing to do here. */
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:

            memset(&scan, 0, sizeof(scan));
            evpl_http_request_header_iterate(request, probe_count_cb, &scan);

            /* The accessor and the callback argument are two routes to the
             * same fact, so they must agree; nothing else in the suite says
             * so, and evpl_http_request_type had no caller at all. */
            if (evpl_http_request_type(request) != request_type) {
                fprintf(stderr, "echo: request type accessor disagrees with "
                        "the notification (%d vs %d)\n",
                        evpl_http_request_type(request), request_type);
                exit(1);
            }

            evpl_http_request_add_header(request, ECHO_METHOD,
                                         evpl_http_request_type_to_string(
                                             request));

            /* Through the length out-param, which nothing else calls: an
             * application that forwards a URI needs its length, and a length
             * that disagrees with the string is a truncation nobody sees. */
            uri_echo = evpl_http_request_url(request, &uri_len);

            if (uri_len != (int) strlen(uri_echo)) {
                fprintf(stderr, "echo: request_url length %d disagrees with "
                        "the string (%zu)\n", uri_len, strlen(uri_echo));
                exit(1);
            }

            evpl_http_request_add_header(request, ECHO_URI, uri_echo);

            /* Looked up by name as well as counted by iteration: an
             * application reads a header the first way, and the two must
             * produce the same value.  evpl_http_request_header had no caller
             * either, so nothing checked that the lookup finds what the
             * iteration sees -- including the case-insensitive match, which
             * HdrMixedCase depends on. */
            probe = evpl_http_request_header(request, PROBE_NAME);

            if ((probe != NULL) != (scan.found != 0) ||
                (probe && strcmp(probe, scan.value) != 0)) {
                fprintf(stderr, "echo: header lookup and iteration disagree "
                        "('%s' vs '%s')\n", probe ? probe : "(absent)",
                        scan.found ? scan.value : "(absent)");
                exit(1);
            }

            if (probe) {
                snprintf(echo, sizeof(echo), "[%s]", probe);
            } else {
                snprintf(echo, sizeof(echo), "%s", ECHO_ABSENT);
            }

            evpl_http_request_add_header(request, ECHO_PROBE, echo);

            snprintf(count, sizeof(count), "%d", scan.count);
            evpl_http_request_add_header(request, ECHO_PROBE_COUNT, count);

            /* Response splitting, reached from the one direction the wire
             * cannot: an application header whose value carries a CRLF, or
             * whose name is not a token.  Neither can arrive in a request --
             * the parser splits lines on LF, so a header value never contains
             * one -- but an application builds header values from redirect
             * targets, query parameters and database rows, and any of those
             * can. */
            if (evpl_http_request_header(request, INJECT_ASK)) {
                int refused = 0;

                refused += evpl_http_request_add_header(
                    request, "X-Injected",
                    "ok\r\n" INJECT_SMUGGLED ": yes") < 0;

                refused += evpl_http_request_add_header(
                    request, "X-Bad Name", "value") < 0;

                refused += evpl_http_request_add_header(request, "", "value")
                    < 0;

                evpl_http_request_add_header(request, INJECT_RESULT,
                                             refused == 3 ? "refused" :
                                             "accepted");
            }

            /* Echo the request body back verbatim.  The same code runs for
             * HEAD: whether a body reaches the wire for a HEAD request is the
             * server's decision to make (RFC 9110 section 9.3.2), not the
             * application's, and taking it here would hide the answer.
             *
             * Drained in bounded steps and flattened into one buffer.  A
             * dribbled request arrives as one iovec per byte, so asking for
             * the whole of what is available in one call would return an
             * unbounded number of them -- evpl_http_request_get_datav writes
             * as many as the bytes need, and the caller's array is the only
             * thing that bounds it.  Asking for at most as many bytes as the
             * array has entries makes the bound hold whatever the
             * fragmentation. */
            avail = evpl_http_request_get_data_avail(request);

            while (avail > 0 && st->len < (int) sizeof(st->body)) {
                want = avail > ECHO_DRAIN_IOV ? ECHO_DRAIN_IOV : (int) avail;
                niov = evpl_http_request_get_datav(evpl, request, iov, want);

                if (niov <= 0) {
                    break;
                }

                for (i = 0; i < niov; i++) {
                    memcpy(st->body + st->len, iov[i].data, iov[i].length);
                    st->len += iov[i].length;
                    evpl_iovec_release(evpl, &iov[i]);
                }

                avail = evpl_http_request_get_data_avail(request);
            }

            /* Anything that will not fit in one piece is handed over in
             * several, which is the shape an application streaming a file
             * would use and the only one that reaches WANT_DATA. */
            st->streamed = st->len > ECHO_STREAM_CHUNK;

            /* The response framing is the application's to choose between the
             * two libevpl offers, and the status phase chooses it through this
             * header.  Which of them may actually reach the wire for a given
             * request is NOT the application's business -- a transfer coding
             * belongs only in a response to an HTTP/1.1 request, and only on a
             * status that may carry content -- so asking for the wrong one
             * here is how the driver finds out whether the library knows
             * that. */
            /* An application that has its own clock reading, or that has to
             * make the value match something it has signed, supplies its own
             * Date -- and the library must then leave it alone. */
            if (evpl_http_request_header(request, RESPOND_DATE)) {
                evpl_http_request_add_header(request, "Date",
                                             RESPOND_DATE_VALUE);
            }

            chunked = evpl_http_request_header(request, RESPOND_CHUNKED) != NULL;

            if (chunked) {
                evpl_http_server_set_response_chunked(request);
            } else {
                evpl_http_server_set_response_length(request, st->len);
            }

            echo_send_next(evpl, request, st);

            if (chunked && st->sent == st->len) {
                /* A chunked response ends where the application says it does,
                 * so say so: there is no length counting down to zero. */
                evpl_http_request_add_datav(request, NULL, 0);
            }

            /* The status is the application's to choose, and the status
             * phase chooses it through this header. */
            probe = evpl_http_request_header(request, RESPOND_STATUS);

            evpl_http_server_dispatch_default(request, probe ? atoi(probe) :
                                              200);
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
            /* libevpl has drained what it was given and the response is not
             * complete: hand over the next piece. */
            echo_send_next(evpl, request, st);

            if (st->sent == st->len) {
                evpl_http_request_add_datav(request, NULL, 0);
            }
            break;
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
            break;
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
            free(st);
            break;
        case EVPL_HTTP_NOTIFY_FAILED:
            /* The defect phase closes on the server mid-exchange constantly,
             * so a request that can no longer be answered is expected here.
             * What matters is that the notification arrives at all: without
             * it this allocation would leak once per abandoned request, which
             * is the shape of leak the arm exists to prevent. */
            free(st);
            break;
    } /* switch */
} /* server_notify */

static void
server_dispatch(
    struct evpl                 *evpl,
    struct evpl_http_agent      *agent,
    struct evpl_http_request    *request,
    evpl_http_notify_callback_t *notify_callback,
    void                       **notify_data,
    void                        *private_data)
{
    struct echo_state *st = calloc(1, sizeof(*st));

    if (!st) {
        fprintf(stderr, "echo: out of memory\n");
        exit(1);
    }

    *notify_callback = server_notify;
    *notify_data     = st;
} /* server_dispatch */

static void *
server_function(void *ptr)
{
    struct test_server      *ctx = ptr;
    struct evpl_http_server *server;
    struct evpl             *evpl;
    struct evpl_endpoint    *endpoint;
    struct evpl_listener    *listener;
    struct evpl_http_agent  *agent;

    evpl = evpl_create(NULL);

    evpl_add_doorbell(evpl, &ctx->doorbell, server_wake);

    agent = evpl_http_init(evpl);

    endpoint = evpl_endpoint_create("0.0.0.0", port);

    listener = evpl_listener_create();

    server = evpl_http_attach(agent, listener, server_dispatch, NULL);

    evpl_listen(listener, EVPL_STREAM_SOCKET_TCP, endpoint);

    __sync_synchronize();

    ctx->run = 1;

    while (ctx->run) {
        evpl_continue(evpl);
    }

    evpl_http_server_destroy(agent, server);
    evpl_http_destroy(agent);

    evpl_listener_destroy(listener);
    evpl_destroy(evpl);

    return NULL;
} /* server_function */

/* ------------------------------------------------------------------ *
* A growable byte buffer for building requests
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
        fprintf(stderr, "out of memory building a request\n");
        exit(1);
    }
} /* wb_init */

static void
wb_free(struct wirebuf *wb)
{
    free(wb->data);
    wb->data = NULL;
    wb->len  = 0;
    wb->cap  = 0;
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
            fprintf(stderr, "out of memory building a request\n");
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
 * The body every case that carries one sends, and the bytes the echo is
 * compared against.  A repeating pattern rather than a constant, so that a
 * server which returns the right number of the wrong bytes is caught.
 */
static void
fill_body(
    char *dst,
    int   len)
{
    int i;

    for (i = 0; i < len; i++) {
        dst[i] = (char) ('a' + (i % 26));
    }
} /* fill_body */

/* ------------------------------------------------------------------ *
* Class to wire bytes
* ------------------------------------------------------------------ */

static const char *
version_wire(int ver)
{
    return ver == HVER_V11 ? "HTTP/1.1" : "HTTP/1.0";
} /* version_wire */

static int
body_is_chunked(int body_cls)
{
    switch (body_cls) {
        case HBDY_BODYCHUNKED:
        case HBDY_BODYCHUNKEDEXT:
        case HBDY_BODYCHUNKEDTRAILER:
        case HBDY_BODYCHUNKEDMANY:
            return 1;
        default:
            return 0;
    } /* switch */
} /* body_is_chunked */

static int
body_length(int body_cls)
{
    switch (body_cls) {
        case HBDY_BODYNONE:  return 0;
        case HBDY_BODYEMPTY: return 0;
        case HBDY_BODYONE:   return 1;
        case HBDY_BODYSMALL: return BODY_SMALL_LEN;
        case HBDY_BODYLARGE: return BODY_LARGE_LEN;
        case HBDY_BODYCHUNKED:
        case HBDY_BODYCHUNKEDEXT:
        case HBDY_BODYCHUNKEDTRAILER:
            return BODY_CHUNKED_LEN;
        case HBDY_BODYCHUNKEDMANY:
            return BODY_LARGE_LEN;
        default:             return 0;
    } /* switch */
} /* body_length */

static const char *
method_wire(int method_cls)
{
    switch (method_cls) {
        case HMETH_MGET:    return "GET";
        case HMETH_MHEAD:   return "HEAD";
        case HMETH_MPOST:   return "POST";
        case HMETH_MPUT:    return "PUT";
        case HMETH_MDELETE: return "DELETE";
        default:            return "GET";
    } /* switch */
} /* method_wire */

/* What evpl_http_request_type_to_string() spells the method as, which is what
 * comes back in X-Echo-Method. */
static const char *
method_echoed(int method_cls)
{
    switch (method_cls) {
        case HMETH_MGET:    return "Get";
        case HMETH_MHEAD:   return "Head";
        case HMETH_MPOST:   return "Post";
        case HMETH_MPUT:    return "Put";
        case HMETH_MDELETE: return "Delete";
        default:            return "Get";
    } /* switch */
} /* method_echoed */

static char g_uri_long[URI_LONG_PATH_LEN + 16];
static char g_uri_absolute[128];
static char g_host_value[64];

static const char *
uri_wire(int uri_cls)
{
    switch (uri_cls) {
        case HURI_URIROOT:     return URI_ROOT;
        case HURI_URIPATH:     return URI_PATH;
        case HURI_URIQUERY:    return URI_QUERY;
        case HURI_URIESCAPED:  return URI_ESCAPED;
        case HURI_URILONG:     return g_uri_long;
        case HURI_URIABSOLUTE: return g_uri_absolute;
        default:               return URI_PATH;
    } /* switch */
} /* uri_wire */

/*
 * The header fields a request carries, less the ones the framing adds (Host,
 * Connection, Content-Length, Transfer-Encoding, Expect).  Every shape here is
 * legal RFC 9112 section 5 grammar; the model says which, this says how it is
 * spelled.
 */
static void
append_headers(
    struct wirebuf *wb,
    int             hdr_cls)
{
    char line[128];
    int  i;

    switch (hdr_cls) {
        case HHDR_HDRNONE:
            break;
        case HHDR_HDRPLAIN:
            wb_str(wb, PROBE_NAME ": " PROBE_VALUE "\r\n");
            break;
        case HHDR_HDRPADDED:
            /* LWS is SP and HT, either side of the value, and none of it is
             * part of the value. */
            wb_str(wb, PROBE_NAME ":  \t" PROBE_VALUE " \t\r\n");
            break;
        case HHDR_HDREMPTY:
            wb_str(wb, PROBE_NAME ":\r\n");
            break;
        case HHDR_HDRMIXEDCASE:
            wb_str(wb, "x-pRoBe: " PROBE_VALUE "\r\n");
            break;
        case HHDR_HDRFOLDED:
            /* A continuation line: the field continues on the next line
             * because that line begins with LWS. */
            wb_str(wb, PROBE_NAME ": probe-\r\n\tvalue\r\n");
            break;
        case HHDR_HDRDUPLICATE:
            wb_str(wb, PROBE_NAME ": " PROBE_VALUE "\r\n");
            wb_str(wb, PROBE_NAME ": " PROBE_SECOND_VALUE "\r\n");
            break;
        case HHDR_HDRMANY:
            for (i = 0; i < 16; i++) {
                snprintf(line, sizeof(line), "X-Fill-%d: filler-value-%d\r\n",
                         i, i);
                wb_str(wb, line);
            }
            wb_str(wb, PROBE_NAME ": " PROBE_VALUE "\r\n");
            break;
        default:
            break;
    } /* switch */
} /* append_headers */

/*
 * Append `len` bytes of `body` chunked-encoded (RFC 9112 section 7.1).
 *
 *     chunked-body = *chunk last-chunk trailer-section CRLF
 *     chunk        = chunk-size [ chunk-ext ] CRLF chunk-data CRLF
 *
 * The three variants differ only in the parts a decoder can produce the right
 * body without ever looking at, which is exactly why they are separate cases:
 * an extension that is not skipped corrupts the size, and a trailer section
 * that is not consumed is left to be read as the start of the next request.
 */
static void
append_chunked_body(
    struct wirebuf *wb,
    const char     *body,
    int             len,
    int             body_cls)
{
    char line[64];
    int  off = 0, chunk;
    int  split = body_cls == HBDY_BODYCHUNKEDMANY ? CHUNK_SPLIT_LEN : len;

    while (off < len) {
        chunk = len - off;

        if (split > 0 && chunk > split) {
            chunk = split;
        }

        if (body_cls == HBDY_BODYCHUNKEDEXT) {
            /* With the "bad whitespace" the chunk-ext grammar allows around
             * the semicolon, since a decoder that stops at the first space
             * reads the size and then loses the rest of the line. */
            snprintf(line, sizeof(line), "%x ;probe=1;flag\r\n", chunk);
        } else {
            snprintf(line, sizeof(line), "%x\r\n", chunk);
        }

        wb_str(wb, line);
        wb_append(wb, body + off, chunk);
        wb_str(wb, "\r\n");

        off += chunk;
    }

    wb_str(wb, "0\r\n");

    if (body_cls == HBDY_BODYCHUNKEDTRAILER) {
        wb_str(wb, "X-Trailer: after-the-body\r\n");
        wb_str(wb, "X-Trailer-Two: and-another\r\n");
    }

    wb_str(wb, "\r\n");
} /* append_chunked_body */

/*
 * Build one request of the positive matrix.  Returns the body bytes it
 * carried (into `body`) so the echo can be compared against them.
 */
static void
build_request(
    struct wirebuf                 *wb,
    const struct http_request_case *c,
    char                           *body,
    int                            *body_len)
{
    char line[128];

    *body_len = body_length(c->body);

    /* Assembled piecewise rather than through one snprintf: UriLong is longer
     * than any reasonable fixed buffer, and a truncated request line would
     * run into the header block and quietly test something else. */
    wb_str(wb, method_wire(c->method));
    wb_str(wb, " ");
    wb_str(wb, uri_wire(c->uri));
    wb_str(wb, " ");
    wb_str(wb, version_wire(c->ver));
    wb_str(wb, "\r\n");

    /* RFC 9112 section 3.2: "A client MUST send a Host header field in all
     * HTTP/1.1 request messages" -- including one whose request-target is
     * already in absolute-form.  Part of the framing rather than a header
     * class, the same way Content-Length is. */
    if (c->ver == HVER_V11) {
        wb_str(wb, "Host: ");
        wb_str(wb, g_host_value);
        wb_str(wb, "\r\n");
    }

    append_headers(wb, c->hdr);

    if (c->conn == HCONN_CONNKEEPALIVE) {
        wb_str(wb, "Connection: keep-alive\r\n");
    } else if (c->conn == HCONN_CONNCLOSE) {
        wb_str(wb, "Connection: close\r\n");
    }

    if (c->expect_cls == HEXP_EXPECTCONTINUE) {
        wb_str(wb, "Expect: 100-continue\r\n");
    }

    if (body_is_chunked(c->body)) {
        wb_str(wb, "Transfer-Encoding: chunked\r\n");
    } else if (c->body != HBDY_BODYNONE) {
        snprintf(line, sizeof(line), "Content-Length: %d\r\n", *body_len);
        wb_str(wb, line);
    }

    wb_str(wb, "\r\n");

    if (*body_len) {
        fill_body(body, *body_len);
    }

    if (body_is_chunked(c->body)) {
        append_chunked_body(wb, body, *body_len, c->body);
    } else if (*body_len) {
        wb_append(wb, body, *body_len);
    }
} /* build_request */

/* ------------------------------------------------------------------ *
* The raw client
* ------------------------------------------------------------------ */

static int
connect_raw(void)
{
    struct sockaddr_in addr;
    int                fd, one = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd < 0) {
        return -1;
    }

    setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port        = htons(port);

    if (connect(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0) {
        close(fd);
        return -1;
    }

    return fd;
} /* connect_raw */

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
            /* The server hung up mid-request.  That is an outcome in itself
             * for several defects, so it is not an error here: the classifier
             * downstream decides what it means. */
            return -1;
        }

        off += n;
    }

    return 0;
} /* write_all */

/*
 * Put the request on the wire the way the case says to.  The delivery mode is
 * a dimension of the model rather than an implementation detail: a parser
 * defect that is only detected because the whole request arrived in one read
 * is not really detected.
 *
 * Pipelined is the one that is a protocol claim rather than a fragmentation
 * choice -- the same request twice in a single write, which RFC 9112 section
 * 9.3.2 permits and requires the server to answer in order.
 */
static void
deliver(
    int             fd,
    struct wirebuf *wb,
    int             delivery)
{
    size_t half, i, dribble;

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
        case HDLV_PIPELINED:
            /* Both requests in one write, so that when the server's first
             * read returns, the second request is already buffered and no
             * further read event is coming to announce it. */
        {
            struct wirebuf both;

            wb_init(&both);
            wb_append(&both, wb->data, wb->len);
            wb_append(&both, wb->data, wb->len);
            write_all(fd, both.data, both.len);
            wb_free(&both);
        }
        break;
        default:
            write_all(fd, wb->data, wb->len);
            break;
    } /* switch */
} /* deliver */

/* ------------------------------------------------------------------ *
* The response reader
*
* A reader owns the socket buffer and a cursor, so a connection that carries
* more than one response -- a pipelined pair, or one reused for a second
* request -- is parsed as a sequence rather than as a single message.  That
* also makes the interim-response rule expressible: a 1xx is a complete
* message that is not the answer, so it is parsed, counted, and skipped.
* ------------------------------------------------------------------ */

#define MAX_RESPONSE  (2 * BODY_LARGE_LEN + 65536)
#define MAX_RSP_HDRS  64
#define MAX_RSP_NAME  128
#define MAX_RSP_VALUE 2048
#define MAX_RSP_BODY  (BODY_LARGE_LEN + 4096)

struct reader {
    int  fd;
    int  len;        /* bytes read from the socket so far   */
    int  pos;        /* where the next unparsed message starts */
    int  eof;
    char buf[MAX_RESPONSE];
};

struct rawrsp {
    int     have_status;
    int     status;
    char    version[16];
    char    reason[128];

    int     nhdr;
    struct {
        char name[MAX_RSP_NAME];
        char value[MAX_RSP_VALUE];
    } hdr[MAX_RSP_HDRS];

    int64_t content_length;   /* -1 when the response declares none */
    int     chunked;
    int     close_delimited;

    /* The decoded content, whichever framing carried it. */
    int     body_len;
    char    body[MAX_RSP_BODY];

    int     interim;          /* 1xx messages skipped before this one */
    int     eof;              /* the peer closed at or before this message */
    int     simple;           /* no status line at all */
};

static const char *
rsp_header(
    const struct rawrsp *r,
    const char          *name)
{
    int i;

    for (i = 0; i < r->nhdr; i++) {
        if (strcasecmp(r->hdr[i].name, name) == 0) {
            return r->hdr[i].value;
        }
    }

    return NULL;
} /* rsp_header */

static int
rsp_header_count(
    const struct rawrsp *r,
    const char          *name)
{
    int i, n = 0;

    for (i = 0; i < r->nhdr; i++) {
        if (strcasecmp(r->hdr[i].name, name) == 0) {
            n++;
        }
    }

    return n;
} /* rsp_header_count */

/* The next CRLF at or after `p`, or NULL.  Spelled out rather than reached
 * for through memmem(), which is a GNU extension libevpl does not otherwise
 * depend on. */
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

static void
copy_field(
    char       *dst,
    size_t      cap,
    const char *src,
    size_t      len)
{
    if (len > cap - 1) {
        len = cap - 1;
    }

    memcpy(dst, src, len);
    dst[len] = '\0';
} /* copy_field */

static void
body_append(
    struct rawrsp *r,
    const char    *src,
    int            len)
{
    if (r->body_len + len > MAX_RSP_BODY) {
        len = MAX_RSP_BODY - r->body_len;
    }

    if (len > 0) {
        memcpy(r->body + r->body_len, src, len);
        r->body_len += len;
    }
} /* body_append */

/*
 * Parse one message beginning at rd->buf[start].
 *
 * Returns the offset just past the message, or -1 if it has not fully arrived
 * yet, or -2 if the bytes are not a status line at all.  Nothing is consumed:
 * the caller advances the cursor, so a partial parse costs only the work of
 * redoing it when more bytes turn up.
 */
static int
parse_message(
    const struct reader *rd,
    struct rawrsp       *r,
    int                  start,
    int                  expect_body_absent)
{
    const char *base = rd->buf;
    const char *end  = rd->buf + rd->len;
    const char *line, *eol, *sp1, *sp2, *colon, *value, *vend;
    const char *cl;
    int         hdr_end, no_body, chunk;
    char        size[64];

    memset(r, 0, sizeof(*r));

    r->content_length = -1;

    if (rd->len - start < 5) {
        return rd->eof ? -2 : -1;
    }

    if (memcmp(base + start, "HTTP/", 5) != 0) {
        /* A Simple-Response, which has no status line and no headers at all:
         * every byte is content, and it ends with the connection. */
        r->simple = 1;
        body_append(r, base + start, rd->len - start);
        return rd->eof ? rd->len : -1;
    }

    line = base + start;
    eol  = find_crlf(line, end);

    if (!eol) {
        return -1;
    }

    sp1 = memchr(line, ' ', eol - line);

    if (!sp1) {
        /* A status line with only one token.  Recorded in `version` so the
         * classifier can tell it from having received nothing at all. */
        copy_field(r->version, sizeof(r->version), line, eol - line);
        return -2;
    }

    copy_field(r->version, sizeof(r->version), line, sp1 - line);

    sp2 = memchr(sp1 + 1, ' ', eol - (sp1 + 1));

    r->status      = atoi(sp1 + 1);
    r->have_status = r->status >= 100 && r->status <= 599;

    if (sp2) {
        copy_field(r->reason, sizeof(r->reason), sp2 + 1, eol - (sp2 + 1));
    }

    line = eol + 2;

    for (;;) {
        if (line >= end) {
            return -1;
        }

        eol = find_crlf(line, end);

        if (!eol) {
            return -1;
        }

        if (eol == line) {
            line += 2;
            break;
        }

        colon = memchr(line, ':', eol - line);

        if (colon && r->nhdr < MAX_RSP_HDRS) {
            value = colon + 1;

            while (value < eol && (*value == ' ' || *value == '\t')) {
                value++;
            }

            vend = eol;

            while (vend > value && (*(vend - 1) == ' ' || *(vend - 1) == '\t')) {
                vend--;
            }

            copy_field(r->hdr[r->nhdr].name, MAX_RSP_NAME, line, colon - line);
            copy_field(r->hdr[r->nhdr].value, MAX_RSP_VALUE, value,
                       vend - value);
            r->nhdr++;
        }

        line = eol + 2;
    }

    hdr_end = (int) (line - base);

    cl = rsp_header(r, "Content-Length");

    r->content_length = cl ? strtoll(cl, NULL, 10) : -1;

    cl = rsp_header(r, "Transfer-Encoding");

    r->chunked = cl && strcasecmp(cl, "chunked") == 0;

    /* RFC 9112 section 6.3: a 1xx, 204 or 304 response, and any response to a
     * HEAD request, "is always terminated by the first empty line after the
     * header fields, regardless of the header fields present in the
     * message". */
    no_body = expect_body_absent || r->status / 100 == 1 || r->status == 204 ||
        r->status == 304;

    if (no_body) {
        return hdr_end;
    }

    if (r->chunked) {
        int p = hdr_end;

        for (;;) {
            eol = find_crlf(base + p, end);

            if (!eol) {
                return -1;
            }

            copy_field(size, sizeof(size), base + p, eol - (base + p));

            chunk = (int) strtol(size, NULL, 16);

            p = (int) (eol + 2 - base);

            if (chunk == 0) {
                break;
            }

            if (rd->len - p < chunk + 2) {
                return -1;
            }

            body_append(r, base + p, chunk);
            p += chunk + 2;
        }

        /* The trailer section, then the CRLF that ends the coding: zero or
         * more field lines followed by an empty one. */
        for (;;) {
            eol = find_crlf(base + p, end);

            if (!eol) {
                return -1;
            }

            if (eol == base + p) {
                p += 2;
                break;
            }

            p = (int) (eol + 2 - base);
        }

        return p;
    }

    if (r->content_length >= 0) {
        if (rd->len - hdr_end < r->content_length) {
            /* A truncated body is only final once the peer has closed. */
            if (!rd->eof) {
                return -1;
            }

            body_append(r, base + hdr_end, rd->len - hdr_end);
            return rd->len;
        }

        body_append(r, base + hdr_end, (int) r->content_length);
        return hdr_end + (int) r->content_length;
    }

    /* Neither a length nor a coding: the content runs to the close. */
    r->close_delimited = 1;

    if (!rd->eof) {
        return -1;
    }

    body_append(r, base + hdr_end, rd->len - hdr_end);

    return rd->len;
} /* parse_message */

static int64_t
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
} /* now_ms */

/*
 * Read once into the reader's buffer, waiting at most `timeout`.  Returns 1 if
 * bytes arrived, 0 on timeout, -1 on close or error.
 */
static int
rd_fill(
    struct reader *rd,
    int            timeout)
{
    struct pollfd pfd;
    int           n;

    if (rd->eof || rd->len == MAX_RESPONSE) {
        return -1;
    }

    pfd.fd      = rd->fd;
    pfd.events  = POLLIN;
    pfd.revents = 0;

    if (timeout < 0) {
        timeout = 0;
    }

    n = poll(&pfd, 1, timeout);

    if (n < 0) {
        return errno == EINTR ? 0 : -1;
    }

    if (n == 0) {
        return 0;
    }

    n = read(rd->fd, rd->buf + rd->len, MAX_RESPONSE - rd->len);

    if (n < 0) {
        if (errno == EINTR) {
            return 0;
        }

        /* A reset is a close: a server that hangs up on a request the client
         * is still dribbling out will reset the rest of it, and the read fails
         * rather than returning EOF.  Recording that as a stall would say the
         * server held the connection when it did the opposite, and would make
         * the same defect classify differently depending only on how the
         * request was delivered. */
        if (errno == ECONNRESET) {
            rd->eof = 1;
        }

        return -1;
    }

    if (n == 0) {
        rd->eof = 1;
        return -1;
    }

    rd->len += n;

    return 1;
} /* rd_fill */

/*
 * Read the next response off the connection.
 *
 * With `skip_interim` set, 1xx messages are parsed, counted into r->interim
 * and skipped: RFC 9110 section 15.2 makes them interim by definition -- "A
 * client MUST be able to parse one or more 1xx responses received prior to a
 * final response" -- so the answer is whatever follows them, and whether one
 * was allowed to be there at all is a separate check.  The status phase clears
 * it, because there the 1xx IS the message under examination and nothing
 * further is coming.
 *
 * `expect_body_absent` is the HEAD case: the response declares a length but
 * must not carry the bytes, so the reader spends a short grace proving none
 * arrive rather than blocking on a body that is required to be missing.
 */
static void
read_response(
    struct reader *rd,
    struct rawrsp *r,
    int            expect_body_absent,
    int            skip_interim)
{
    int64_t deadline = now_ms() + RESPONSE_TIMEOUT_MS;
    int     interim  = 0;
    int     msg_end, avail, n;

    for (;;) {
        msg_end = parse_message(rd, r, rd->pos, expect_body_absent);

        if (msg_end == -2) {
            r->interim = interim;
            r->eof     = rd->eof;
            return;
        }

        if (msg_end >= 0) {
            if (skip_interim && r->have_status && r->status / 100 == 1) {
                /* An interim response.  Skip it and keep reading for the
                 * answer, which is what a 1xx says is still coming. */
                interim++;
                rd->pos = msg_end;
                continue;
            }

            rd->pos    = msg_end;
            r->interim = interim;
            r->eof     = rd->eof;

            if (expect_body_absent) {
                /* Prove the body really is absent rather than merely late. */
                int64_t grace = now_ms() + NOBODY_GRACE_MS;

                while (now_ms() < grace && rd->len == msg_end) {
                    if (rd_fill(rd, (int) (grace - now_ms())) < 0) {
                        break;
                    }
                }

                avail = rd->len - msg_end;

                /* Anything that follows is only a body if it is not the next
                 * response: a pipelined pair puts the second status line
                 * exactly where a forbidden body would be, and counting that
                 * as content would fail the HEAD rule for obeying it. */
                n = avail < 5 ? avail : 5;

                if (avail > 0 && memcmp(rd->buf + msg_end, "HTTP/", n) != 0) {
                    body_append(r, rd->buf + msg_end, avail);
                }
            }

            return;
        }

        if (now_ms() >= deadline || rd_fill(rd, (int) (deadline - now_ms())) < 0) {
            /* Out of time, or the peer closed.  Parse one last time: a close
             * is the delimiter for a close-delimited body and for a truncated
             * one, so the final read can complete a message. */
            msg_end = parse_message(rd, r, rd->pos, expect_body_absent);

            if (msg_end >= 0) {
                rd->pos = msg_end;
            }

            r->interim = interim;
            r->eof     = rd->eof;
            return;
        }
    }
} /* read_response */

/*
 * Whether the connection is still there after a response.
 *
 * Costs a wait either way: a close that has not arrived yet is
 * indistinguishable from one that never will until the deadline passes.
 */
static int
connection_closed(
    struct reader *rd,
    int            timeout)
{
    int64_t deadline = now_ms() + timeout;

    while (!rd->eof && now_ms() < deadline) {
        if (rd_fill(rd, (int) (deadline - now_ms())) <= 0) {
            break;
        }
    }

    return rd->eof;
} /* connection_closed */

static int
classify(const struct rawrsp *r)
{
    if (r->simple) {
        return ACT_SIMPLE;
    }

    if (!r->have_status) {
        if (r->version[0] == '\0' && r->nhdr == 0 && r->body_len == 0) {
            return r->eof ? ACT_NORESPONSE : ACT_STALLED;
        }

        return ACT_MALFORMED;
    }

    return r->status;
} /* classify */

/*
 * Checks that sit outside the model, applied to every response that has a
 * status line at all.  None of them is a property of a particular case -- they
 * are what makes any response to an HTTP/1.x request a well-formed one -- so
 * holding them here rather than bending them into the case table keeps the
 * model about what the request means.
 */
static void
check_framing(
    int                  phase,
    int                  subject,
    int                  ver,
    const struct rawrsp *r)
{
    char detail[256];
    int  actual = classify(r);

    if (actual == ACT_NORESPONSE || actual == ACT_STALLED ||
        actual == ACT_SIMPLE || actual == ACT_MALFORMED) {
        /* No status line to check the shape of; whether there should have
         * been one is the status aspect's business, not this one's. */
        return;
    }

    if (strcmp(r->version, "HTTP/1.0") != 0 &&
        strcmp(r->version, "HTTP/1.1") != 0) {
        snprintf(detail, sizeof(detail),
                 "status line version '%s' is neither HTTP/1.0 nor HTTP/1.1",
                 r->version);
        record(phase, ASPECT_FRAMING, subject, VACT_OK, VACT_BAD, 0, detail);
        return;
    }

    if (r->reason[0] == '\0') {
        record(phase, ASPECT_FRAMING, subject, VACT_OK, VACT_BAD, 0,
               "status line carries no reason phrase");
        return;
    }

    /* RFC 9112 section 6.1: "A server MUST NOT send a response containing
     * Transfer-Encoding unless the corresponding request indicates HTTP/1.1
     * (or later)."  An HTTP/1.0 client has no way to delimit a body framed
     * with a coding its version does not have, so this is a response the peer
     * cannot read. */
    if (r->chunked && ver != HVER_V11) {
        record(phase, ASPECT_FRAMING, subject, VACT_OK, VACT_BAD, 0,
               "chunked response to an HTTP/1.0 request");
        return;
    }

    /* RFC 9110 section 8.6: "A sender MUST NOT send a Content-Length header
     * field in any message that contains a Transfer-Encoding header field."
     * Two framings that disagree is the response-splitting primitive, and it
     * is the same defect the server refuses on the way in. */
    if (r->chunked && rsp_header(r, "Content-Length")) {
        record(phase, ASPECT_FRAMING, subject, VACT_OK, VACT_BAD, 0,
               "both Content-Length and Transfer-Encoding on one response");
        return;
    }

    /* Section 8.6 again: "A server MUST NOT send a Content-Length header field
     * in any response with a status code of 1xx (Informational) or 204 (No
     * Content)."  These carry no content by definition, so a length is
     * describing something that is not there. */
    if ((r->status / 100 == 1 || r->status == 204) &&
        rsp_header(r, "Content-Length")) {
        snprintf(detail, sizeof(detail),
                 "Content-Length on a %d response", r->status);
        record(phase, ASPECT_FRAMING, subject, VACT_OK, VACT_BAD, 0, detail);
        return;
    }

    if ((r->status / 100 == 1 || r->status == 204) && r->chunked) {
        snprintf(detail, sizeof(detail),
                 "Transfer-Encoding on a %d response", r->status);
        record(phase, ASPECT_FRAMING, subject, VACT_OK, VACT_BAD, 0, detail);
        return;
    }

    /* RFC 9110 section 6.6.1: "An origin server MUST send a Date header field
     * in all [2xx, 3xx and 4xx] cases" -- it is optional only for 1xx and 5xx,
     * and forbidden only to a server with no clock.  Everything downstream
     * that reasons about the age of a response starts from it, so a response
     * without one cannot be cached, revalidated or have its freshness
     * computed at all. */
    if (r->status >= 200 && r->status < 500 &&
        rsp_header(r, "Date") == NULL) {
        snprintf(detail, sizeof(detail), "no Date header on a %d response",
                 r->status);
        record(phase, ASPECT_FRAMING, subject, VACT_OK, VACT_BAD, 0, detail);
        return;
    }

    /* And exactly one.  RFC 9110 section 5.3 forbids two field lines with the
     * same name unless the field is a comma-separated list, which Date is not
     * -- so a library that adds its own on top of an application's has made
     * the message malformed rather than complete. */
    if (rsp_header_count(r, "Date") > 1) {
        record(phase, ASPECT_FRAMING, subject, VACT_OK, VACT_BAD, 0,
               "more than one Date header on one response");
        return;
    }

    record(phase, ASPECT_FRAMING, subject, VACT_OK, VACT_OK, 1, NULL);
} /* check_framing */

/* ------------------------------------------------------------------ *
* Phase 1: the positive matrix
* ------------------------------------------------------------------ */

/*
 * Whether this case pays for the waits that prove the connection's fate.
 *
 * Whether the server CLOSES depends on the request's version and its
 * Connection header and on nothing else, so it is sampled per (version,
 * method, connection) triple rather than on all eleven hundred cases -- at a
 * quarter of a second each, doing it everywhere would dominate the run.
 *
 * Whether a connection the server KEPT can carry another request depends on
 * something else entirely: whether the parser consumed exactly the bytes of
 * the request it just answered.  Anything left behind -- an unconsumed trailer
 * section, a miscounted chunk -- is read as the start of the next request, so
 * that sample is keyed on the body framing instead.  It is the only check here
 * that can see the difference.
 */
static int g_persist_checked[2][5][3];
static int g_reuse_checked[2][9];

static void
check_probe(
    const struct http_request_case *c,
    const struct rawrsp            *r)
{
    const char *echo  = rsp_header(r, ECHO_PROBE);
    const char *count = rsp_header(r, ECHO_PROBE_COUNT);
    char        want[256];
    char        detail[512];
    int         ok, n;

    if (!echo || !count) {
        snprintf(detail, sizeof(detail), "the response carried no %s",
                 echo ? ECHO_PROBE_COUNT : ECHO_PROBE);
        record(PHASE_REQUEST, ASPECT_PROBE, c->hdr, c->expect_probe,
               HPROBE_PROBEABSENT, 0, detail);
        return;
    }

    n = atoi(count);

    switch (c->expect_probe) {
        case HPROBE_PROBEABSENT:
            ok = strcmp(echo, ECHO_ABSENT) == 0 && n == 0;
            break;
        case HPROBE_PROBEVALUE:
            snprintf(want, sizeof(want), "[%s]", PROBE_VALUE);
            ok = strcmp(echo, want) == 0 && n == 1;
            break;
        case HPROBE_PROBEEMPTY:
            ok = strcmp(echo, "[]") == 0 && n == 1;
            break;
        case HPROBE_PROBETWICE:
            ok = n == 2;
            break;
        case HPROBE_PROBEANY:
            ok = strcmp(echo, ECHO_ABSENT) != 0 && strcmp(echo, "[]") != 0 &&
                n == 1;
            break;
        default:
            ok = 0;
            break;
    } /* switch */

    snprintf(detail, sizeof(detail), "%s reflected as '%s' x%d",
             http_hdr_name(c->hdr), echo, n);

    record(PHASE_REQUEST, ASPECT_PROBE, c->hdr, c->expect_probe,
           ok ? c->expect_probe : HPROBE_PROBEANY, ok, ok ? NULL : detail);
} /* check_probe */

/*
 * Check everything about one response that the case predicts.  Split out from
 * run_request_case because a pipelined case has two of them to check, and the
 * second is checked against exactly the same prediction as the first: two
 * identical requests must draw two identical answers, in order.
 */
static void
check_response(
    const struct http_request_case *c,
    const struct rawrsp            *r,
    const char                     *body,
    int                             body_len,
    int                             which)
{
    char        detail[512];
    const char *echo;
    int         actual = classify(r);
    int         ok;

    snprintf(detail, sizeof(detail), "%s %s %s, %s, %s, %s, %s%s",
             http_version_name(c->ver), http_method_name(c->method),
             http_uri_name(c->uri), http_hdr_name(c->hdr),
             http_body_name(c->body), http_conn_name(c->conn),
             http_delivery_name(c->delivery),
             which ? " (second of a pipelined pair)" : "");

    ok = actual == c->expect_status;

    record(PHASE_REQUEST, ASPECT_STATUS, c->hdr, c->expect_status, actual, ok,
           ok ? NULL : detail);

    if (!ok) {
        /* Nothing downstream of the status means anything if the request was
         * not served: there is no echo to compare and no body to check. */
        return;
    }

    check_framing(PHASE_REQUEST, c->ver, c->ver, r);

    /* RFC 9110 section 10.1.1: an HTTP/1.0 request's 100-continue expectation
     * MUST be ignored, so a 1xx before the answer is a message the client
     * cannot tell from the answer itself. */
    ok = c->expect_interim == HINTERIM_INTERIMALLOWED || r->interim == 0;

    snprintf(detail, sizeof(detail),
             "%d interim response(s) before the answer to a %s request",
             r->interim, http_version_name(c->ver));

    record(PHASE_REQUEST, ASPECT_INTERIM, c->ver, VACT_OK,
           ok ? VACT_OK : VACT_BAD, ok, ok ? NULL : detail);

    /* What the server understood. */
    echo = rsp_header(r, ECHO_METHOD);
    ok   = echo && strcmp(echo, method_echoed(c->method)) == 0;

    snprintf(detail, sizeof(detail), "method reflected as '%s', wanted '%s'",
             echo ? echo : "(absent)", method_echoed(c->method));

    record(PHASE_REQUEST, ASPECT_ECHO_METHOD, c->method, VACT_OK,
           ok ? VACT_OK : VACT_BAD, ok, ok ? NULL : detail);

    echo = rsp_header(r, ECHO_URI);
    ok   = echo && strcmp(echo, uri_wire(c->uri)) == 0;

    snprintf(detail, sizeof(detail), "uri reflected as '%.64s', wanted '%.64s'",
             echo ? echo : "(absent)", uri_wire(c->uri));

    record(PHASE_REQUEST, ASPECT_ECHO_URI, c->uri, VACT_OK,
           ok ? VACT_OK : VACT_BAD, ok, ok ? NULL : detail);

    check_probe(c, r);

    /* The body. */
    if (c->expect_body == HBODY_BODYABSENT) {
        ok = r->body_len == 0;

        snprintf(detail, sizeof(detail),
                 "%d body bytes returned for a HEAD request", r->body_len);

        record(PHASE_REQUEST, ASPECT_BODY, c->method, HBODY_BODYABSENT,
               ok ? HBODY_BODYABSENT : HBODY_BODYECHOED, ok,
               ok ? NULL : detail);
    } else {
        ok = r->body_len == body_len &&
            (body_len == 0 || memcmp(r->body, body, body_len) == 0);

        snprintf(detail, sizeof(detail),
                 "%d body bytes returned, sent %d", r->body_len, body_len);

        record(PHASE_REQUEST, ASPECT_BODY, c->method, HBODY_BODYECHOED,
               ok ? HBODY_BODYECHOED : HBODY_BODYANY, ok, ok ? NULL : detail);
    }

    /* An HTTP/1.0 server may only say keep-alive to a client that asked. */
    if (c->ver == HVER_V10 && c->conn == HCONN_CONNDEFAULT) {
        echo = rsp_header(r, "Connection");
        ok   = !(echo && strcasecmp(echo, "keep-alive") == 0);

        record(PHASE_REQUEST, ASPECT_KEEPALIVE, c->conn, VACT_OK,
               ok ? VACT_OK : VACT_BAD, ok, ok ? NULL :
               "unsolicited 'Connection: keep-alive' on an HTTP/1.0 response");
    }
} /* check_response */

/*
 * The MustPersist obligation, which is two things at once (RFC 9112 section
 * 9.6): a server that is going to close MUST say so, and one that did not say
 * so has left a connection another request can be sent on.  Checking only the
 * first would let a server satisfy HTTP/1.1 by announcing a close on every
 * response, which is HTTP/1.0 with extra words; checking only the second would
 * fail a server that is entitled to close and said so.
 */
static void
check_reuse(
    struct reader                  *rd,
    const struct http_request_case *c,
    struct wirebuf                 *wb,
    const char                     *body,
    int                             body_len)
{
    struct rawrsp r;
    char          detail[256];
    int           ok, actual;

    /* The caller has already established that the response did not announce a
     * close, so the connection has to still be there.  Proving that costs a
     * wait either way: a close that has not arrived yet is indistinguishable
     * from one that never will until the grace passes. */
    if (connection_closed(rd, PERSIST_GRACE_MS)) {
        record(PHASE_REQUEST, ASPECT_REUSE, c->conn, VACT_OK, VACT_BAD, 0,
               "the connection was closed after an HTTP/1.1 response that "
               "did not announce a close");
        return;
    }

    deliver(rd->fd, wb, HDLV_ONEWRITE);

    read_response(rd, &r, c->expect_body == HBODY_BODYABSENT, 1);

    actual = classify(&r);
    ok     = actual == c->expect_status;

    snprintf(detail, sizeof(detail),
             "second request on the same connection answered %s",
             ok ? "correctly" : outcome_name(actual));

    record(PHASE_REQUEST, ASPECT_REUSE, c->conn, VACT_OK,
           ok ? VACT_OK : VACT_BAD, ok, ok ? NULL : detail);

    if (ok) {
        check_response(c, &r, body, body_len, 0);
    }
} /* check_reuse */

static void
run_request_case(const struct http_request_case *c)
{
    struct wirebuf wb;
    struct reader *rd;
    struct rawrsp  r;
    static char    body[BODY_LARGE_LEN];
    char           detail[256];
    const char    *conn_hdr;
    int            body_len, want_persist, ok, actual;

    rd = calloc(1, sizeof(*rd));

    if (!rd) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }

    rd->fd = connect_raw();

    if (rd->fd < 0) {
        fprintf(stderr, "request case: connect failed: %s\n", strerror(errno));
        g_results.unexpected++;
        free(rd);
        return;
    }

    g_results.request_run++;

    wb_init(&wb);
    build_request(&wb, c, body, &body_len);

    want_persist                                  = !g_persist_checked[c->ver][c->method][c->conn];
    g_persist_checked[c->ver][c->method][c->conn] = 1;

    if (c->expect_persist == HPERSIST_MUSTPERSIST &&
        !g_reuse_checked[c->ver][c->body]) {
        g_reuse_checked[c->ver][c->body] = 1;
        want_persist                     = 1;
    }

    deliver(rd->fd, &wb, c->delivery);

    read_response(rd, &r, c->expect_body == HBODY_BODYABSENT, 1);

    check_response(c, &r, body, body_len, 0);

    actual = classify(&r);

    if (actual != c->expect_status) {
        goto out;
    }

    conn_hdr = rsp_header(&r, "Connection");

    /* The second half of a pipelined pair.  RFC 9112 section 9.3.2: "A server
     * MUST send its responses to those requests in the same order that the
     * requests were received" -- and, before ordering can mean anything, it
     * has to send them at all.  A server that stops parsing when one request
     * is complete never sees the second, because the read event that carried
     * it has already been delivered. */
    if (c->delivery == HDLV_PIPELINED) {
        struct rawrsp r2;

        read_response(rd, &r2, c->expect_body == HBODY_BODYABSENT, 1);

        actual = classify(&r2);
        ok     = actual == c->expect_status;

        snprintf(detail, sizeof(detail),
                 "the second of two pipelined requests was answered %s",
                 outcome_name(actual));

        record(PHASE_REQUEST, ASPECT_PIPELINE, c->ver, VACT_OK,
               ok ? VACT_OK : VACT_BAD, ok, ok ? NULL : detail);

        if (ok) {
            check_response(c, &r2, body, body_len, 1);
        }

        goto out;
    }

    if (!want_persist) {
        goto out;
    }

    switch (c->expect_persist) {
        case HPERSIST_MUSTCLOSE:
            ok = connection_closed(rd, CLOSE_TIMEOUT_MS);

            record(PHASE_REQUEST, ASPECT_PERSIST, c->conn, PACT_CLOSED,
                   ok ? PACT_CLOSED : PACT_OPEN, ok, ok ? NULL :
                   "the connection was still open after the response");
            break;

        case HPERSIST_MAYPERSIST:
            /* An HTTP/1.0 server that holds the connection has to have said
             * so; one that closes is within its rights either way. */
            ok = connection_closed(rd, CLOSE_TIMEOUT_MS) ||
                (conn_hdr && strcasecmp(conn_hdr, "keep-alive") == 0);

            record(PHASE_REQUEST, ASPECT_PERSIST, c->conn, PACT_CLOSED,
                   rd->eof ? PACT_CLOSED : PACT_OPEN, ok, ok ? NULL :
                   "the connection was held open without a Keep-Alive "
                   "acknowledgement");
            break;

        default:
            if (conn_hdr && strcasecmp(conn_hdr, "close") == 0) {
                /* The escape hatch, taken: the server said it was closing, so
                 * all that is left to check is that it did. */
                ok = connection_closed(rd, CLOSE_TIMEOUT_MS);

                record(PHASE_REQUEST, ASPECT_PERSIST, c->conn, PACT_CLOSED,
                       ok ? PACT_CLOSED : PACT_OPEN, ok, ok ? NULL :
                       "the response announced a close that did not happen");
            } else {
                check_reuse(rd, c, &wb, body, body_len);
            }
            break;
    } /* switch */

 out:
    wb_free(&wb);
    close(rd->fd);
    free(rd);
} /* run_request_case */

static void
run_request_phase(void)
{
    unsigned int i;

    for (i = 0; i < HTTP_NUM_REQUEST_CASES; i++) {
        run_request_case(&http_request_cases[i]);
    }
} /* run_request_phase */

/* ------------------------------------------------------------------ *
* Phase 2: the defect taxonomy
* ------------------------------------------------------------------ */

/*
 * Build one malformed request.  Sets *half_close when the defect is the
 * absence of the rest of the request: those cases have to stop sending and
 * say so, because "the client has not finished yet" and "the client will
 * never finish" are different situations and only one of them permits the
 * server to answer nothing.
 *
 * `ver` is the version the defect is being tested at, which for most of them
 * only changes the request line -- but for HostMissing and
 * PostWithoutContentLength it is the whole of what is under test.
 */
static void
build_defect(
    struct wirebuf *wb,
    int             defect,
    int             ver,
    int            *half_close)
{
    char        line[256];
    const char *v = version_wire(ver);
    int         i;

    *half_close = 0;

    /* Every defect that is not about the request line or the Host header
     * starts from a well-formed one at the version under test. */
#define REQ_LINE(method, uri)              \
        do {                               \
            wb_str(wb, method " " uri " "); \
            wb_str(wb, v);                 \
            wb_str(wb, "\r\n");            \
            if (ver == HVER_V11) {         \
                wb_str(wb, "Host: ");      \
                wb_str(wb, g_host_value);  \
                wb_str(wb, "\r\n");        \
            }                              \
        } while (0)

    switch (defect) {
        case HDEF_NODEFECT:
            REQ_LINE("GET", URI_PATH);
            wb_str(wb, PROBE_NAME ": " PROBE_VALUE "\r\n\r\n");
            break;

        case HDEF_METHODUNKNOWN:
            REQ_LINE("FROB", URI_PATH);
            wb_str(wb, "\r\n");
            break;

        case HDEF_METHODLOWERCASE:
            REQ_LINE("get", URI_PATH);
            wb_str(wb, "\r\n");
            break;

        case HDEF_METHODEMPTY:
            REQ_LINE("", URI_PATH);
            wb_str(wb, "\r\n");
            break;

        case HDEF_REQUESTLINEONETOKEN:
            wb_str(wb, "GET\r\n\r\n");
            break;

        case HDEF_REQUESTLINEEXTRATOKEN:
            wb_str(wb, "GET " URI_PATH " ");
            wb_str(wb, v);
            wb_str(wb, " trailing\r\n\r\n");
            break;

        case HDEF_REQUESTLINENOVERSION:
            /* An HTTP/0.9 Simple-Request: the request line alone, with no
             * version and therefore no header block to terminate. */
            wb_str(wb, "GET " URI_PATH "\r\n");
            break;

        case HDEF_LEADINGCRLFBEFOREREQUESTLINE:
            /* The stray CRLF a buggy client leaves after a previous body.
             * RFC 9112 section 2.2 asks a server to skip at least one. */
            wb_str(wb, "\r\n");
            REQ_LINE("GET", URI_PATH);
            wb_str(wb, "\r\n");
            break;

        case HDEF_VERSIONMALFORMED:
            wb_str(wb, "GET " URI_PATH " HTTP/1\r\n\r\n");
            break;

        case HDEF_VERSIONMAJORUNSUPPORTED:
            wb_str(wb, "GET " URI_PATH " HTTP/2.0\r\n\r\n");
            break;

        case HDEF_VERSIONMINORUNKNOWN:
            wb_str(wb, "GET " URI_PATH " HTTP/1.9\r\n"
                   "Host: ");
            wb_str(wb, g_host_value);
            wb_str(wb, "\r\n\r\n");
            break;

        case HDEF_URITOOLONG:
            wb_str(wb, "GET /");
            wb_fill(wb, 'a', MAX_HEADER_LINE * 2);
            wb_str(wb, " ");
            wb_str(wb, v);
            wb_str(wb, "\r\n\r\n");
            break;

        case HDEF_HEADERNOCOLON:
            REQ_LINE("GET", URI_PATH);
            wb_str(wb, "ThisIsNotAHeaderField\r\n\r\n");
            break;

        case HDEF_HEADERNAMEEMPTY:
            REQ_LINE("GET", URI_PATH);
            wb_str(wb, ": value\r\n\r\n");
            break;

        case HDEF_HEADERSPACEBEFORECOLON:
            REQ_LINE("GET", URI_PATH);
            wb_str(wb, PROBE_NAME " : " PROBE_VALUE "\r\n\r\n");
            break;

        case HDEF_HEADERLINEOVERLONG:
            /* One field longer than the parser's line buffer, but a block
             * that would otherwise be well inside max_header_size: the line
             * is what overflows, not the block. */
            REQ_LINE("GET", URI_PATH);
            wb_str(wb, "X-Long: ");
            wb_fill(wb, 'a', MAX_HEADER_LINE + 64);
            wb_str(wb, "\r\n\r\n");
            break;

        case HDEF_HEADERBLOCKOVERLONG:
            /* The mirror image: every line is comfortably short, and it is
             * their total that passes max_header_size. */
            REQ_LINE("GET", URI_PATH);

            for (i = 0; i * 128 < MAX_HEADER_SIZE + 512; i++) {
                snprintf(line, sizeof(line), "X-Fill-%03d: ", i);
                wb_str(wb, line);
                wb_fill(wb, 'a', 128 - (int) strlen(line) - 2);
                wb_str(wb, "\r\n");
            }

            wb_str(wb, "\r\n");
            break;

        case HDEF_HEADERFOLDEDFIRST:
            /* The fold is the FIRST line of the block, so there is no field
             * for it to continue.  Not through REQ_LINE, because the Host it
             * adds would be the field above and this would be an ordinary
             * fold; the Host goes after instead, so the only defect is the
             * one under test. */
            wb_str(wb, "GET " URI_PATH " ");
            wb_str(wb, v);
            wb_str(wb, "\r\n\tcontinuation-of-nothing\r\n");

            if (ver == HVER_V11) {
                wb_str(wb, "Host: ");
                wb_str(wb, g_host_value);
                wb_str(wb, "\r\n");
            }

            wb_str(wb, "\r\n");
            break;

        case HDEF_LEADINGCRLFFLOOD:
            /* The robustness rule asked to run forever.  More empty lines than
             * the header budget can hold, then a request that would otherwise
             * be served. */
            for (i = 0; i * 2 < MAX_HEADER_SIZE + 512; i++) {
                wb_str(wb, "\r\n");
            }

            REQ_LINE("GET", URI_PATH);
            wb_str(wb, "\r\n");
            break;

        case HDEF_HEADERBLOCKUNTERMINATED:
            REQ_LINE("GET", URI_PATH);
            wb_str(wb, PROBE_NAME ": " PROBE_VALUE "\r\n");
            *half_close = 1;
            break;

        case HDEF_HOSTMISSING:
            /* Deliberately NOT through REQ_LINE: the absence of the Host is
             * the defect, and at HTTP/1.0 the same bytes are a perfectly good
             * request. */
            wb_str(wb, "GET " URI_PATH " ");
            wb_str(wb, v);
            wb_str(wb, "\r\n" PROBE_NAME ": " PROBE_VALUE "\r\n\r\n");
            break;

        case HDEF_HOSTDUPLICATE:
            wb_str(wb, "GET " URI_PATH " ");
            wb_str(wb, v);
            wb_str(wb, "\r\nHost: ");
            wb_str(wb, g_host_value);
            wb_str(wb, "\r\nHost: elsewhere.invalid\r\n\r\n");
            break;

        case HDEF_BARELFLINEENDINGS:
            wb_str(wb, "GET " URI_PATH " ");
            wb_str(wb, v);
            wb_str(wb, "\n");

            if (ver == HVER_V11) {
                wb_str(wb, "Host: ");
                wb_str(wb, g_host_value);
                wb_str(wb, "\n");
            }

            wb_str(wb, PROBE_NAME ": " PROBE_VALUE "\n\n");
            break;

        case HDEF_CONTENTLENGTHNOTNUMERIC:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Content-Length: not-a-number\r\n\r\n");
            break;

        case HDEF_CONTENTLENGTHNEGATIVE:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Content-Length: -1\r\n\r\n");
            break;

        case HDEF_CONTENTLENGTHDUPLICATECONFLICTING:
            /* Two lengths, and the body is as long as the first: a server
             * that takes the second waits forever, one that takes the first
             * leaves three bytes to be read as the next request. */
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Content-Length: 5\r\n"
                   "Content-Length: 8\r\n\r\nabcde");
            break;

        case HDEF_CONTENTLENGTHTRAILINGJUNK:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Content-Length: 5x\r\n\r\nabcde");
            break;

        case HDEF_CONTENTLENGTHOVERFLOW:
            /* Twenty-three digits: a decimal numeral no 64-bit counter can
             * hold, which is exactly what RFC 9110 section 8.6 asks a
             * recipient to anticipate. */
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Content-Length: 99999999999999999999999\r\n\r\n");
            break;

        case HDEF_BODYSHORTOFCONTENTLENGTH:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Content-Length: 32\r\n\r\nshort");
            *half_close = 1;
            break;

        case HDEF_POSTWITHOUTCONTENTLENGTH:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, PROBE_NAME ": " PROBE_VALUE "\r\n\r\n");
            break;

        case HDEF_TRANSFERENCODINGWITHCONTENTLENGTH:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Content-Length: 5\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n"
                   "5\r\nabcde\r\n0\r\n\r\n");
            break;

        case HDEF_TRANSFERENCODINGCHUNKEDNOTFINAL:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Transfer-Encoding: chunked, gzip\r\n\r\n"
                   "5\r\nabcde\r\n0\r\n\r\n");
            break;

        case HDEF_TRANSFERENCODINGUNKNOWNCODING:
            /* Spaced either side of the comma, since RFC 9110 section 5.6.1
             * allows optional whitespace around a list element and a parser
             * that keeps it compares "gzip " against "gzip". */
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Transfer-Encoding: gzip , chunked\r\n\r\n"
                   "5\r\nabcde\r\n0\r\n\r\n");
            break;

        case HDEF_TRANSFERENCODINGONHTTP10:
            /* A coding HTTP/1.0 does not have, on a request that claims
             * HTTP/1.0: the two ends cannot agree on where it ends. */
            wb_str(wb, "POST " URI_PATH " HTTP/1.0\r\n"
                   "Transfer-Encoding: chunked\r\n\r\n"
                   "5\r\nabcde\r\n0\r\n\r\n");
            break;

        case HDEF_TRANSFERENCODINGEMPTY:
            /* The field is there and names no coding, so the message says a
             * coding delimits it and none does. */
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Transfer-Encoding: ,\r\n\r\n"
                   "5\r\nabcde\r\n0\r\n\r\n");
            break;

        case HDEF_CHUNKSIZETRAILINGJUNK:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Transfer-Encoding: chunked\r\n\r\n"
                   "5x\r\nabcde\r\n0\r\n\r\n");
            break;

        case HDEF_CHUNKSIZENOTHEX:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Transfer-Encoding: chunked\r\n\r\n"
                   "zz\r\nabcde\r\n0\r\n\r\n");
            break;

        case HDEF_CHUNKSIZENEGATIVE:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Transfer-Encoding: chunked\r\n\r\n"
                   "-5\r\nabcde\r\n0\r\n\r\n");
            break;

        case HDEF_CHUNKSIZEOVERFLOW:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Transfer-Encoding: chunked\r\n\r\n"
                   "FFFFFFFFFFFFFFFFF\r\nabcde\r\n0\r\n\r\n");
            break;

        case HDEF_CHUNKBADTERMINATOR:
            /* The CRLF after the chunk data is something else, so a parser
             * that does not check reads the next size from the middle of the
             * content. */
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Transfer-Encoding: chunked\r\n\r\n"
                   "5\r\nabcdeXX0\r\n\r\n");
            break;

        case HDEF_CHUNKNOLASTCHUNK:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Transfer-Encoding: chunked\r\n\r\n"
                   "5\r\nabcde\r\n");
            *half_close = 1;
            break;

        case HDEF_CHUNKTRUNCATED:
            REQ_LINE("POST", URI_PATH);
            wb_str(wb, "Transfer-Encoding: chunked\r\n\r\n"
                   "20\r\nabcde");
            *half_close = 1;
            break;

        default:
            fprintf(stderr, "defect %d has no wire encoding; add one to "
                    "build_defect()\n", defect);
            exit(1);
    } /* switch */

#undef REQ_LINE
} /* build_defect */

/*
 * Whether an observed outcome satisfies the model's expectation.  Status(n)
 * is exact; NotSuccess is the arm for the shapes the RFCs do not pin down,
 * where refusing and closing are both defensible and only reporting success
 * is not.
 */
static int
outcome_matches(
    const struct http_defect_case *c,
    int                            actual)
{
    switch (c->expect) {
        case HOUT_STATUS:
            return actual == c->expect_status;
        case HOUT_NOTSUCCESS:
            return actual == ACT_NORESPONSE ||
                   (actual >= 400 && actual <= 599);
        case HOUT_SIMPLERESPONSE:
            return actual == ACT_SIMPLE;
        default:
            return 0;
    } /* switch */
} /* outcome_matches */

static void
run_defect_case(const struct http_defect_case *c)
{
    struct wirebuf wb;
    struct reader *rd;
    struct rawrsp  r;
    char           detail[256];
    int            half_close, actual, ok;

    rd = calloc(1, sizeof(*rd));

    if (!rd) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }

    rd->fd = connect_raw();

    if (rd->fd < 0) {
        fprintf(stderr, "defect case %s: connect failed: %s\n",
                http_defect_name(c->defect), strerror(errno));
        g_results.unexpected++;
        free(rd);
        return;
    }

    g_results.defect_run++;

    wb_init(&wb);
    build_defect(&wb, c->defect, c->ver, &half_close);

    deliver(rd->fd, &wb, c->delivery);

    if (half_close) {
        shutdown(rd->fd, SHUT_WR);
    }

    read_response(rd, &r, 0, 1);

    actual = classify(&r);
    ok     = outcome_matches(c, actual);

    snprintf(detail, sizeof(detail), "%s, %s, %s -> %s",
             http_defect_name(c->defect), http_version_name(c->ver),
             http_delivery_name(c->delivery), outcome_name(actual));

    /* The expectation key is the required status where the model names one,
     * and the negated outcome tag where it does not -- status codes are
     * positive, so the two can never collide and a divergence row stays
     * readable as either "expected 400" or "expected NotSuccess". */
    record(PHASE_DEFECT, ASPECT_STATUS, c->defect,
           c->expect == HOUT_STATUS ? c->expect_status : -c->expect,
           actual, ok, ok ? NULL : detail);

    check_framing(PHASE_DEFECT, c->defect, c->ver, &r);

    /* Whatever the answer, a refusal ends the connection with it: a server
     * that has just said it cannot tell where this message ends cannot tell
     * where the next one starts either. */
    if (actual != ACT_NORESPONSE && actual != ACT_STALLED) {
        ok = c->expect_persist != HPERSIST_MUSTCLOSE ||
            connection_closed(rd, CLOSE_TIMEOUT_MS);

        record(PHASE_DEFECT, ASPECT_PERSIST, c->defect, PACT_CLOSED,
               rd->eof ? PACT_CLOSED : PACT_OPEN, ok, ok ? NULL :
               "the connection was still open after the response");
    }

    wb_free(&wb);
    close(rd->fd);
    free(rd);
} /* run_defect_case */

static void
run_defect_phase(void)
{
    unsigned int i;

    for (i = 0; i < HTTP_NUM_DEFECT_CASES; i++) {
        run_defect_case(&http_defect_cases[i]);
    }
} /* run_defect_phase */

/* ------------------------------------------------------------------ *
* Phase 3: the status line and the response framing
*
* A check that sits outside the model, for the same reason the framing checks
* do: the code list is libevpl's own table rather than anything the RFCs
* enumerate, and the specification content is a small number of rules --
*
*     status-line = HTTP-version SP status-code SP [ reason-phrase ]
*     status-code = 3DIGIT, leading digit 1 through 5     (RFC 9112 4)
*     no Content-Length or Transfer-Encoding on 1xx or 204   (RFC 9112 6.1)
*     no Transfer-Encoding towards an HTTP/1.0 request       (RFC 9112 6.1)
*     a Date on every 2xx, 3xx and 4xx                       (RFC 9110 6.6.1)
*
* -- applied to a list of inputs.  Bending forty status codes into the model
* would say they were a specification when they are a lookup table.
*
* The phrases themselves are deliberately NOT checked.  RFC 9112 section 4
* makes the reason phrase advisory ("A client SHOULD ignore the reason-phrase
* content"), and RFC 2616 section 6.1.1 said outright that the listed phrases
* "are only recommendations -- they MAY be replaced by local equivalents
* without affecting the protocol".  Asserting them would be asserting
* something the RFC explicitly leaves open.
*
* What IS checked is the part the RFCs do pin down, and it is the reason this
* phase is worth having rather than merely worth measuring: whatever an
* application asks for, what reaches the wire must be a message its peer can
* frame.  The last few status entries ask for things that are not statuses at
* all, and the chunked variants ask for a framing that is not always available,
* where the library -- which owns the wire format, as it does for the HEAD body
* rule -- is the only component in a position to refuse.
* ------------------------------------------------------------------ */

/* Every code evpl_http_response_status_string names, then two valid 3DIGIT
 * statuses it does not: status codes are extensible (RFC 9110 section 15), so
 * an unnamed one must still be carried, with whatever phrase the default arm
 * supplies. */
static const int status_codes[] = {
    100,
    101,
    200,
    201,
    202,
    203,
    204,
    205,
    206,
    300,
    301,
    302,
    303,
    304,
    305,
    307,
    400,
    401,
    402,
    403,
    404,
    405,
    406,
    407,
    408,
    409,
    410,
    411,
    412,
    413,
    414,
    415,
    416,
    417,
    426,
    500,
    501,
    502,
    503,
    504,
    505,
    418,
    451,
};

/* Not statuses.  A status code is three digits with a leading 1..5, so none of
 * these can be represented, and a peer handed one cannot parse the response at
 * all -- which is what libevpl used to send, straight from whatever the
 * application passed.  What it sends instead is not pinned down here beyond
 * having to be a status line; today it is 500. */
static const int status_not_codes[] = {
    0,
    42,
    600,
    1000,
};

/* The statuses the chunked variant is run over: one that may carry content,
 * two that may not, and one error.  The point is the framing rather than the
 * status, so a sample is enough -- but it has to include the two shapes where
 * asking for chunked and being refused it are different answers: a 204 has no
 * content at all, while a 304 keeps the header fields a GET would have got. */
static const int chunked_statuses[] = {
    200,
    204,
    304,
    404,
};

/* Content the chunked variants send, so that the response has something to
 * frame.  A response whose content is empty exercises the header block and
 * nothing else -- and the framing of last resort, where the close delimits
 * the content, has no observable behaviour at all without octets to
 * delimit. */
#define STATUS_BODY     "framed-content"
#define STATUS_BODY_LEN ((int) sizeof(STATUS_BODY) - 1)

static void
run_status_case(
    int         status,
    int         ver,
    int         chunked,
    int         exact,
    const char *method)
{
    struct wirebuf wb;
    struct reader *rd;
    struct rawrsp  r;
    char           line[128];
    char           detail[256];
    int            actual, ok;

    rd = calloc(1, sizeof(*rd));

    if (!rd) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }

    rd->fd = connect_raw();

    if (rd->fd < 0) {
        fprintf(stderr, "status case %d: connect failed: %s\n", status,
                strerror(errno));
        g_results.unexpected++;
        free(rd);
        return;
    }

    g_results.status_run++;

    wb_init(&wb);

    wb_str(&wb, method);
    wb_str(&wb, " " URI_PATH " ");
    wb_str(&wb, version_wire(ver));
    wb_str(&wb, "\r\n");

    if (ver == HVER_V11) {
        wb_str(&wb, "Host: ");
        wb_str(&wb, g_host_value);
        wb_str(&wb, "\r\n");
    }

    /* Nothing here is about connection reuse, so every case asks for the
     * close it is going to get anyway; that also keeps the reader from waiting
     * out a close-delimited body's deadline. */
    wb_str(&wb, "Connection: close\r\n");

    snprintf(line, sizeof(line), "%s: %d\r\n", RESPOND_STATUS, status);
    wb_str(&wb, line);

    if (chunked) {
        wb_str(&wb, RESPOND_CHUNKED ": 1\r\n");
        /* The echo application answers with whatever the request carried, so
         * the request has to carry something for the response framing to have
         * any work to do. */
        snprintf(line, sizeof(line), "Content-Length: %d\r\n",
                 STATUS_BODY_LEN);
        wb_str(&wb, line);
    }

    wb_str(&wb, "\r\n");

    if (chunked) {
        wb_str(&wb, STATUS_BODY);
    }

    deliver(rd->fd, &wb, HDLV_ONEWRITE);

    /* Interim responses are NOT skipped here.  Everywhere else a 1xx is a note
     * that the answer is still coming; here the application asked for one as
     * its answer, so the 1xx is the message under examination and skipping it
     * would leave the reader waiting for a response that was never going to
     * be sent. */
    read_response(rd, &r, strcmp(method, "HEAD") == 0, 0);

    actual = classify(&r);

    /* Well-formedness first: three digits in a class the RFC defines, and a
     * phrase.  check_framing covers the version, the phrase and the framing
     * headers; the range is this phase's business. */
    ok = actual >= 100 && actual <= 599;

    snprintf(detail, sizeof(detail), "asked for %d at %s%s, wire carried %s",
             status, http_version_name(ver), chunked ? " chunked" : "",
             outcome_name(actual));

    record(PHASE_STATUS, ASPECT_FRAMING, status, VACT_OK,
           ok ? VACT_OK : VACT_BAD, ok, ok ? NULL : detail);

    if (ok) {
        check_framing(PHASE_STATUS, status, ver, &r);
    }

    /* Then, where the application asked for a real status, that it is the one
     * that arrived. */
    if (exact) {
        ok = actual == status;

        record(PHASE_STATUS, ASPECT_STATUS, status, status, actual, ok,
               ok ? NULL : detail);
    }

    wb_free(&wb);
    close(rd->fd);
    free(rd);
} /* run_status_case */

/*
 * Response splitting, which is the one defect class in this file whose input
 * comes from the application rather than from the wire.
 *
 * RFC 9110 section 5.5 calls a field value containing CR, LF or NUL "invalid
 * and dangerous" and has a recipient reject or sanitize it; section 5.1 makes
 * a field name a token.  A CRLF inside a value ends the field, so everything
 * after it is read as
 * further fields and, after a second CRLF, as content -- one response becomes
 * two, the second of them chosen by whoever supplied the value.  The wire
 * cannot deliver such a header (the parser splits lines on LF, so a parsed
 * value never contains one), but an application builds header values from
 * redirect targets and query parameters, and those can.
 *
 * The library owns what reaches the wire, so refusing is its job; the echo
 * application asks for the header and reports whether the API took it.
 */
static void
run_injection_case(void)
{
    struct wirebuf wb;
    struct reader *rd;
    struct rawrsp  r;
    const char    *result;
    char           detail[256];
    int            actual, ok;

    rd = calloc(1, sizeof(*rd));

    if (!rd) {
        fprintf(stderr, "out of memory\n");
        exit(1);
    }

    rd->fd = connect_raw();

    if (rd->fd < 0) {
        fprintf(stderr, "injection case: connect failed: %s\n",
                strerror(errno));
        g_results.unexpected++;
        free(rd);
        return;
    }

    g_results.status_run++;

    wb_init(&wb);

    wb_str(&wb, "GET " URI_PATH " HTTP/1.1\r\nHost: ");
    wb_str(&wb, g_host_value);
    /* The application supplies its own Date on the same request, so that the
     * one-Date rule is checked where it can actually be broken: everywhere
     * else in the suite the library is the only source of one. */
    wb_str(&wb, "\r\nConnection: close\r\n" INJECT_ASK ": 1\r\n"
           RESPOND_DATE ": 1\r\n\r\n");

    deliver(rd->fd, &wb, HDLV_ONEWRITE);

    read_response(rd, &r, 0, 1);

    actual = classify(&r);
    result = rsp_header(&r, INJECT_RESULT);

    ok = actual == 200 && result && strcmp(result, "refused") == 0 &&
        rsp_header(&r, INJECT_SMUGGLED) == NULL &&
        rsp_header_count(&r, "Date") == 1 &&
        strcmp(rsp_header(&r, "Date"), RESPOND_DATE_VALUE) == 0;

    snprintf(detail, sizeof(detail),
             "status %s, the API %s the header, %s smuggled field, %d Date(s)",
             outcome_name(actual), result ? result : "(no result reported)",
             rsp_header(&r, INJECT_SMUGGLED) ? "a" : "no",
             rsp_header_count(&r, "Date"));

    record(PHASE_STATUS, ASPECT_FRAMING, 200, VACT_OK,
           ok ? VACT_OK : VACT_BAD, ok, ok ? NULL : detail);

    wb_free(&wb);
    close(rd->fd);
    free(rd);
} /* run_injection_case */

static void
run_status_phase(void)
{
    unsigned int i;
    int          ver;

    for (ver = HVER_V10; ver <= HVER_V11; ver++) {
        for (i = 0; i < sizeof(status_codes) / sizeof(status_codes[0]); i++) {
            run_status_case(status_codes[i], ver, 0, 1, "GET");
        }

        for (i = 0; i < sizeof(status_not_codes) / sizeof(status_not_codes[0]);
             i++) {
            run_status_case(status_not_codes[i], ver, 0, 0, "GET");
        }

        for (i = 0; i < sizeof(chunked_statuses) / sizeof(chunked_statuses[0]);
             i++) {
            run_status_case(chunked_statuses[i], ver, 1, 1, "POST");
        }

        /* And once as HEAD, where the header fields a GET would have got stay
         * and the content does not -- which is a different decision from the
         * one a 204 gets, and reaches it through a different branch. */
        run_status_case(200, ver, 1, 1, "HEAD");
    }

    run_injection_case();
} /* run_status_phase */

/* ------------------------------------------------------------------ *
* main
* ------------------------------------------------------------------ */

static void
report(void)
{
    int i;

    fprintf(stderr,
            "\nhttp/1.x conformance: %d/%u request cases (%d checks, %d "
            "failed), %d/%u defect cases (%d checks, %d failed), "
            "%d status cases (%d checks, %d failed)\n",
            g_results.request_run, (unsigned int) HTTP_NUM_REQUEST_CASES,
            g_results.request_checks, g_results.request_failed,
            g_results.defect_run, (unsigned int) HTTP_NUM_DEFECT_CASES,
            g_results.defect_checks, g_results.defect_failed,
            g_results.status_run, g_results.status_checks,
            g_results.status_failed);

    if (g_num_observed) {
        fprintf(stderr, "\ndivergences from RFC 1945 / RFC 9112:\n");
    }

    for (i = 0; i < g_num_observed; i++) {
        fprintf(stderr, "  %-6s %-12s %-34s expected %5d, got %5d  x%-4d %s\n",
                g_observed[i].phase == PHASE_REQUEST ? "req" :
                g_observed[i].phase == PHASE_DEFECT ? "defect" : "status",
                aspect_name(g_observed[i].aspect),
                subject_name(g_observed[i].phase, g_observed[i].aspect,
                             g_observed[i].subject),
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
    struct test_server server;
    int                opt;

    /* Several cases leave the peer to hang up mid-conversation; a late write
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

    snprintf(g_uri_long, sizeof(g_uri_long), "%s/", URI_PATH);
    memset(g_uri_long + strlen(g_uri_long), 'p', URI_LONG_PATH_LEN);
    g_uri_long[sizeof(URI_PATH "/") - 1 + URI_LONG_PATH_LEN] = '\0';

    snprintf(g_host_value, sizeof(g_host_value), "127.0.0.1:%d", port);
    snprintf(g_uri_absolute, sizeof(g_uri_absolute), "http://%s%s",
             g_host_value, URI_PATH);

    evpl_init(NULL);

    server.run = 0;

    pthread_create(&server.thread, NULL, server_function, &server);

    while (!server.run) {
        __sync_synchronize();
    }

    run_request_phase();
    run_defect_phase();
    run_status_phase();

    server.run = 0;
    __sync_synchronize();
    evpl_ring_doorbell(&server.doorbell);
    pthread_join(server.thread, NULL);

    report();

    return g_results.unexpected ? 1 : 0;
} /* main */
