/*
 * SPDX-FileCopyrightText: 2026 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Model-based HTTP/1.0 conformance test.
 *
 * Two phases, both driven by cases generated from the Quint model in
 * quint/http10.qnt and compiled in as http_cases.h:
 *
 *   1. Requests.  Legal HTTP/1.0 requests -- every method, URI shape, header
 *      grammar, body length and connection disposition the model enumerates --
 *      are written onto a raw socket, and the response is checked against what
 *      RFC 1945 requires.  The server behind the socket is a real libevpl HTTP
 *      server running an echo application, so the reply carries the method,
 *      the URI, the probe header and the body it parsed: the oracle is what
 *      the server understood, not merely that it answered.
 *
 *   2. Defects.  Deliberately malformed requests, likewise written raw.  Each
 *      response is classified and compared against the status RFC 1945
 *      requires.
 *
 * Both phases drive a raw socket rather than libevpl's own HTTP client,
 * because that client cannot express any of this: evpl_http_client_send_headers
 * hardcodes "HTTP/1.1" and emits a fixed header block, so it can neither send
 * an HTTP/1.0 request nor a malformed one.
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
* which is the whole point of the split: http10.qnt says "a header whose
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
#define ECHO_ABSENT         "(absent)"

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

#define PHASE_REQUEST       0
#define PHASE_DEFECT        1

/* ASPECT_PERSIST actuals. */
#define PACT_CLOSED         0
#define PACT_OPEN           1

/* ASPECT_KEEPALIVE / ASPECT_ECHO_* / ASPECT_FRAMING actuals: the check either
 * held or it did not, and the report carries the case that failed it. */
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
 * reject: the methods and URI forms here are the ones RFC 1945 defines, while
 * the header block is where a hand-written parser meets folding, empty values
 * and repeated fields.  The full case is printed alongside, so a refusal that
 * really came from somewhere else is still legible in the log. */
static const char *
subject_name(
    int phase,
    int aspect,
    int subject)
{
    if (phase == PHASE_DEFECT) {
        return http_defect_name(subject);
    }

    switch (aspect) {
        case ASPECT_STATUS:
        case ASPECT_PROBE:
            return http_hdr_name(subject);
        case ASPECT_PERSIST:
        case ASPECT_KEEPALIVE:
            return http_conn_name(subject);
        case ASPECT_ECHO_URI:
            return http_uri_name(subject);
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
    * 1. HTTP/1.0 connection semantics are not implemented.
    *
    * RFC 1945 section 1.4: "The connection is closed by the server after
    * sending the response."  libevpl's HTTP/1.x server never closes a
    * connection it has answered on, and evpl_http_server_dispatch_default
    * additionally attaches "Connection: keep-alive" to every response,
    * unsolicited -- which RFC 2068 section 19.7.1.1 reserves for a reply to
    * a client that asked for it.  Together they leave an HTTP/1.0 client
    * that does not implement the Keep-Alive extension waiting on a close
    * that never comes, for every request it makes.
    *
    * Fixing it needs a decision the test cannot make: whether to close on
    * the HTTP/1.0 default, honour Connection on both versions, or keep
    * today's always-persistent behaviour and document it as HTTP/1.1-only.
    * ---------------------------------------------------------------- */

    { .phase   = PHASE_REQUEST,
      .aspect  = ASPECT_PERSIST,
      .subject = HCONN_CONNDEFAULT,
      .expect  = PACT_CLOSED,
      .actual  = PACT_OPEN,
      .note    = "HTTP/1.0 response does not close the connection" },
    { .phase   = PHASE_REQUEST,
      .aspect  = ASPECT_KEEPALIVE,
      .subject = HCONN_CONNDEFAULT,
      .expect  = VACT_OK,
      .actual  = VACT_BAD,
      .note    = "unsolicited Connection: keep-alive on every response" },

    /* The same fact, seen from the defect phase: every request that got an
     * answer kept its connection.  One row per defect that reaches a
     * response, because the divergence key carries the case. */
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_PERSIST,
      .subject = HDEF_NODEFECT,
      .expect  = PACT_CLOSED,
      .actual  = PACT_OPEN,
      .note    = "HTTP/1.0 response does not close the connection" },
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_PERSIST,
      .subject = HDEF_REQUESTLINEEXTRATOKEN,
      .expect  = PACT_CLOSED,
      .actual  = PACT_OPEN,
      .note    = "HTTP/1.0 response does not close the connection" },
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_PERSIST,
      .subject = HDEF_HEADERSPACEBEFORECOLON,
      .expect  = PACT_CLOSED,
      .actual  = PACT_OPEN,
      .note    = "HTTP/1.0 response does not close the connection" },
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_PERSIST,
      .subject = HDEF_POSTWITHOUTCONTENTLENGTH,
      .expect  = PACT_CLOSED,
      .actual  = PACT_OPEN,
      .note    = "HTTP/1.0 response does not close the connection" },
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_PERSIST,
      .subject = HDEF_CONTENTLENGTHNOTNUMERIC,
      .expect  = PACT_CLOSED,
      .actual  = PACT_OPEN,
      .note    = "HTTP/1.0 response does not close the connection" },

    /* ---------------------------------------------------------------- *
    * 2. The request line is parsed loosely where RFC 1945 section 5.1 is
    *    exact.
    *
    * strtok_r treats a run of SP and HT as one delimiter and skips leading
    * ones, so " /echo HTTP/1.0" parses as a request whose method is "/echo".
    * That is answered -- 501, since it is not a method the server knows --
    * but the request line is malformed rather than the method unimplemented,
    * and 400 is what says so.  The same permissiveness discards a fourth
    * token on the line entirely.
    * ---------------------------------------------------------------- */

    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_METHODEMPTY,
      .expect  = 400,
      .actual  = 501,
      .note    = "a leading space is skipped, so the URI parses as a method" },

    /* ---------------------------------------------------------------- *
    * 3. The header-field grammar of RFC 1945 section 4.2 is only partly
    *    implemented, and a field it does not understand fails the whole
    *    request rather than being carried through.
    *
    * The parser splits a field on the first colon with strtok_r and treats a
    * NULL value token as fatal, so "X-Probe:" -- a field present with an
    * empty value, which the grammar allows ("field-name ':' [ field-value ]")
    * -- closes the connection.  A continuation line fares the same way: it
    * has no colon of its own, so it parses as a malformed field rather than
    * as more of the field above it.  Both are legal requests that a
    * conforming server must serve, and both are things a client library
    * emits without thinking about it.
    *
    * Leading LWS is skipped one space at a time (`while (*token == ' ')`),
    * so a tab survives into the value, and trailing LWS is never stripped at
    * all -- an application comparing a header value against a constant gets
    * a mismatch it has no way to see coming.
    * ---------------------------------------------------------------- */

    { .phase   = PHASE_REQUEST,
      .aspect  = ASPECT_STATUS,
      .subject = HHDR_HDREMPTY,
      .expect  = 200,
      .actual  = 400,
      .note    = "a header with an empty value is refused with 400" },
    { .phase   = PHASE_REQUEST,
      .aspect  = ASPECT_STATUS,
      .subject = HHDR_HDRFOLDED,
      .expect  = 200,
      .actual  = 400,
      .note    = "a continuation line is refused with 400" },
    { .phase   = PHASE_REQUEST,
      .aspect  = ASPECT_PROBE,
      .subject = HHDR_HDRPADDED,
      .expect  = HPROBE_PROBEVALUE,
      .actual  = HPROBE_PROBEANY,
      .note    = "leading HT and all trailing LWS are kept in the value" },

    /* The mirror image: a field the grammar does NOT allow is accepted.  A
     * space before the colon makes the field-name "X-Probe ", which is not a
     * token, and RFC 7230 section 3.2.4 later made rejecting it a MUST
     * precisely because a front end and a back end that disagree about
     * whether it is a header is how a request smuggles one past a filter. */
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_HEADERSPACEBEFORECOLON,
      .expect  = 400,
      .actual  = 200,
      .note    = "whitespace before the colon is accepted as a field name" },

    /* ---------------------------------------------------------------- *
    * 4. Content-Length is taken on trust.
    *
    * The value goes straight through strtoul with no check that it is a
    * decimal number at all, and a second Content-Length simply overwrites
    * the first.  A value that is not a number reads as zero, so a request
    * WITH an entity is treated as one without and its body becomes whatever
    * the server parses next; two conflicting values pick where the next
    * request starts, which is the classic desync a request-smuggling attack
    * is built on.  RFC 1945 section 8.3 also requires a POST to carry a
    * length and names 400 for one that does not.
    *
    * The memory-safety half of this -- a length above INT_MAX truncating
    * into evpl_recvv's int parameter and yielding a stale iovec -- was
    * found by this suite and is fixed in http.c; what remains is the
    * validation.
    * ---------------------------------------------------------------- */

    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_CONTENTLENGTHNOTNUMERIC,
      .expect  = 400,
      .actual  = 200,
      .note    = "a non-numeric Content-Length reads as zero" },
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_CONTENTLENGTHNEGATIVE,
      .expect  = 400,
      .actual  = ACT_STALLED,
      .note    = "'-1' wraps to a length no client will ever satisfy" },
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_CONTENTLENGTHDUPLICATECONFLICTING,
      .expect  = 400,
      .actual  = ACT_STALLED,
      .note    = "the last of two conflicting Content-Lengths wins" },
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_POSTWITHOUTCONTENTLENGTH,
      .expect  = 400,
      .actual  = 200,
      .note    = "a POST with no Content-Length is served as an empty one" },

    /* ---------------------------------------------------------------- *
    * 5. The request line is parsed permissively where RFC 1945 is exact,
    *    and strictly where it recommends tolerance.
    * ---------------------------------------------------------------- */

    /* strtok_r keeps handing out tokens, and only the first three are read,
     * so anything after the version is silently discarded.  Request-Line is
     * exactly three fields (section 5.1). */
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_REQUESTLINEEXTRATOKEN,
      .expect  = 400,
      .actual  = 200,
      .note    = "a fourth token on the request line is ignored" },

    /* The version is matched with strncmp against exactly "HTTP/1.1" and
     * "HTTP/1.0", so "HTTP/1.9" is refused.  RFC 2145 section 2.3: a higher
     * minor version is a request to be served at the version the server does
     * speak, which is what makes the minor number usable for negotiation. */
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_VERSIONMINORUNKNOWN,
      .expect  = 200,
      .actual  = 400,
      .note    = "HTTP/1.9 is refused rather than served as HTTP/1.1" },

    /* RECOMMENDED rather than required: RFC 1945 section 19.3 asks parsers to
     * accept a bare LF as a line terminator.  Recorded because a server that
     * refuses it interoperates worse than the RFC asks, not because it
     * violates a MUST. */
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_BARELFLINEENDINGS,
      .expect  = 200,
      .actual  = 400,
      .note    = "bare LF line endings are refused (RFC 1945 19.3 tolerance)" },

    /* HTTP/0.9.  A request line with no version is a Simple-Request, and RFC
     * 1945 section 6 answers it with a Simple-Response -- the body with no
     * status line.  Obsolete, and supporting it means the response shape
     * depends on the request, so this is recorded rather than pursued. */
    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_REQUESTLINENOVERSION,
      .expect  = -HOUT_SIMPLERESPONSE,
      .actual  = 400,
      .note    = "an HTTP/0.9 Simple-Request is answered 400, not with a body" },

    /* ---------------------------------------------------------------- *
    * 6. An over-long request line can wedge the connection.
    *
    * evpl_http_parse_line peeks at most 8 iovecs (evpl_peekv's maxiovecs),
    * so where the request line spans more receive buffers than that it never
    * accumulates the maxline bytes that would make it report the overflow,
    * and returns "need more data" for data that has already arrived.  The
    * connection then makes no further progress and holds its buffers until
    * the peer gives up.  Reachable from an unauthenticated peer, and only on
    * some delivery patterns, which is why it shows up on one case in three.
    * ---------------------------------------------------------------- */

    { .phase   = PHASE_DEFECT,
      .aspect  = ASPECT_STATUS,
      .subject = HDEF_URITOOLONG,
      .expect  = -HOUT_NOTSUCCESS,
      .actual  = ACT_STALLED,
      .note    = "an over-long request line can stall rather than be refused" },
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

    if (phase == PHASE_REQUEST) {
        g_results.request_checks++;
    } else {
        g_results.defect_checks++;
    }

    if (ok) {
        return;
    }

    if (phase == PHASE_REQUEST) {
        g_results.request_failed++;
    } else {
        g_results.defect_failed++;
    }

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

/* How many iovecs the echo application drains at a time, and the flat buffer
 * it reassembles them into.  Touched only by the server thread. */
#define ECHO_DRAIN_IOV 64

static char g_echo_body[BODY_LARGE_LEN + 64];

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
    struct evpl_iovec iov[ECHO_DRAIN_IOV];
    struct evpl_iovec rsp;
    struct probe_scan scan;
    char              echo[1024];
    char              count[16];
    uint64_t          avail;
    int               niov, i, want, total = 0;

    switch (notify_type) {
        case EVPL_HTTP_NOTIFY_RECEIVE_DATA:
            /* The body is drained once, at completion, so that the echo is a
             * single contiguous comparison.  Nothing to do here. */
            break;
        case EVPL_HTTP_NOTIFY_RECEIVE_COMPLETE:

            memset(&scan, 0, sizeof(scan));
            evpl_http_request_header_iterate(request, probe_count_cb, &scan);

            evpl_http_request_add_header(request, ECHO_METHOD,
                                         evpl_http_request_type_to_string(
                                             request));

            evpl_http_request_add_header(request, ECHO_URI,
                                         evpl_http_request_url(request, NULL));

            if (scan.found) {
                snprintf(echo, sizeof(echo), "[%s]", scan.value);
            } else {
                snprintf(echo, sizeof(echo), "%s", ECHO_ABSENT);
            }

            evpl_http_request_add_header(request, ECHO_PROBE, echo);

            snprintf(count, sizeof(count), "%d", scan.count);
            evpl_http_request_add_header(request, ECHO_PROBE_COUNT, count);

            /* Echo the request body back verbatim.  The same code runs for
             * HEAD: whether a body reaches the wire for a HEAD request is the
             * server's decision to make (RFC 1945 section 8.2), not the
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

            while (avail > 0 && total < (int) sizeof(g_echo_body)) {
                want = avail > ECHO_DRAIN_IOV ? ECHO_DRAIN_IOV : (int) avail;
                niov = evpl_http_request_get_datav(evpl, request, iov, want);

                if (niov <= 0) {
                    break;
                }

                for (i = 0; i < niov; i++) {
                    memcpy(g_echo_body + total, iov[i].data, iov[i].length);
                    total += iov[i].length;
                    evpl_iovec_release(evpl, &iov[i]);
                }

                avail = evpl_http_request_get_data_avail(request);
            }

            evpl_http_server_set_response_length(request, total);

            if (total) {
                evpl_iovec_alloc(evpl, total, 0, 1, 0, &rsp);
                memcpy(rsp.data, g_echo_body, total);
                rsp.length = total;
                evpl_http_request_add_datav(request, &rsp, 1);
            }

            evpl_http_server_dispatch_default(request, 200);
            break;
        case EVPL_HTTP_NOTIFY_WANT_DATA:
        case EVPL_HTTP_NOTIFY_RESPONSE_HEADERS:
        case EVPL_HTTP_NOTIFY_RESPONSE_COMPLETE:
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
    *notify_callback = server_notify;
    *notify_data     = NULL;
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

static int
body_length(int body_cls)
{
    switch (body_cls) {
        case HBDY_BODYNONE:  return 0;
        case HBDY_BODYEMPTY: return 0;
        case HBDY_BODYONE:   return 1;
        case HBDY_BODYSMALL: return BODY_SMALL_LEN;
        case HBDY_BODYLARGE: return BODY_LARGE_LEN;
        default:             return 0;
    } /* switch */
} /* body_length */

static const char *
method_wire(int method_cls)
{
    switch (method_cls) {
        case HMETH_MGET:  return "GET";
        case HMETH_MHEAD: return "HEAD";
        case HMETH_MPOST: return "POST";
        default:          return "GET";
    } /* switch */
} /* method_wire */

/* What evpl_http_request_type_to_string() spells the method as, which is what
 * comes back in X-Echo-Method. */
static const char *
method_echoed(int method_cls)
{
    switch (method_cls) {
        case HMETH_MGET:  return "Get";
        case HMETH_MHEAD: return "Head";
        case HMETH_MPOST: return "Post";
        default:          return "Get";
    } /* switch */
} /* method_echoed */

static char g_uri_long[URI_LONG_PATH_LEN + 16];

static const char *
uri_wire(int uri_cls)
{
    switch (uri_cls) {
        case HURI_URIROOT:    return URI_ROOT;
        case HURI_URIPATH:    return URI_PATH;
        case HURI_URIQUERY:   return URI_QUERY;
        case HURI_URIESCAPED: return URI_ESCAPED;
        case HURI_URILONG:    return g_uri_long;
        default:              return URI_PATH;
    } /* switch */
} /* uri_wire */

/*
 * The header fields a request carries, less the ones the framing adds
 * (Connection, Content-Length).  Every shape here is legal RFC 1945 section
 * 4.2 grammar; the model says which, this says how it is spelled.
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
    wb_str(wb, " HTTP/1.0\r\n");

    append_headers(wb, c->hdr);

    if (c->conn == HCONN_CONNKEEPALIVE) {
        wb_str(wb, "Connection: keep-alive\r\n");
    }

    if (c->body != HBDY_BODYNONE) {
        snprintf(line, sizeof(line), "Content-Length: %d\r\n", *body_len);
        wb_str(wb, line);
    }

    wb_str(wb, "\r\n");

    if (*body_len) {
        fill_body(body, *body_len);
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
        default:
            write_all(fd, wb->data, wb->len);
            break;
    } /* switch */
} /* deliver */

/* ------------------------------------------------------------------ *
* The response parser
* ------------------------------------------------------------------ */

#define MAX_RESPONSE  (BODY_LARGE_LEN + 65536)
#define MAX_RSP_HDRS  64
#define MAX_RSP_NAME  128
#define MAX_RSP_VALUE 2048

struct rawrsp {
    char    buf[MAX_RESPONSE];
    int     len;
    int     eof;

    int     have_status;
    int     status;
    char    version[16];
    char    reason[128];

    int     hdr_end;          /* offset past the CRLFCRLF, -1 until seen */
    int     nhdr;
    struct {
        char name[MAX_RSP_NAME];
        char value[MAX_RSP_VALUE];
    } hdr[MAX_RSP_HDRS];

    int64_t content_length;   /* -1 when the response declares none */
    int     chunked;

    int     body_len;
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

/*
 * Parse as much of the accumulated bytes as have arrived.  Idempotent: it is
 * called after every read and stops as soon as it needs bytes it does not
 * have, so a response split across a hundred reads parses exactly once.
 */
static void
parse_response(struct rawrsp *r)
{
    const char *base = r->buf;
    const char *end  = r->buf + r->len;
    const char *line, *eol, *sp1, *sp2, *colon, *value, *vend;
    const char *cl;

    if (r->hdr_end >= 0) {
        r->body_len = r->len - r->hdr_end;
        return;
    }

    if (r->len < 5 || memcmp(base, "HTTP/", 5) != 0) {
        /* Either not enough bytes to tell, or a Simple-Response, which has no
         * status line and no headers at all: every byte is body. */
        return;
    }

    line = base;
    eol  = find_crlf(line, end);

    if (!eol) {
        return;
    }

    sp1 = memchr(line, ' ', eol - line);

    if (!sp1) {
        return;
    }

    copy_field(r->version, sizeof(r->version), line, sp1 - line);

    sp2 = memchr(sp1 + 1, ' ', eol - (sp1 + 1));

    r->status      = atoi(sp1 + 1);
    r->have_status = r->status >= 100 && r->status <= 599;

    if (sp2) {
        copy_field(r->reason, sizeof(r->reason), sp2 + 1, eol - (sp2 + 1));
    }

    line = eol + 2;

    while (line < end) {
        eol = find_crlf(line, end);

        if (!eol) {
            return;
        }

        if (eol == line) {
            r->hdr_end  = (int) ((line + 2) - base);
            r->body_len = r->len - r->hdr_end;
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

    if (r->hdr_end < 0) {
        return;
    }

    cl = rsp_header(r, "Content-Length");

    r->content_length = cl ? strtoll(cl, NULL, 10) : -1;

    cl = rsp_header(r, "Transfer-Encoding");

    r->chunked = cl && strcasecmp(cl, "chunked") == 0;
} /* parse_response */

static int64_t
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);

    return (int64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
} /* now_ms */

/*
 * Read the response.
 *
 * `expect_body_absent` is the HEAD case: the response declares a length but
 * must not carry the bytes, so the reader spends a short grace proving none
 * arrive rather than blocking on a body that is required to be missing.
 *
 * `wait_close` asks for the extra wait that proves the server closed the
 * connection.  It is expensive and the answer does not vary with the URI or
 * the header shape, so run_request_case only asks for it on a sample.
 */
static void
read_response(
    struct rawrsp *r,
    int            fd,
    int            expect_body_absent,
    int            wait_close)
{
    struct pollfd pfd;
    int64_t       deadline, grace = -1;
    int           n, timeout;
    int           complete = 0;

    memset(r, 0, sizeof(*r));

    r->hdr_end        = -1;
    r->content_length = -1;

    deadline = now_ms() + RESPONSE_TIMEOUT_MS;

    for (;;) {
        parse_response(r);

        if (!complete && r->hdr_end >= 0) {
            if (expect_body_absent) {
                if (r->body_len > 0) {
                    /* A body arrived where none may: nothing further to
                     * learn, and waiting for the rest of it wastes the
                     * grace. */
                    return;
                }

                if (grace < 0) {
                    grace = now_ms() + NOBODY_GRACE_MS;
                }

                if (now_ms() >= grace) {
                    complete = 1;
                }
            } else if (r->content_length >= 0 &&
                       r->body_len >= r->content_length) {
                complete = 1;
            }

            if (complete) {
                if (!wait_close) {
                    return;
                }

                deadline = now_ms() + CLOSE_TIMEOUT_MS;
            }
        }

        timeout = (int) (deadline - now_ms());

        if (grace >= 0 && !complete) {
            int g = (int) (grace - now_ms());

            if (g < timeout) {
                timeout = g;
            }
        }

        if (timeout < 0) {
            timeout = 0;
        }

        pfd.fd      = fd;
        pfd.events  = POLLIN;
        pfd.revents = 0;

        n = poll(&pfd, 1, timeout);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            return;
        }

        if (n == 0) {
            if (grace >= 0 && !complete && now_ms() >= grace) {
                continue;
            }
            return;
        }

        if (r->len == MAX_RESPONSE) {
            return;
        }

        n = read(fd, r->buf + r->len, MAX_RESPONSE - r->len);

        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }

            /* A reset is a close: a server that hangs up on a request the
             * client is still dribbling out will reset the rest of it, and
             * the read fails rather than returning EOF.  Recording that as a
             * stall would say the server held the connection when it did the
             * opposite, and would make the same defect classify differently
             * depending only on how the request was delivered. */
            if (errno == ECONNRESET) {
                r->eof = 1;
            }

            return;
        }

        if (n == 0) {
            r->eof = 1;
            parse_response(r);
            return;
        }

        r->len += n;
    }
} /* read_response */

static int
classify(const struct rawrsp *r)
{
    if (r->len == 0) {
        return r->eof ? ACT_NORESPONSE : ACT_STALLED;
    }

    if (r->len < 5 || memcmp(r->buf, "HTTP/", 5) != 0) {
        return ACT_SIMPLE;
    }

    if (!r->have_status || r->hdr_end < 0) {
        return ACT_MALFORMED;
    }

    return r->status;
} /* classify */

/*
 * Checks that sit outside the model, applied to every response that has a
 * status line at all.  None of them is a property of a particular case -- they
 * are what makes any response to an HTTP/1.0 request a well-formed one -- so
 * holding them here rather than bending them into the case table keeps the
 * model about what the request means.
 */
static void
check_framing(
    int                  phase,
    int                  subject,
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

    /* Chunked transfer coding is an HTTP/1.1 addition (RFC 2616 section 3.6.1);
     * an HTTP/1.0 client has no way to delimit a response framed with it, so
     * sending one to an HTTP/1.0 request is a response the peer cannot read. */
    if (r->chunked) {
        record(phase, ASPECT_FRAMING, subject, VACT_OK, VACT_BAD, 0,
               "chunked response to an HTTP/1.0 request");
        return;
    }

    record(phase, ASPECT_FRAMING, subject, VACT_OK, VACT_OK, 1, NULL);
} /* check_framing */

/* ------------------------------------------------------------------ *
* Phase 1: the positive matrix
* ------------------------------------------------------------------ */

/*
 * Whether this case pays for the wait that proves the connection closed.  The
 * answer depends on the request's version and its Connection header and on
 * nothing else, so it is checked once per (method, connection) pair rather
 * than on all several hundred cases -- at a quarter of a second each, doing it
 * everywhere would dominate the run.
 */
static int g_persist_checked[3][2];

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

static void
run_request_case(const struct http_request_case *c)
{
    struct wirebuf wb;
    struct rawrsp  r;
    static char    body[BODY_LARGE_LEN];
    char           detail[512];
    const char    *echo;
    int            fd, body_len, actual, want_close, ok;

    fd = connect_raw();

    if (fd < 0) {
        fprintf(stderr, "request case: connect failed: %s\n", strerror(errno));
        g_results.unexpected++;
        return;
    }

    g_results.request_run++;

    wb_init(&wb);
    build_request(&wb, c, body, &body_len);

    want_close                            = !g_persist_checked[c->method][c->conn];
    g_persist_checked[c->method][c->conn] = 1;

    deliver(fd, &wb, c->delivery);

    read_response(&r, fd, c->expect_body == HBODY_BODYABSENT, want_close);

    actual = classify(&r);

    /* Status. */
    snprintf(detail, sizeof(detail), "%s %s, %s, %s, %s, %s",
             http_method_name(c->method), http_uri_name(c->uri),
             http_hdr_name(c->hdr), http_body_name(c->body),
             http_conn_name(c->conn), http_delivery_name(c->delivery));

    ok = actual == c->expect_status;

    record(PHASE_REQUEST, ASPECT_STATUS, c->hdr, c->expect_status, actual, ok,
           ok ? NULL : detail);

    if (!ok) {
        /* Nothing downstream of the status means anything if the request was
         * not served: there is no echo to compare and no body to check. */
        goto out;
    }

    check_framing(PHASE_REQUEST, c->method, &r);

    /* What the server understood. */
    echo = rsp_header(&r, ECHO_METHOD);
    ok   = echo && strcmp(echo, method_echoed(c->method)) == 0;

    snprintf(detail, sizeof(detail), "method reflected as '%s', wanted '%s'",
             echo ? echo : "(absent)", method_echoed(c->method));

    record(PHASE_REQUEST, ASPECT_ECHO_METHOD, c->method, VACT_OK,
           ok ? VACT_OK : VACT_BAD, ok, ok ? NULL : detail);

    echo = rsp_header(&r, ECHO_URI);
    ok   = echo && strcmp(echo, uri_wire(c->uri)) == 0;

    snprintf(detail, sizeof(detail), "uri reflected as '%.64s', wanted '%.64s'",
             echo ? echo : "(absent)", uri_wire(c->uri));

    record(PHASE_REQUEST, ASPECT_ECHO_URI, c->uri, VACT_OK,
           ok ? VACT_OK : VACT_BAD, ok, ok ? NULL : detail);

    check_probe(c, &r);

    /* The body. */
    if (c->expect_body == HBODY_BODYABSENT) {
        ok = r.body_len == 0;

        snprintf(detail, sizeof(detail),
                 "%d body bytes returned for a HEAD request", r.body_len);

        record(PHASE_REQUEST, ASPECT_BODY, c->method, HBODY_BODYABSENT,
               ok ? HBODY_BODYABSENT : HBODY_BODYECHOED, ok,
               ok ? NULL : detail);
    } else {
        ok = r.body_len == body_len &&
            (body_len == 0 ||
             memcmp(r.buf + r.hdr_end, body, body_len) == 0);

        snprintf(detail, sizeof(detail),
                 "%d body bytes returned, sent %d", r.body_len, body_len);

        record(PHASE_REQUEST, ASPECT_BODY, c->method, HBODY_BODYECHOED,
               ok ? HBODY_BODYECHOED : HBODY_BODYANY, ok, ok ? NULL : detail);
    }

    /* An HTTP/1.0 server may only say keep-alive to a client that asked. */
    if (c->conn == HCONN_CONNDEFAULT) {
        echo = rsp_header(&r, "Connection");
        ok   = !(echo && strcasecmp(echo, "keep-alive") == 0);

        record(PHASE_REQUEST, ASPECT_KEEPALIVE, c->conn, VACT_OK,
               ok ? VACT_OK : VACT_BAD, ok, ok ? NULL :
               "unsolicited 'Connection: keep-alive' on an HTTP/1.0 response");
    }

    /* And it must close unless it did say so. */
    if (want_close) {
        if (c->expect_persist == HPERSIST_MUSTCLOSE) {
            ok = r.eof;
        } else {
            echo = rsp_header(&r, "Connection");
            ok   = r.eof || (echo && strcasecmp(echo, "keep-alive") == 0);
        }

        record(PHASE_REQUEST, ASPECT_PERSIST, c->conn, PACT_CLOSED,
               r.eof ? PACT_CLOSED : PACT_OPEN, ok, ok ? NULL :
               "the connection was still open after the response");
    }

 out:
    wb_free(&wb);
    close(fd);
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
 */
static void
build_defect(
    struct wirebuf *wb,
    int             defect,
    int            *half_close)
{
    char line[256];
    int  i;

    *half_close = 0;

    switch (defect) {
        case HDEF_NODEFECT:
            wb_str(wb, "GET " URI_PATH " HTTP/1.0\r\n"
                   PROBE_NAME ": " PROBE_VALUE "\r\n\r\n");
            break;

        case HDEF_METHODUNKNOWN:
            wb_str(wb, "FROB " URI_PATH " HTTP/1.0\r\n\r\n");
            break;

        case HDEF_METHODLOWERCASE:
            wb_str(wb, "get " URI_PATH " HTTP/1.0\r\n\r\n");
            break;

        case HDEF_METHODEMPTY:
            wb_str(wb, " " URI_PATH " HTTP/1.0\r\n\r\n");
            break;

        case HDEF_REQUESTLINEONETOKEN:
            wb_str(wb, "GET\r\n\r\n");
            break;

        case HDEF_REQUESTLINEEXTRATOKEN:
            wb_str(wb, "GET " URI_PATH " HTTP/1.0 trailing\r\n\r\n");
            break;

        case HDEF_REQUESTLINENOVERSION:
            /* An HTTP/0.9 Simple-Request: the request line alone, with no
             * version and therefore no header block to terminate. */
            wb_str(wb, "GET " URI_PATH "\r\n");
            break;

        case HDEF_VERSIONMALFORMED:
            wb_str(wb, "GET " URI_PATH " HTTP/1\r\n\r\n");
            break;

        case HDEF_VERSIONMAJORUNSUPPORTED:
            wb_str(wb, "GET " URI_PATH " HTTP/2.0\r\n\r\n");
            break;

        case HDEF_VERSIONMINORUNKNOWN:
            wb_str(wb, "GET " URI_PATH " HTTP/1.9\r\n\r\n");
            break;

        case HDEF_URITOOLONG:
            wb_str(wb, "GET /");
            wb_fill(wb, 'a', MAX_HEADER_LINE * 2);
            wb_str(wb, " HTTP/1.0\r\n\r\n");
            break;

        case HDEF_HEADERNOCOLON:
            wb_str(wb, "GET " URI_PATH " HTTP/1.0\r\n"
                   "ThisIsNotAHeaderField\r\n\r\n");
            break;

        case HDEF_HEADERNAMEEMPTY:
            wb_str(wb, "GET " URI_PATH " HTTP/1.0\r\n"
                   ": value\r\n\r\n");
            break;

        case HDEF_HEADERSPACEBEFORECOLON:
            wb_str(wb, "GET " URI_PATH " HTTP/1.0\r\n"
                   PROBE_NAME " : " PROBE_VALUE "\r\n\r\n");
            break;

        case HDEF_HEADERLINEOVERLONG:
            /* One field longer than the parser's line buffer, but a block
             * that would otherwise be well inside max_header_size: the line
             * is what overflows, not the block. */
            wb_str(wb, "GET " URI_PATH " HTTP/1.0\r\nX-Long: ");
            wb_fill(wb, 'a', MAX_HEADER_LINE + 64);
            wb_str(wb, "\r\n\r\n");
            break;

        case HDEF_HEADERBLOCKOVERLONG:
            /* The mirror image: every line is comfortably short, and it is
             * their total that passes max_header_size. */
            wb_str(wb, "GET " URI_PATH " HTTP/1.0\r\n");

            for (i = 0; i * 128 < MAX_HEADER_SIZE + 512; i++) {
                snprintf(line, sizeof(line), "X-Fill-%03d: ", i);
                wb_str(wb, line);
                wb_fill(wb, 'a', 128 - (int) strlen(line) - 2);
                wb_str(wb, "\r\n");
            }

            wb_str(wb, "\r\n");
            break;

        case HDEF_HEADERBLOCKUNTERMINATED:
            wb_str(wb, "GET " URI_PATH " HTTP/1.0\r\n"
                   PROBE_NAME ": " PROBE_VALUE "\r\n");
            *half_close = 1;
            break;

        case HDEF_BARELFLINEENDINGS:
            wb_str(wb, "GET " URI_PATH " HTTP/1.0\n"
                   PROBE_NAME ": " PROBE_VALUE "\n\n");
            break;

        case HDEF_CONTENTLENGTHNOTNUMERIC:
            wb_str(wb, "POST " URI_PATH " HTTP/1.0\r\n"
                   "Content-Length: not-a-number\r\n\r\n");
            break;

        case HDEF_CONTENTLENGTHNEGATIVE:
            wb_str(wb, "POST " URI_PATH " HTTP/1.0\r\n"
                   "Content-Length: -1\r\n\r\n");
            break;

        case HDEF_CONTENTLENGTHDUPLICATECONFLICTING:
            /* Two lengths, and the body is as long as the first: a server
             * that takes the second waits forever, one that takes the first
             * leaves three bytes to be read as the next request. */
            wb_str(wb, "POST " URI_PATH " HTTP/1.0\r\n"
                   "Content-Length: 5\r\n"
                   "Content-Length: 8\r\n\r\nabcde");
            break;

        case HDEF_BODYSHORTOFCONTENTLENGTH:
            wb_str(wb, "POST " URI_PATH " HTTP/1.0\r\n"
                   "Content-Length: 32\r\n\r\nshort");
            *half_close = 1;
            break;

        case HDEF_POSTWITHOUTCONTENTLENGTH:
            wb_str(wb, "POST " URI_PATH " HTTP/1.0\r\n"
                   PROBE_NAME ": " PROBE_VALUE "\r\n\r\n");
            break;

        default:
            fprintf(stderr, "defect %d has no wire encoding; add one to "
                    "build_defect()\n", defect);
            exit(1);
    } /* switch */
} /* build_defect */

/*
 * Whether an observed outcome satisfies the model's expectation.  Status(n)
 * is exact; NotSuccess is the arm for the shapes RFC 1945 does not pin down,
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
    struct rawrsp  r;
    char           detail[256];
    int            fd, half_close, actual, ok;

    fd = connect_raw();

    if (fd < 0) {
        fprintf(stderr, "defect case %s: connect failed: %s\n",
                http_defect_name(c->defect), strerror(errno));
        g_results.unexpected++;
        return;
    }

    g_results.defect_run++;

    wb_init(&wb);
    build_defect(&wb, c->defect, &half_close);

    deliver(fd, &wb, c->delivery);

    if (half_close) {
        shutdown(fd, SHUT_WR);
    }

    /* A defect response never carries an echoed body, and every defect case
     * expects the connection to close, so the close wait is affordable here
     * and is what distinguishes "refused and released" from "refused and
     * held". */
    read_response(&r, fd, 0, 1);

    actual = classify(&r);
    ok     = outcome_matches(c, actual);

    snprintf(detail, sizeof(detail), "%s, %s -> %s",
             http_defect_name(c->defect), http_delivery_name(c->delivery),
             outcome_name(actual));

    /* The expectation key is the required status where the model names one,
     * and the negated outcome tag where it does not -- status codes are
     * positive, so the two can never collide and a divergence row stays
     * readable as either "expected 400" or "expected NotSuccess". */
    record(PHASE_DEFECT, ASPECT_STATUS, c->defect,
           c->expect == HOUT_STATUS ? c->expect_status : -c->expect,
           actual, ok, ok ? NULL : detail);

    check_framing(PHASE_DEFECT, c->defect, &r);

    /* RFC 1945 section 1.4: whatever the answer, the connection ends with it.
     * A server that refuses a request and then holds the connection open has
     * left a peer it has already decided it cannot talk to holding a
     * resource. */
    if (actual != ACT_NORESPONSE && actual != ACT_STALLED) {
        record(PHASE_DEFECT, ASPECT_PERSIST, c->defect, PACT_CLOSED,
               r.eof ? PACT_CLOSED : PACT_OPEN, r.eof, r.eof ? NULL :
               "the connection was still open after the response");
    }

    wb_free(&wb);
    close(fd);
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
* main
* ------------------------------------------------------------------ */

static void
report(void)
{
    int i;

    fprintf(stderr,
            "\nhttp/1.0 conformance: %d/%u request cases (%d checks, %d "
            "failed), %d/%u defect cases (%d checks, %d failed)\n",
            g_results.request_run, (unsigned int) HTTP_NUM_REQUEST_CASES,
            g_results.request_checks, g_results.request_failed,
            g_results.defect_run, (unsigned int) HTTP_NUM_DEFECT_CASES,
            g_results.defect_checks, g_results.defect_failed);

    if (g_num_observed) {
        fprintf(stderr, "\ndivergences from RFC 1945:\n");
    }

    for (i = 0; i < g_num_observed; i++) {
        fprintf(stderr, "  %-6s %-12s %-28s expected %5d, got %5d  x%-4d %s\n",
                g_observed[i].phase == PHASE_REQUEST ? "req" : "defect",
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

    evpl_init(NULL);

    server.run = 0;

    pthread_create(&server.thread, NULL, server_function, &server);

    while (!server.run) {
        __sync_synchronize();
    }

    run_request_phase();
    run_defect_phase();

    server.run = 0;
    __sync_synchronize();
    evpl_ring_doorbell(&server.doorbell);
    pthread_join(server.thread, NULL);

    report();

    return g_results.unexpected ? 1 : 0;
} /* main */
