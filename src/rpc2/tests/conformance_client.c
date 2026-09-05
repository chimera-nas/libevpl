/*
 * SPDX-FileCopyrightText: 2026 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Model-based conformance test for the RPC2 *client*.
 *
 * conformance.c drives libevpl's server with malformed calls.  This is its
 * mirror image, and it exists because inverting the harness is the only way to
 * reach the client's inbound path: a real server never produces a reply for an
 * xid nobody sent, a truncated result, or a MSG_DENIED with a decodable body
 * bolted on, so nothing that talks to a real server can test what the client
 * does with one.
 *
 * The harness is a hostile server: a raw TCP listener that a genuine libevpl
 * rpc2 client connects to.  For each case it reads the client's CALL, takes
 * the xid, and writes back exactly the bytes the model asked for.  The oracle
 * is the client's own reply callback -- its status argument, or its failure to
 * fire at all.
 *
 * Cases come from quint/client.qnt via a build step (client_cases.h).  Each
 * carries two predictions:
 *
 *   - the required callback outcome (success / decode error / some failure /
 *     no callback for this reply);
 *   - whether the connection must survive, checked by completing an ordinary
 *     call on it afterwards.  That probe is also what distinguishes "the
 *     client correctly ignored this reply" from "the client is wedged".
 *
 * The model encodes the SPECIFICATION, so a mismatch is a candidate bug in
 * libevpl rather than a broken test.  Reviewed, consciously deferred
 * divergences go in known_divergences[] with a note; anything else fails.
 *
 * TCP-only by construction: the whole point is hand-built record-marked bytes,
 * which do not exist on the RDMA transports.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <fcntl.h>
#include <time.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>

/* The raw-socket helpers below drive a peer directly, without going through
 * libevpl, so they have to handle the same portability wrinkles it does:
 * SOCK_NONBLOCK and MSG_NOSIGNAL are Linux extensions, and the BSDs spell them
 * as an fcntl() and the SO_NOSIGPIPE socket option.  This harness is only
 * registered where quint is present, which today means Linux, but keeping it
 * portable leaves that a property of the toolchain rather than of the code. */
#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif /* ifndef MSG_NOSIGNAL */

/* Non-blocking, and no SIGPIPE when the peer goes away. */
static int
raw_socket_prepare(int fd)
{
    int flags;

#ifdef SO_NOSIGPIPE
    int one = 1;

    setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &one, sizeof(one));
#endif /* ifdef SO_NOSIGPIPE */

    flags = fcntl(fd, F_GETFL, 0);

    if (flags < 0 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return -1;
    }

    return 0;
} /* raw_socket_prepare */

#include "evpl/evpl.h"
#include "evpl/evpl_rpc2.h"
#include "evpl/evpl_rpc2_gss.h"

#include "krb5_local.h"

#include "core/test_log.h"
#include "test_common.h"

#include "conformance_client_xdr.h"
#include "client_cases.h"

static int port = 8000;

/* RPC envelope constants (RFC 5531 section 9), spelled out here rather than
 * pulled from the generated rpc2 header: this file must be able to encode
 * values the enums do not name. */
#define RPC_CALL            0
#define RPC_REPLY           1
#define RPC_MSG_ACCEPTED    0
#define RPC_MSG_DENIED      1
#define RPC_SUCCESS         0
#define RPC_RPC_MISMATCH    0
#define RPC_AUTH_ERROR      1
#define RPC_AUTH_BADCRED    1
#define RPC_AUTH_NONE       0
#define RPC_AUTH_SYS        1
#define RPC_RPCSEC_GSS      6

/* hello_world.x, which this test reuses unmodified. */
#define HELLO_PROG          42
#define HELLO_VERS          1
#define HELLO_PROC_GREET    1

#define CALL_ID             42
#define CALL_GREETING       "Hello from client!"
#define REPLY_ID            100
#define REPLY_GREETING      "Hello from the hostile server!"

/*
 * Outcomes the driver can observe that the model has no name for.  CEXP_*
 * codes come from the model; these extend the same space so a divergence can
 * be reported as one pair of names.
 */
#define ACT_NO_CALLBACK     100    /* deadline passed, connection still up   */
#define ACT_CONN_LOST       101    /* connection died, callback never fired  */
#define ACT_WRONG_VALUE     102    /* status 0 but the results did not match */
#define ACT_DOUBLE_CALLBACK 103    /* one call completed more than once      */

/*
 * Wall-clock budget for one exchange.  Loopback replies land in microseconds,
 * so anything approaching this is a client that has stopped making progress.
 * Kept small because the CbDropped cases are expected to hit it.
 */
#define REPLY_TIMEOUT_MS    300

/* Budget for the connect/accept handshake, which involves no RPC at all. */
#define ACCEPT_TIMEOUT_MS   2000

/* ------------------------------------------------------------------ *
* Known divergences from the specification
*
* Each entry records a case where libevpl's behaviour differs from what the
* model requires, so the suite can stay green while the gap remains visible.
* Removing an entry turns the corresponding case back into a hard failure,
* which is what should happen once the underlying issue is fixed.
* ------------------------------------------------------------------ */

struct known_divergence {
    int         defect;   /* CDEF_* */
    int         expect;   /* CEXP_*, what the model requires */
    int         actual;   /* CEXP_ or ACT_ code: what libevpl does today */
    const char *note;
};

/* Empty: the two bugs this harness found on its first run -- the client
 * ignoring reply_stat/accept_stat, and disconnect freeing pending calls
 * without firing their callbacks -- are both fixed in rpc2.c, so every case
 * now has to match the model on its own merits.
 */
static const struct known_divergence known_divergences[] = {
    { -1, -1, -1, NULL },
};

static int
is_known_divergence(
    int defect,
    int expect,
    int actual)
{
    unsigned int i;

    for (i = 0; i < sizeof(known_divergences) / sizeof(known_divergences[0]); i++) {
        if (known_divergences[i].defect == defect &&
            known_divergences[i].expect == expect &&
            known_divergences[i].actual == actual) {
            return 1;
        }
    }
    return 0;
} /* is_known_divergence */

static const char *
defect_name(int d)
{
    switch (d) {
        case CDEF_REPLYWELLFORMED:           return "ReplyWellFormed";
        case CDEF_REPLYVERFAUTHSYS:          return "ReplyVerfAuthSys";
        case CDEF_REPLYSPLITACROSSFRAGMENTS: return "ReplySplitAcrossFragments";
        case CDEF_REPLYUNKNOWNXID:           return "ReplyUnknownXid";
        case CDEF_REPLYDUPLICATED:           return "ReplyDuplicated";
        case CDEF_REPLYISACALL:              return "ReplyIsACall";
        case CDEF_REPLYHEADERTRUNCATED:      return "ReplyHeaderTruncated";
        case CDEF_REPLYMTYPEUNDEFINED:       return "ReplyMtypeUndefined";
        case CDEF_REPLYVERFBODYOVERLONG:     return "ReplyVerfBodyOverlong";
        case CDEF_PEERCLOSESWITHOUTREPLY:    return "PeerClosesWithoutReply";
        case CDEF_REPLYREJECTEDAUTH:         return "ReplyRejectedAuth";
        case CDEF_REPLYREJECTEDRPCMISMATCH:  return "ReplyRejectedRpcMismatch";
        case CDEF_REPLYACCEPTSTAT:           return "ReplyAcceptStat";
        case CDEF_REPLYDENIEDWITHBODY:       return "ReplyDeniedWithBody";
        case CDEF_REPLYACCEPTSTATWITHBODY:   return "ReplyAcceptStatWithBody";
        case CDEF_REPLYSTATUNDEFINED:        return "ReplyStatUndefined";
        case CDEF_REPLYEMPTYBODY:            return "ReplyEmptyBody";
        case CDEF_REPLYTRUNCATEDBODY:        return "ReplyTruncatedBody";
        case CDEF_REPLYTRAILINGGARBAGE:      return "ReplyTrailingGarbage";
        case CDEF_REPLYGARBAGEBODY:          return "ReplyGarbageBody";
        case CDEF_REPLYSTRINGLENOVERFLOW:    return "ReplyStringLenOverflow";
        case CDEF_REPLYSTRINGLENBEYONDMESSAGE: return "ReplyStringLenBeyondMessage";
        case CDEF_GSSINTEGREPLYVALID:        return "GssIntegReplyValid";
        case CDEF_GSSPRIVREPLYVALID:         return "GssPrivReplyValid";
        case CDEF_GSSINTEGREPLYCHECKSUMBAD:  return "GssIntegReplyChecksumBad";
        case CDEF_GSSPRIVREPLYSEALCORRUPT:   return "GssPrivReplySealCorrupt";
        case CDEF_GSSINTEGREPLYSEQMISMATCH:  return "GssIntegReplySeqMismatch";
        case CDEF_GSSPRIVREPLYSEQMISMATCH:   return "GssPrivReplySeqMismatch";
        case CDEF_GSSINTEGREPLYLENGTHBEYONDMESSAGE:
            return "GssIntegReplyLengthBeyondMessage";
        case CDEF_GSSINTEGREPLYCHECKSUMMISSING:
            return "GssIntegReplyChecksumMissing";
        case CDEF_GSSINTEGREPLYUNPROTECTED:  return "GssIntegReplyUnprotected";
        case CDEF_GSSPRIVREPLYUNPROTECTED:   return "GssPrivReplyUnprotected";
        default:                             return "?";
    } /* switch */
} /* defect_name */

static const char *
outcome_name(int o)
{
    switch (o) {
        case CEXP_CBSUCCESS:     return "CALLBACK_OK";
        case CEXP_CBDECODEERROR: return "CALLBACK_DECODE_ERROR";
        case CEXP_CBFAILED:      return "CALLBACK_FAILED";
        case CEXP_CBDROPPED:     return "REPLY_DROPPED";
        case ACT_NO_CALLBACK:    return "NO_CALLBACK";
        case ACT_CONN_LOST:      return "CONN_LOST_CALLBACK_LOST";
        case ACT_WRONG_VALUE:    return "WRONG_VALUE";
        case ACT_DOUBLE_CALLBACK: return "DOUBLE_CALLBACK";
        default:                 return "?";
    } /* switch */
} /* outcome_name */

static const char *
delivery_name(int d)
{
    switch (d) {
        case CDLV_ONEWRITE:  return "one-write";
        case CDLV_TWOWRITES: return "two-writes";
        case CDLV_DRIBBLE:   return "dribble";
        default:             return "?";
    } /* switch */
} /* delivery_name */

/* ------------------------------------------------------------------ *
* Shared state
* ------------------------------------------------------------------ */

struct results {
    int run;
    int matched;
    int known;
    int unknown;
    /* Matches broken down by the outcome the model asked for.  A run that
     * "passed" without ever reaching a callback would look identical to a
     * healthy one in the totals alone; this is what makes the positive
     * coverage visible in the output. */
    int matched_by_expect[4];
};

static struct results g_results;

/* Deterministic filler for the garbage-body cases. */
#define MAX_PAYLOAD 256
static uint8_t        g_pattern[MAX_PAYLOAD];

static void
pattern_init(void)
{
    unsigned int i;

    for (i = 0; i < MAX_PAYLOAD; i++) {
        g_pattern[i] = (uint8_t) (i * 7 + 13);
    }
} /* pattern_init */

static uint64_t
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
} /* now_ms */

/* ------------------------------------------------------------------ *
* The client under test
* ------------------------------------------------------------------ */

/* What one outstanding call observed.  A call may only ever complete once, so
 * `fired` is a count and not a flag: a second completion is itself a defect
 * this harness is in a position to see. */
struct call_state {
    int      fired;
    int      status;
    int      matched;
    /* Copied out for the failure message: a value that came back wrong is far
     * more useful reported than counted. */
    uint32_t got_id;
    char     got_greeting[80];
};

/*
 * Call state outlives the call that owns it.
 *
 * A case whose reply the client is required to ignore leaves its call
 * outstanding on purpose, and libevpl completes every still-pending call when
 * the connection goes down -- which can be several cases later.  So the state a
 * callback writes into cannot live on the stack frame of the case that started
 * the call: by the time the completion arrives that frame is gone, and the
 * address has been reused by a later case's state.  Allocate it instead, and
 * keep every allocation on a list to be released at the end of the run so the
 * ASan build stays quiet.
 */
static struct call_state *g_call_states[512];
static int                g_num_call_states;

static struct call_state *
call_state_alloc(void)
{
    struct call_state *cs = calloc(1, sizeof(*cs));

    evpl_test_abort_if(!cs, "out of memory allocating call state");
    evpl_test_abort_if(g_num_call_states >= (int) (sizeof(g_call_states) / sizeof(g_call_states[0])),
                       "call state table exhausted; raise g_call_states[]");

    g_call_states[g_num_call_states++] = cs;
    return cs;
} /* call_state_alloc */

static void
call_states_release(void)
{
    int i;

    for (i = 0; i < g_num_call_states; i++) {
        free(g_call_states[i]);
    }
    g_num_call_states = 0;
} /* call_states_release */

static void
client_reply_cb(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct Hello                *reply,
    int                          status,
    void                        *private_data)
{
    struct call_state *cs = private_data;

    cs->fired++;
    cs->status = status;

    /* The contract is that a non-zero status means the reply argument is not
     * to be touched, so this deliberately checks status first -- a client that
     * hands back a half-decoded value with a failure status would be caught by
     * the value comparison never running rather than by a crash here. */
    if (status == 0 && reply && reply->greeting.str) {
        cs->got_id = reply->id;
        snprintf(cs->got_greeting, sizeof(cs->got_greeting), "%.*s",
                 (int) reply->greeting.len, reply->greeting.str);

        cs->matched = (reply->id == REPLY_ID) &&
            strcmp(cs->got_greeting, REPLY_GREETING) == 0;
    }
} /* client_reply_cb */

static struct HELLO_V1        g_prog;
static struct evpl_rpc2_conn *g_conn;
static int                    g_conn_alive;

/*
 * The connection's liveness is not observable from the conn pointer -- rpc2
 * frees it on disconnect -- so it is tracked from the notify callback.  Every
 * subsequent use of g_conn is gated on this, which is also what turns "the
 * client hung up" into an observation rather than a use-after-free.
 */
static void
client_notify_cb(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_conn   *conn,
    struct evpl_rpc2_notify *notify,
    void                    *private_data)
{
    if (notify->notify_type == EVPL_RPC2_NOTIFY_DISCONNECTED &&
        conn == g_conn) {
        g_conn_alive = 0;
    }
} /* client_notify_cb */

static void
issue_call_cred(
    struct evpl                 *evpl,
    struct call_state           *cs,
    const struct evpl_rpc2_cred *cred)
{
    struct Hello request;

    memset(cs, 0, sizeof(*cs));
    memset(&request, 0, sizeof(request));

    request.id = CALL_ID;
    xdr_set_str_static(&request, greeting, CALL_GREETING,
                       strlen(CALL_GREETING));

    g_prog.send_call_GREET(&g_prog.rpc2, evpl, g_conn, cred, &request,
                           0, 0, NULL, 0, 0, client_reply_cb, cs);
} /* issue_call_cred */

static void
issue_call(
    struct evpl       *evpl,
    struct call_state *cs)
{
    issue_call_cred(evpl, cs, NULL);
} /* issue_call */

/* ------------------------------------------------------------------ *
* Wire byte assembly, borrowed wholesale from conformance.c
* ------------------------------------------------------------------ */

struct wirebuf {
    uint8_t  data[2048];
    uint32_t len;
};

static void
put32(
    struct wirebuf *b,
    uint32_t        v)
{
    evpl_test_abort_if(b->len + 4 > sizeof(b->data), "wire buffer overflow");
    b->data[b->len++] = (uint8_t) (v >> 24);
    b->data[b->len++] = (uint8_t) (v >> 16);
    b->data[b->len++] = (uint8_t) (v >> 8);
    b->data[b->len++] = (uint8_t) v;
} /* put32 */

static void
put_bytes(
    struct wirebuf *b,
    const void     *src,
    uint32_t        n)
{
    uint32_t pad = (4 - (n & 3)) & 3;

    evpl_test_abort_if(b->len + n + pad > sizeof(b->data), "wire buffer overflow");
    memcpy(b->data + b->len, src, n);
    b->len += n;
    memset(b->data + b->len, 0, pad);
    b->len += pad;
} /* put_bytes */

static uint32_t
get32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16) |
           ((uint32_t) p[2] << 8) | (uint32_t) p[3];
} /* get32 */

/* struct Hello { unsigned int id; string greeting; } */
static void
put_hello(struct wirebuf *b)
{
    put32(b, REPLY_ID);
    put32(b, (uint32_t) strlen(REPLY_GREETING));
    put_bytes(b, REPLY_GREETING, (uint32_t) strlen(REPLY_GREETING));
} /* put_hello */

/* xid, REPLY, MSG_ACCEPTED, AUTH_NONE verifier, SUCCESS. */
static void
put_accepted_header(
    struct wirebuf *b,
    uint32_t        xid)
{
    put32(b, xid);
    put32(b, RPC_REPLY);
    put32(b, RPC_MSG_ACCEPTED);
    put32(b, RPC_AUTH_NONE);
    put32(b, 0);
    put32(b, RPC_SUCCESS);
} /* put_accepted_header */

/* xid, REPLY, MSG_ACCEPTED, AUTH_NONE verifier, <stat> (+ range for
 * PROG_MISMATCH, which is the one accept_stat carrying a body of its own). */
static void
put_accepted_error_header(
    struct wirebuf *b,
    uint32_t        xid,
    uint32_t        stat)
{
    put32(b, xid);
    put32(b, RPC_REPLY);
    put32(b, RPC_MSG_ACCEPTED);
    put32(b, RPC_AUTH_NONE);
    put32(b, 0);
    put32(b, stat);

    if (stat == 2) {  /* PROG_MISMATCH carries mismatch_info */
        put32(b, HELLO_VERS);
        put32(b, HELLO_VERS);
    }
} /* put_accepted_error_header */

static void
put_denied_auth_header(
    struct wirebuf *b,
    uint32_t        xid)
{
    put32(b, xid);
    put32(b, RPC_REPLY);
    put32(b, RPC_MSG_DENIED);
    put32(b, RPC_AUTH_ERROR);
    put32(b, RPC_AUTH_BADCRED);
} /* put_denied_auth_header */

/*
 * Assemble the reply message (no record mark) for one case.
 *
 * `xid` is the one the client actually chose for the outstanding call, read
 * back off the wire -- the client owns xid allocation, so guessing it is not
 * an option and the unknown-xid case is built by perturbing it.
 */
static void
build_reply(
    struct wirebuf           *b,
    const struct client_case *c,
    uint32_t                  xid)
{
    uint32_t body_start;

    b->len = 0;

    switch (c->defect) {
        case CDEF_REPLYWELLFORMED:
        case CDEF_REPLYDUPLICATED:
        case CDEF_REPLYSPLITACROSSFRAGMENTS:
            put_accepted_header(b, xid);
            put_hello(b);
            break;

        case CDEF_REPLYVERFAUTHSYS:
            /* A reply verifier that is not AUTH_NONE is legal and must decode:
             * flavor, body length, then authsys_parms (stamp, machinename,
             * uid, gid, gids<16>) -- 24 bytes with a one-character name. */
            put32(b, xid);
            put32(b, RPC_REPLY);
            put32(b, RPC_MSG_ACCEPTED);
            put32(b, RPC_AUTH_SYS);
            put32(b, 24);
            put32(b, 1);              /* stamp                   */
            put32(b, 1);              /* machinename.len         */
            put_bytes(b, "h", 1);
            put32(b, 0);              /* uid                     */
            put32(b, 0);              /* gid                     */
            put32(b, 0);              /* gids.len                */
            put32(b, RPC_SUCCESS);
            put_hello(b);
            break;

        case CDEF_REPLYUNKNOWNXID:
            /* Perturbed rather than fixed: it must miss every xid the client
             * has ever issued on this connection, and the client counts up
             * from 1. */
            put_accepted_header(b, xid ^ 0x5a5a5a5au);
            put_hello(b);
            break;

        case CDEF_REPLYISACALL:
            put32(b, xid ^ 0x5a5a5a5au);
            put32(b, RPC_CALL);
            put32(b, 2);              /* rpcvers                 */
            put32(b, HELLO_PROG);
            put32(b, HELLO_VERS);
            put32(b, 0);              /* proc: NULL              */
            put32(b, RPC_AUTH_NONE);
            put32(b, 0);
            put32(b, RPC_AUTH_NONE);
            put32(b, 0);
            break;

        case CDEF_REPLYHEADERTRUNCATED:
            put_accepted_header(b, xid);
            put_hello(b);
            b->len = (uint32_t) c->param;
            break;

        case CDEF_REPLYMTYPEUNDEFINED:
            put32(b, xid);
            put32(b, (uint32_t) c->param);
            put_hello(b);
            break;

        case CDEF_REPLYVERFBODYOVERLONG:
            put32(b, xid);
            put32(b, RPC_REPLY);
            put32(b, RPC_MSG_ACCEPTED);
            put32(b, RPC_AUTH_NONE);
            put32(b, 8);              /* claims 8 bytes AUTH_NONE cannot have */
            put32(b, 0xdeadbeefu);
            put32(b, 0xcafebabeu);
            put32(b, RPC_SUCCESS);
            put_hello(b);
            break;

        case CDEF_PEERCLOSESWITHOUTREPLY:
            /* No bytes at all; the caller closes the socket instead. */
            break;

        case CDEF_REPLYREJECTEDAUTH:
            put_denied_auth_header(b, xid);
            break;

        case CDEF_REPLYREJECTEDRPCMISMATCH:
            put32(b, xid);
            put32(b, RPC_REPLY);
            put32(b, RPC_MSG_DENIED);
            put32(b, RPC_RPC_MISMATCH);
            put32(b, 2);              /* low                     */
            put32(b, 2);              /* high                    */
            break;

        case CDEF_REPLYACCEPTSTAT:
            put_accepted_error_header(b, xid, (uint32_t) c->param);
            break;

        case CDEF_REPLYDENIEDWITHBODY:
            put_denied_auth_header(b, xid);
            put_hello(b);
            break;

        case CDEF_REPLYACCEPTSTATWITHBODY:
            put_accepted_error_header(b, xid, (uint32_t) c->param);
            put_hello(b);
            break;

        case CDEF_REPLYSTATUNDEFINED:
            put32(b, xid);
            put32(b, RPC_REPLY);
            put32(b, (uint32_t) c->param);
            put_hello(b);
            break;

        case CDEF_REPLYEMPTYBODY:
            put_accepted_header(b, xid);
            break;

        case CDEF_REPLYTRUNCATEDBODY:
            put_accepted_header(b, xid);
            body_start = b->len;
            put_hello(b);
            b->len = body_start + (uint32_t) c->param;
            break;

        case CDEF_REPLYTRAILINGGARBAGE:
            put_accepted_header(b, xid);
            put_hello(b);
            put_bytes(b, g_pattern, (uint32_t) c->param);
            break;

        case CDEF_REPLYGARBAGEBODY:
            put_accepted_header(b, xid);
            put_bytes(b, g_pattern, 16);
            break;

        case CDEF_REPLYSTRINGLENOVERFLOW:
            put_accepted_header(b, xid);
            put32(b, REPLY_ID);
            put32(b, 0xffffffffu);
            break;

        case CDEF_REPLYSTRINGLENBEYONDMESSAGE:
            put_accepted_header(b, xid);
            put32(b, REPLY_ID);
            put32(b, 4096);           /* claims far more than follows */
            put_bytes(b, g_pattern, 4);
            break;

        default:
            evpl_test_abort("unhandled defect %u; the model gained a variant "
                            "the driver has no arm for", c->defect);
    } /* switch */
} /* build_reply */

/* ------------------------------------------------------------------ *
* The hostile server: a raw TCP listener
* ------------------------------------------------------------------ */

static int g_listen_fd = -1;
static int g_peer_fd   = -1;

static int
listen_raw(int listen_port)
{
    struct sockaddr_in addr;
    int                fd, flag = 1;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        return -1;
    }

    if (raw_socket_prepare(fd) < 0) {
        close(fd);
        return -1;
    }

    setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &flag, sizeof(flag));

    memset(&addr, 0, sizeof(addr));
    addr.sin_family      = AF_INET;
    addr.sin_port        = htons(listen_port);
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);

    if (bind(fd, (struct sockaddr *) &addr, sizeof(addr)) < 0 ||
        listen(fd, 8) < 0) {
        close(fd);
        return -1;
    }

    return fd;
} /* listen_raw */

/*
 * Everything below shares one event loop with the client under test, so it may
 * never block on the socket: the peer that owes it bytes is running on this
 * same thread and only runs while evpl_continue is being pumped.
 */
static int
accept_peer(struct evpl *evpl)
{
    uint64_t deadline = now_ms() + ACCEPT_TIMEOUT_MS;
    int      fd, flag = 1;

    for (;;) {
        fd = accept(g_listen_fd, NULL, NULL);
        if (fd >= 0) {
            fcntl(fd, F_SETFL, fcntl(fd, F_GETFL, 0) | O_NONBLOCK);
            setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
            return fd;
        }
        if (errno != EAGAIN && errno != EWOULDBLOCK) {
            return -1;
        }
        evpl_continue(evpl);
        if (now_ms() > deadline) {
            return -1;
        }
    }
} /* accept_peer */

static int
send_all(
    struct evpl *evpl,
    const void  *buf,
    size_t       len)
{
    const uint8_t *p        = buf;
    uint64_t       deadline = now_ms() + REPLY_TIMEOUT_MS;
    ssize_t        n;

    while (len) {
        n = send(g_peer_fd, p, len, MSG_NOSIGNAL);
        if (n > 0) {
            p   += n;
            len -= n;
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
            evpl_continue(evpl);
            if (now_ms() > deadline) {
                return -1;
            }
            continue;
        }
        return -1;
    }
    return 0;
} /* send_all */

#define READ_OK      0
#define READ_TIMEOUT (-1)
#define READ_EOF     (-2)

static int
read_exact(
    struct evpl *evpl,
    uint8_t     *buf,
    uint32_t     want,
    uint64_t     deadline)
{
    uint32_t off = 0;
    ssize_t  n;

    while (off < want) {
        n = recv(g_peer_fd, buf + off, want - off, 0);
        if (n == 0) {
            return READ_EOF;
        }
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                return READ_EOF;
            }
            evpl_continue(evpl);
            if (now_ms() > deadline) {
                return READ_TIMEOUT;
            }
            continue;
        }
        off += n;
    }
    return READ_OK;
} /* read_exact */

/* rpc_gss_proc_t (RFC 2203 sec 5.1) */
#define GSS_PROC_DATA          0
#define GSS_PROC_INIT          1
#define GSS_PROC_CONTINUE_INIT 2
#define GSS_PROC_DESTROY       3

static int
deliver(
    struct evpl              *evpl,
    const struct client_case *c,
    const struct wirebuf     *msg);

/*
 * Whether this call is a context retirement.
 *
 *   header:  xid, mtype, rpcvers, prog, vers, proc   (24 bytes)
 *   cred:    flavor, length, rpc_gss_cred_vers_1 { version, gss_proc, ... }
 */
static int
call_is_gss_destroy(
    const uint8_t *call,
    uint32_t       len)
{
    uint32_t cred_len;

    if (len < 32 + 8 || get32(call + 24) != RPC_RPCSEC_GSS) {
        return 0;
    }

    cred_len = get32(call + 28);

    if (cred_len < 8 || (uint64_t) 32 + cred_len > len) {
        return 0;
    }

    return get32(call + 36) == GSS_PROC_DESTROY;
} /* call_is_gss_destroy */

static int
answer_gss_destroy(
    struct evpl *evpl,
    uint32_t     xid)
{
    struct wirebuf     msg;
    struct client_case one = { 0, CDLV_ONEWRITE, 0, 0, -1 };

    msg.len = 0;
    put_accepted_header(&msg, xid);

    return deliver(evpl, &one, &msg);
} /* answer_gss_destroy */

/*
 * Read one record-marked message the client sent, returning only CALLs.
 *
 * The ReplyIsACall case provokes the client into answering with a REPLY of its
 * own (PROG_UNAVAIL: a client connection exports no programs).  Those replies
 * share the socket with the calls this harness is waiting for, so they are
 * skipped here rather than being mistaken for the next call and desyncing
 * every case that follows.
 */
static int
read_call(
    struct evpl *evpl,
    uint8_t     *buf,
    uint32_t     bufsz,
    uint32_t    *out_len,
    uint32_t    *out_xid)
{
    uint8_t  mark[4];
    uint32_t len;
    uint64_t deadline = now_ms() + REPLY_TIMEOUT_MS;
    int      rc;

    for (;;) {
        rc = read_exact(evpl, mark, 4, deadline);
        if (rc != READ_OK) {
            return rc;
        }

        len = get32(mark) & 0x7fffffffu;
        if (len > bufsz) {
            return READ_EOF;
        }

        rc = read_exact(evpl, buf, len, deadline);
        if (rc != READ_OK) {
            return rc;
        }

        if (len >= 8 && get32(buf + 4) == RPC_CALL) {
            /* A context being retired is not a call any case is waiting for.
             * It is answered and skipped here for the same reason the client's
             * own PROG_UNAVAIL replies are: whichever case happens to be
             * reading when it arrives would otherwise mistake it for its own
             * call and desync every case after it. */
            if (call_is_gss_destroy(buf, len)) {
                if (answer_gss_destroy(evpl, get32(buf))) {
                    return READ_EOF;
                }
                continue;
            }

            *out_len = len;
            *out_xid = get32(buf);
            return READ_OK;
        }
    }
} /* read_call */

/*
 * Put one assembled message on the wire.
 *
 * The delivery mode is part of the case: a defect that is only detected
 * because the whole record arrived in a single read is not really detected,
 * and the client's record-mark framing is precisely the code that has to cope
 * with byte-at-a-time arrival.
 */
static int
deliver(
    struct evpl              *evpl,
    const struct client_case *c,
    const struct wirebuf     *msg)
{
    uint8_t  rec[sizeof(msg->data) + 4];
    uint32_t total, half, i;

    rec[0] = (uint8_t) (0x80 | ((msg->len >> 24) & 0x7f));
    rec[1] = (uint8_t) (msg->len >> 16);
    rec[2] = (uint8_t) (msg->len >> 8);
    rec[3] = (uint8_t) msg->len;
    memcpy(rec + 4, msg->data, msg->len);
    total = msg->len + 4;

    switch (c->delivery) {
        case CDLV_ONEWRITE:
            return send_all(evpl, rec, total);

        case CDLV_TWOWRITES:
            half = total / 2;
            if (half == 0) {
                half = total;
            }
            if (send_all(evpl, rec, half)) {
                return -1;
            }
            /* Let the client observe the partial record before the rest
             * arrives; without this the kernel usually coalesces the two
             * writes and the split never happens. */
            evpl_continue(evpl);
            evpl_continue(evpl);
            return send_all(evpl, rec + half, total - half);

        case CDLV_DRIBBLE:
            for (i = 0; i < total; i++) {
                if (send_all(evpl, rec + i, 1)) {
                    return -1;
                }
                evpl_continue(evpl);
            }
            return 0;

        default:
            evpl_test_abort("unhandled delivery %u", c->delivery);
    } /* switch */

    return -1;
} /* deliver */

/*
 * Deliver one message as `n` record-mark fragments (RFC 5531 section 11).
 * Only the last carries the terminal bit, so this exercises the client's
 * inbound reassembly accumulator rather than its fast path.
 */
static int
deliver_fragmented(
    struct evpl          *evpl,
    const struct wirebuf *msg,
    uint32_t              nfrag)
{
    uint8_t  hdr[4];
    uint32_t off = 0, i, this_len, remaining;

    if (nfrag == 0 || nfrag > msg->len) {
        nfrag = msg->len ? msg->len : 1;
    }

    for (i = 0; i < nfrag; i++) {
        remaining = msg->len - off;
        this_len  = (i + 1 == nfrag) ? remaining : remaining / (nfrag - i);
        if (this_len == 0) {
            this_len = 1;
        }

        hdr[0] = (uint8_t) ((i + 1 == nfrag ? 0x80 : 0x00) |
                            ((this_len >> 24) & 0x7f));
        hdr[1] = (uint8_t) (this_len >> 16);
        hdr[2] = (uint8_t) (this_len >> 8);
        hdr[3] = (uint8_t) this_len;

        if (send_all(evpl, hdr, 4) ||
            send_all(evpl, msg->data + off, this_len)) {
            return -1;
        }

        evpl_continue(evpl);
        off += this_len;
    }

    return 0;
} /* deliver_fragmented */

/* ------------------------------------------------------------------ *
* Case execution
* ------------------------------------------------------------------ */

static struct evpl_rpc2_thread *g_thread;
static struct evpl_endpoint    *g_endpoint;

static int
ensure_conn(struct evpl *evpl)
{
    if (g_conn_alive) {
        return 0;
    }

    if (g_peer_fd >= 0) {
        close(g_peer_fd);
        g_peer_fd = -1;
    }

    g_conn = evpl_rpc2_client_connect(g_thread, EVPL_STREAM_SOCKET_TCP,
                                      g_endpoint, NULL, 0, NULL);
    if (!g_conn) {
        return -1;
    }
    g_conn_alive = 1;

    g_peer_fd = accept_peer(evpl);
    if (g_peer_fd < 0) {
        return -1;
    }

    return 0;
} /* ensure_conn */

/* Pump until the call completes, the connection dies, or the budget runs
 * out.  The deadline is what separates "the client correctly ignored this
 * reply" from "the client is stuck", and it is the only reason this loop is
 * bounded at all -- a dropped reply produces no event to wait on. */
static void
pump_until_fired(
    struct evpl       *evpl,
    struct call_state *cs)
{
    uint64_t deadline = now_ms() + REPLY_TIMEOUT_MS;

    while (!cs->fired && g_conn_alive && now_ms() < deadline) {
        evpl_continue(evpl);
    }
} /* pump_until_fired */

/* Complete an ordinary call on the connection.  Returns 1 if it round-tripped.
 * This is the evidence for "the connection is still usable", which is the
 * other half of every case whose reply the client is required to ignore. */
static int
probe_connection(struct evpl *evpl)
{
    struct call_state *cs = call_state_alloc();
    struct wirebuf     msg;
    uint8_t            buf[2048];
    uint32_t           len, xid;

    struct client_case one = { 0, CDLV_ONEWRITE, 0, 0, -1 };

    if (!g_conn_alive || g_peer_fd < 0) {
        return 0;
    }

    issue_call(evpl, cs);

    if (read_call(evpl, buf, sizeof(buf), &len, &xid) != READ_OK) {
        return 0;
    }

    msg.len = 0;
    put_accepted_header(&msg, xid);
    put_hello(&msg);

    if (deliver(evpl, &one, &msg)) {
        return 0;
    }

    pump_until_fired(evpl, cs);

    return cs->fired == 1 && cs->status == 0 && cs->matched;
} /* probe_connection */

/* ------------------------------------------------------------------ *
* RPCSEC_GSS replies: the harness as an acceptor
*
* Everything above is an unprotected call, so the client's GSS receive path --
* the one that has to open a wrapped reply before its decoder ever sees
* results -- is unreachable from here.  Reaching it means the hostile server
* has to hold up its end of a real context: answer the client's
* RPCSEC_GSS_INIT with an rpc_gss_init_res (RFC 2203 sec 5.2.3), then wrap
* what it sends back the way the negotiated service requires.
*
* krb5_local's acceptor half is used unmodified, so the checksums the client
* verifies are real ones from a real mechanism.  That is what makes a
* deliberately corrupted checksum meaningful: it is corrupt relative to a
* mechanism that would otherwise have accepted it, not relative to a stub
* that was going to say yes regardless.
* ------------------------------------------------------------------ */

#define GSS_HANDLE_VALUE 0x5eed1234u
#define GSS_SEQ_WINDOW   64

static struct krb5_local                   *g_kl;
static const struct evpl_rpc2_gss_provider *g_acc;
static void                                *g_acc_ctx;
static struct evpl_rpc2_gss_client         *g_gss;
static int                                  g_gss_ready;
static int                                  g_gss_failed;
static int                                  g_gss_skipped;

/* Which service each GSS defect is expressed under.  The wrapping is what the
 * case is about, so the service is a property of the defect rather than a
 * separate dimension: an unsealable token has no meaning under integrity. */
static int
gss_case_service(int defect)
{
    switch (defect) {
        case CDEF_GSSINTEGREPLYVALID:
        case CDEF_GSSINTEGREPLYCHECKSUMBAD:
        case CDEF_GSSINTEGREPLYSEQMISMATCH:
        case CDEF_GSSINTEGREPLYLENGTHBEYONDMESSAGE:
        case CDEF_GSSINTEGREPLYCHECKSUMMISSING:
        case CDEF_GSSINTEGREPLYUNPROTECTED:
            return EVPL_RPC2_GSS_SVC_INTEGRITY;
        case CDEF_GSSPRIVREPLYVALID:
        case CDEF_GSSPRIVREPLYSEALCORRUPT:
        case CDEF_GSSPRIVREPLYSEQMISMATCH:
        case CDEF_GSSPRIVREPLYUNPROTECTED:
            return EVPL_RPC2_GSS_SVC_PRIVACY;
        default:
            return -1;
    } /* switch */
} /* gss_case_service */

static int
is_gss_case(int defect)
{
    return gss_case_service(defect) >= 0;
} /* is_gss_case */

static void
gss_ready_cb(
    struct evpl_rpc2_gss_client *client,
    int                          status,
    void                        *arg)
{
    (void) arg;

    if (status) {
        g_gss_failed = 1;
    } else {
        g_gss       = client;
        g_gss_ready = 1;
    }
} /* gss_ready_cb */

/*
 * Answer one leg of the client's context establishment.
 *
 * The call is NULLPROC with an RPCSEC_GSS credential naming the procedure;
 * its argument is the initiator's token as a counted opaque.  The reply is
 * MSG_ACCEPTED/SUCCESS whose results are the rpc_gss_init_res, and -- once the
 * context is complete -- whose verifier is a MIC over the advertised
 * seq_window (RFC 2203 sec 5.2.3.1).
 *
 */
static int
gss_answer_init_leg(
    struct evpl   *evpl,
    const uint8_t *call,
    uint32_t       len,
    uint32_t       xid,
    int           *complete)
{
    struct wirebuf     msg;
    struct client_case one = { 0, CDLV_ONEWRITE, 0, 0, -1 };
    const uint8_t     *token;
    void              *out_token = NULL;
    void              *mic       = NULL;
    size_t             out_len   = 0, mic_len = 0;
    uint32_t           off, cred_len, verf_len, token_len, window_be;
    char               principal[256];

    /* xid, mtype, rpcvers, prog, vers, proc, then the two opaque_auths. */
    off = 24;
    if (len < off + 8) {
        return -1;
    }
    cred_len = get32(call + off + 4);

    if (cred_len < 16 || (uint64_t) off + 8 + cred_len > len) {
        return -1;
    }

    off += 8 + ((cred_len + 3) & ~3u);

    if (len < off + 8) {
        return -1;
    }
    verf_len = get32(call + off + 4);
    off     += 8 + ((verf_len + 3) & ~3u);

    if (len < off + 4) {
        return -1;
    }
    token_len = get32(call + off);
    token     = call + off + 4;

    if ((uint64_t) off + 4 + token_len > len) {
        return -1;
    }

    if (g_acc->accept(krb5_local_arg(g_kl), &g_acc_ctx, token, token_len,
                      &out_token, &out_len, complete,
                      principal, sizeof(principal))) {
        return -1;
    }

    msg.len = 0;
    put32(&msg, xid);
    put32(&msg, RPC_REPLY);
    put32(&msg, RPC_MSG_ACCEPTED);

    window_be = htonl(GSS_SEQ_WINDOW);

    if (*complete &&
        g_acc->get_mic(krb5_local_arg(g_kl), g_acc_ctx, &window_be,
                       sizeof(window_be), &mic, &mic_len) == 0) {
        put32(&msg, RPC_RPCSEC_GSS);
        put32(&msg, (uint32_t) mic_len);
        put_bytes(&msg, mic, (uint32_t) mic_len);
        free(mic);
    } else {
        put32(&msg, RPC_AUTH_NONE);
        put32(&msg, 0);
    }

    put32(&msg, RPC_SUCCESS);

    /* rpc_gss_init_res: handle, major, minor, seq_window, token. */
    put32(&msg, 4);
    put32(&msg, GSS_HANDLE_VALUE);
    put32(&msg, *complete ? 0 /* GSS_S_COMPLETE */ : 1 /* CONTINUE_NEEDED */);
    put32(&msg, 0);
    put32(&msg, GSS_SEQ_WINDOW);
    put32(&msg, (uint32_t) out_len);
    if (out_len) {
        put_bytes(&msg, out_token, (uint32_t) out_len);
    }

    free(out_token);

    return deliver(evpl, &one, &msg);
} /* gss_answer_init_leg */

/* Bring up a context on the current connection under `service`, playing the
 * acceptor by hand.  Returns 0 once the client reports it established. */
static int
gss_establish(
    struct evpl *evpl,
    uint32_t     service)
{
    uint8_t  buf[4096];
    uint32_t len, xid;
    int      complete = 0, guard;

    g_gss_ready  = 0;
    g_gss_failed = 0;
    g_acc_ctx    = NULL;

    evpl_rpc2_gss_client_create(evpl, &g_prog.rpc2, g_conn,
                                krb5_local_initiator_provider(),
                                krb5_local_arg(g_kl), service,
                                "conformance@localhost", gss_ready_cb, NULL);

    for (guard = 0; guard < 8 && !g_gss_ready && !g_gss_failed; guard++) {
        if (read_call(evpl, buf, sizeof(buf), &len, &xid) != READ_OK) {
            return -1;
        }

        if (gss_answer_init_leg(evpl, buf, len, xid, &complete)) {
            return -1;
        }

        evpl_continue(evpl);
        evpl_continue(evpl);
    }

    return g_gss_ready ? 0 : -1;
} /* gss_establish */

static void
gss_release(struct evpl *evpl)
{
    if (g_gss) {
        evpl_rpc2_gss_client_destroy(evpl, g_gss);
        g_gss = NULL;
    }

    if (g_acc_ctx) {
        g_acc->destroy(krb5_local_arg(g_kl), g_acc_ctx);
        g_acc_ctx = NULL;
    }
} /* gss_release */

/*
 * The sequence number the client put in the credential of the call it just
 * sent.  The reply has to echo it (RFC 2203 sec 5.3.3.2), and it is chosen by
 * the client, so it is read back off the wire rather than assumed.
 *
 *   rpc_gss_cred_vers_1: version, gss_proc, seq_num, service, handle<>
 */
static int
gss_call_seq(
    const uint8_t *call,
    uint32_t       len,
    uint32_t      *out_seq)
{
    uint32_t cred_len;

    if (len < 24 + 8) {
        return -1;
    }

    cred_len = get32(call + 28);

    if (cred_len < 16 || (uint64_t) 32 + cred_len > len) {
        return -1;
    }

    *out_seq = get32(call + 32 + 8);
    return 0;
} /* gss_call_seq */

/*
 * Build the reply body for a GSS case.
 *
 * Both services put a counted blob first: under integrity it is the plaintext
 * rpc_gss_data_t (seq_num followed by the results) with a checksum after it,
 * and under privacy it is that same plaintext sealed into a single token.
 * Every defect here is a deliberate deviation from one of those two shapes.
 */
static int
build_gss_reply(
    struct wirebuf           *b,
    const struct client_case *c,
    uint32_t                  xid,
    uint32_t                  seq)
{
    struct wirebuf plain;
    uint8_t        sealed[2048];
    void          *mic = NULL;
    size_t         mic_len = 0, sealed_len = 0;
    uint32_t       echoed = seq;
    uint32_t       seq_be;

    if (c->defect == CDEF_GSSINTEGREPLYSEQMISMATCH ||
        c->defect == CDEF_GSSPRIVREPLYSEQMISMATCH) {
        echoed = seq + 1;
    }

    /* rpc_gss_data_t, the plaintext both services are built around. */
    plain.len = 0;
    put32(&plain, echoed);
    put_hello(&plain);

    b->len = 0;
    put32(b, xid);
    put32(b, RPC_REPLY);
    put32(b, RPC_MSG_ACCEPTED);

    /* The reply verifier under an established context is a MIC over the
     * sequence number of the call being answered. */
    seq_be = htonl(seq);

    if (g_acc->get_mic(krb5_local_arg(g_kl), g_acc_ctx, &seq_be, sizeof(seq_be),
                       &mic, &mic_len) == 0) {
        put32(b, RPC_RPCSEC_GSS);
        put32(b, (uint32_t) mic_len);
        put_bytes(b, mic, (uint32_t) mic_len);
        free(mic);
        mic = NULL;
    } else {
        put32(b, RPC_AUTH_NONE);
        put32(b, 0);
    }

    put32(b, RPC_SUCCESS);

    /* The peer that simply left the protection off: results in the clear
     * where the service requires them wrapped. */
    if (c->defect == CDEF_GSSINTEGREPLYUNPROTECTED ||
        c->defect == CDEF_GSSPRIVREPLYUNPROTECTED) {
        put_hello(b);
        return 0;
    }

    if (gss_case_service(c->defect) == EVPL_RPC2_GSS_SVC_PRIVACY) {
        if (g_acc->wrap(krb5_local_arg(g_kl), g_acc_ctx, plain.data, plain.len,
                        sealed, sizeof(sealed), &sealed_len)) {
            return -1;
        }

        put32(b, (uint32_t) sealed_len);

        if (c->defect == CDEF_GSSPRIVREPLYSEALCORRUPT) {
            /* The last byte of the token, so the damage is inside the sealed
             * region for any wrap-token layout rather than in a header field
             * that a length check might reject first. */
            sealed[sealed_len - 1] ^= 0xff;
        }

        put_bytes(b, sealed, (uint32_t) sealed_len);
        return 0;
    }

    /* Integrity: databody_integ, then its checksum. */
    if (c->defect == CDEF_GSSINTEGREPLYLENGTHBEYONDMESSAGE) {
        /* A length that runs past the end of the record.  Nothing after it is
         * reachable, so no checksum is appended: the point is whether the
         * client trusts the length before it checks it. */
        put32(b, plain.len + 4096);
        put_bytes(b, plain.data, plain.len);
        return 0;
    }

    put32(b, plain.len);
    put_bytes(b, plain.data, plain.len);

    if (c->defect == CDEF_GSSINTEGREPLYCHECKSUMMISSING) {
        return 0;
    }

    if (g_acc->get_mic(krb5_local_arg(g_kl), g_acc_ctx, plain.data, plain.len,
                       &mic, &mic_len)) {
        return -1;
    }

    put32(b, (uint32_t) mic_len);

    if (c->defect == CDEF_GSSINTEGREPLYCHECKSUMBAD) {
        ((uint8_t *) mic)[mic_len - 1] ^= 0xff;
    }

    put_bytes(b, mic, (uint32_t) mic_len);
    free(mic);

    return 0;
} /* build_gss_reply */

/*
 * One GSS case: stand a context up on a fresh connection, make the call under
 * it, and answer with the bytes the case calls for.
 *
 * The context is rebuilt per case rather than shared.  A case that leaves the
 * client's replay window or its sequence counter in an unexpected state would
 * otherwise change the meaning of every case after it, and the failure would
 * be attributed to the wrong one.
 */
static int
run_gss_case(
    struct evpl              *evpl,
    const struct client_case *c,
    struct call_state        *cs)
{
    struct evpl_rpc2_cred cred;
    struct wirebuf        msg;
    uint8_t               buf[4096];
    uint32_t              len, xid, seq;
    int                   rc;

    if (gss_establish(evpl, (uint32_t) gss_case_service(c->defect))) {
        gss_release(evpl);
        return -1;
    }

    memset(&cred, 0, sizeof(cred));
    cred.flavor     = EVPL_RPC2_AUTH_RPCSEC_GSS;
    cred.gss.client = g_gss;

    issue_call_cred(evpl, cs, &cred);

    rc = read_call(evpl, buf, sizeof(buf), &len, &xid);
    evpl_test_abort_if(rc != READ_OK,
                       "case %s: never saw the client's protected CALL (rc %d)",
                       defect_name(c->defect), rc);

    evpl_test_abort_if(gss_call_seq(buf, len, &seq),
                       "case %s: could not read the sequence number out of the "
                       "client's credential", defect_name(c->defect));

    if (build_gss_reply(&msg, c, xid, seq)) {
        gss_release(evpl);
        return -1;
    }

    rc = deliver(evpl, c, &msg);
    evpl_test_abort_if(rc, "case %s/%s: failed to write the reply",
                       defect_name(c->defect), delivery_name(c->delivery));

    pump_until_fired(evpl, cs);

    gss_release(evpl);
    return 0;
} /* run_gss_case */

/* ------------------------------------------------------------------ *
* Outbound AUTH_SYS credentials (RFC 5531 Appendix A)
*
* The reply cases above all send AUTH_NONE, which leaves the client's other
* credential flavor -- the one every real NFS client uses -- entirely
* unexercised.  This checks the encode direction, and it belongs in this
* harness rather than in conformance.c because only a hostile server sees the
* bytes: handing the credential to a real libevpl server and asking it what it
* decoded would test the encoder and the decoder against each other, and a
* pair of mutually consistent bugs would pass.  Here the oracle is the RFC's
* own layout, read off the wire.
*
*     struct authsys_parms {
*        unsigned int stamp;
*        string machinename<255>;
*        unsigned int uid;
*        unsigned int gid;
*        unsigned int gids<16>;
*     };
*
* carried in the call's credential as flavor AUTH_SYS with that structure as
* the opaque body (RFC 5531 section 9: opaque_auth is a flavor and a counted
* body, and the body is XDR).
* ------------------------------------------------------------------ */

struct cred_case {
    const char *machinename;
    uint32_t    uid;
    uint32_t    gid;
    uint32_t    num_gids;
    uint32_t    gids[EVPL_RPC2_AUTH_SYS_MAX_GIDS];
};

/*
 * Machine names of length 4n, 4n+1, 4n+2 and 4n+3 between them cover every
 * XDR residue, so all four padding cases are encoded and checked; the group
 * lists cover the empty list and the declared <16> bound, which is where a
 * counted field is most likely to be got wrong.
 */
static const struct cred_case cred_cases[] = {
    { "conformance-client", 4711,                      815,                       3,
        { 0,                    1,                         0xffffffffu } },
    { "h",                  0,                         0,                         0,
        { 0     } },
    { "abc",                1,                         2,                         1,
        { 65534 } },
    { "node",               0xffffffffu,               0xffffffffu,               EVPL_RPC2_AUTH_SYS_MAX_GIDS,
        { 100,                  101,                       102,                       103,
        104, 105, 106, 107,
        108, 109, 110, 111, 112, 113, 114, 115 } },
};

static int                    g_cred_run;
static int                    g_cred_failed;

#define cred_check(cond, ...)               \
        do {                                    \
            if (!(cond)) {                      \
                evpl_test_error(__VA_ARGS__);   \
                g_cred_failed++;                \
                return;                         \
            }                                   \
        } while (0)

static void
check_authsys_call(
    struct evpl            *evpl,
    const struct cred_case *cc)
{
    struct call_state    *cs = call_state_alloc();
    struct evpl_rpc2_cred cred;
    struct wirebuf        msg;
    struct client_case    one = { 0, CDLV_ONEWRITE, 0, 0, -1 };
    static uint32_t       gids[EVPL_RPC2_AUTH_SYS_MAX_GIDS];
    uint8_t               buf[2048];
    const uint8_t        *body;
    uint32_t              len, xid, cred_len, name_len, name_pad, want_len;
    uint32_t              off, p, ngids, i;
    int                   rc;

    evpl_test_abort_if(ensure_conn(evpl),
                       "failed to (re)connect the client under test");

    name_len = (uint32_t) strlen(cc->machinename);
    name_pad = (4 - (name_len & 3)) & 3;

    memcpy(gids, cc->gids, sizeof(gids));

    memset(&cred, 0, sizeof(cred));
    cred.flavor                  = EVPL_RPC2_AUTH_SYS;
    cred.authsys.uid             = cc->uid;
    cred.authsys.gid             = cc->gid;
    cred.authsys.num_gids        = cc->num_gids;
    cred.authsys.gids            = gids;
    cred.authsys.machinename     = cc->machinename;
    cred.authsys.machinename_len = (int) name_len;

    g_cred_run++;

    issue_call_cred(evpl, cs, &cred);

    rc = read_call(evpl, buf, sizeof(buf), &len, &xid);
    evpl_test_abort_if(rc != READ_OK,
                       "credential case '%s': never saw the client's CALL "
                       "(rc %d)", cc->machinename, rc);

    /* xid, mtype, rpcvers, prog, vers, proc, then the credential. */
    off = 24;
    cred_check(len >= off + 8, "credential case '%s': call is %u bytes, too "
               "short to hold a credential at all", cc->machinename, len);

    cred_check(get32(buf + off) == RPC_AUTH_SYS,
               "credential case '%s': call carried auth flavor %u, expected "
               "AUTH_SYS (%u)", cc->machinename, get32(buf + off),
               RPC_AUTH_SYS);
    off += 4;

    cred_len = get32(buf + off);
    off     += 4;

    /* stamp + counted machinename (padded) + uid + gid + counted gids. */
    want_len = 4 + 4 + name_len + name_pad + 4 + 4 + 4 + 4 * cc->num_gids;

    cred_check(cred_len == want_len,
               "credential case '%s': credential body is %u bytes, expected "
               "%u", cc->machinename, cred_len, want_len);

    /* The body is itself padded to a multiple of four inside the message. */
    cred_check(off + ((cred_len + 3) & ~3u) + 8 <= len,
               "credential case '%s': credential body runs past the end of "
               "the call", cc->machinename);

    body = buf + off;

    /* struct evpl_rpc2_cred has no stamp, so libevpl always sends 0.  RFC 5531
     * Appendix A calls it "an arbitrary ID which the caller machine may
     * generate", so a constant is conformant -- asserted to pin down which
     * constant, since a field nobody checks is a field that can quietly start
     * carrying uninitialized stack. */
    cred_check(get32(body) == 0,
               "credential case '%s': stamp is %u, expected 0",
               cc->machinename, get32(body));

    cred_check(get32(body + 4) == name_len,
               "credential case '%s': machinename length is %u, expected %u",
               cc->machinename, get32(body + 4), name_len);

    cred_check(memcmp(body + 8, cc->machinename, name_len) == 0,
               "credential case '%s': machinename bytes did not survive",
               cc->machinename);

    for (i = 0; i < name_pad; i++) {
        cred_check(body[8 + name_len + i] == 0,
                   "credential case '%s': machinename pad byte %u is 0x%02x, "
                   "and RFC 4506 section 4.11 requires zero",
                   cc->machinename, i, body[8 + name_len + i]);
    }

    p = 8 + name_len + name_pad;

    cred_check(get32(body + p) == cc->uid,
               "credential case '%s': uid is %u, expected %u",
               cc->machinename, get32(body + p), cc->uid);

    cred_check(get32(body + p + 4) == cc->gid,
               "credential case '%s': gid is %u, expected %u",
               cc->machinename, get32(body + p + 4), cc->gid);

    ngids = get32(body + p + 8);
    cred_check(ngids == cc->num_gids,
               "credential case '%s': gids count is %u, expected %u",
               cc->machinename, ngids, cc->num_gids);

    for (i = 0; i < ngids; i++) {
        cred_check(get32(body + p + 12 + 4 * i) == cc->gids[i],
                   "credential case '%s': gids[%u] is %u, expected %u",
                   cc->machinename, i, get32(body + p + 12 + 4 * i),
                   cc->gids[i]);
    }

    /* The verifier is unaffected by the credential flavor: an AUTH_SYS call
     * still carries AUTH_NONE there (RFC 5531 Appendix A -- system
     * authentication has no verifier of its own). */
    off += (cred_len + 3) & ~3u;
    cred_check(get32(buf + off) == RPC_AUTH_NONE && get32(buf + off + 4) == 0,
               "credential case '%s': verifier is flavor %u length %u, "
               "expected AUTH_NONE with an empty body",
               cc->machinename, get32(buf + off), get32(buf + off + 4));
    off += 8;

    /* And the arguments still follow it, unshifted -- a credential encoded at
     * the wrong length would leave the call decodable only by accident. */
    cred_check(off + 8 + strlen(CALL_GREETING) <= len,
               "credential case '%s': no room left for the arguments",
               cc->machinename);
    cred_check(get32(buf + off) == CALL_ID &&
               get32(buf + off + 4) == strlen(CALL_GREETING) &&
               memcmp(buf + off + 8, CALL_GREETING,
                      strlen(CALL_GREETING)) == 0,
               "credential case '%s': the arguments did not survive the "
               "credential", cc->machinename);

    /* Answer it, so the call completes and nothing is left outstanding for a
     * later case to trip over. */
    msg.len = 0;
    put_accepted_header(&msg, xid);
    put_hello(&msg);

    cred_check(deliver(evpl, &one, &msg) == 0,
               "credential case '%s': failed to write the reply",
               cc->machinename);

    pump_until_fired(evpl, cs);

    cred_check(cs->fired == 1 && cs->status == 0 && cs->matched,
               "credential case '%s': the call did not complete (fired %d, "
               "status %d, matched %d)", cc->machinename, cs->fired,
               cs->status, cs->matched);
} /* check_authsys_call */

static void
run_case(
    struct evpl              *evpl,
    const struct client_case *c)
{
    struct call_state *cs = call_state_alloc();
    struct wirebuf     msg;
    uint8_t            buf[2048];
    uint32_t           len, xid;
    int                actual, probe_ok, rc;

    if (ensure_conn(evpl)) {
        evpl_test_abort("failed to (re)connect the client under test");
    }

    /* A protected case needs a context first, and a context needs a
     * mechanism; where there is none the case is skipped rather than failed,
     * the same way the krb5 instances of the server-side suite are. */
    if (is_gss_case(c->defect)) {
        if (!g_kl) {
            g_gss_skipped++;
            return;
        }

        g_results.run++;

        if (run_gss_case(evpl, c, cs)) {
            evpl_test_error("case %s/%s: the harness could not hold up its end "
                            "of the context", defect_name(c->defect),
                            delivery_name(c->delivery));
            g_results.unknown++;
            return;
        }

        goto classify;
    }

    g_results.run++;

    issue_call(evpl, cs);

    rc = read_call(evpl, buf, sizeof(buf), &len, &xid);
    evpl_test_abort_if(rc != READ_OK,
                       "case %s/%s: never saw the client's CALL (rc %d)",
                       defect_name(c->defect), delivery_name(c->delivery), rc);

    build_reply(&msg, c, xid);

    if (c->defect == CDEF_PEERCLOSESWITHOUTREPLY) {
        close(g_peer_fd);
        g_peer_fd = -1;
    } else if (c->defect == CDEF_REPLYSPLITACROSSFRAGMENTS) {
        rc = deliver_fragmented(evpl, &msg, (uint32_t) c->param);
        evpl_test_abort_if(rc, "case %s: failed to write the fragments",
                           defect_name(c->defect));
    } else {
        rc = deliver(evpl, c, &msg);
        evpl_test_abort_if(rc, "case %s/%s: failed to write the reply",
                           defect_name(c->defect), delivery_name(c->delivery));
    }

    pump_until_fired(evpl, cs);

    /* The second copy goes out only once the first has been consumed, so that
     * what it collides with is a completed call and not a race. */
    if (c->defect == CDEF_REPLYDUPLICATED && g_conn_alive) {
        rc = deliver(evpl, c, &msg);
        evpl_test_abort_if(rc, "case %s: failed to write the duplicate",
                           defect_name(c->defect));
        evpl_continue(evpl);
        evpl_continue(evpl);
    }

    /* Classify what the client did.  Note the ordering: a second completion
     * outranks whatever the first one said, because no status can make
     * double-completing a call correct. */
 classify:

    if (cs->fired > 1) {
        actual = ACT_DOUBLE_CALLBACK;
    } else if (cs->fired == 1) {
        if (cs->status == 0) {
            actual = cs->matched ? CEXP_CBSUCCESS : ACT_WRONG_VALUE;
        } else if (cs->status == EVPL_RPC2_REPLY_DECODE_ERROR) {
            actual = CEXP_CBDECODEERROR;
        } else {
            actual = CEXP_CBFAILED;
        }
    } else if (!g_conn_alive) {
        actual = ACT_CONN_LOST;
    } else {
        actual = ACT_NO_CALLBACK;
    }

    probe_ok = probe_connection(evpl);

    /* CbFailed is deliberately satisfied by a decode error: the model does not
     * pin down which non-zero status a refusal produces, only that the call
     * completes and completes as a failure. */
    if (c->expect == CEXP_CBFAILED &&
        (actual == CEXP_CBDECODEERROR || actual == CEXP_CBFAILED)) {
        actual = CEXP_CBFAILED;
    }

    /* A reply the client must ignore leaves no trace of its own, so the only
     * proof it was ignored *correctly* -- rather than because the client
     * stopped working -- is a subsequent ordinary call on the same
     * connection. */
    if (c->expect == CEXP_CBDROPPED && actual == ACT_NO_CALLBACK && probe_ok) {
        actual = CEXP_CBDROPPED;
    }

    if (actual == c->expect &&
        (c->survive != CSRV_CONNUP || probe_ok)) {
        g_results.matched++;
        g_results.matched_by_expect[c->expect]++;
        return;
    }

    if (is_known_divergence(c->defect, c->expect, actual)) {
        g_results.known++;
        evpl_test_info("known divergence: %s(%lld)/%s expected %s, got %s",
                       defect_name(c->defect), (long long) c->param,
                       delivery_name(c->delivery),
                       outcome_name(c->expect), outcome_name(actual));
        return;
    }

    g_results.unknown++;
    evpl_test_error(
        "DIVERGENCE: %s(%lld)/%s expected %s, got %s (status %d, fired %d, "
        "conn %s, probe %s, results id=%u greeting='%s')",
        defect_name(c->defect), (long long) c->param,
        delivery_name(c->delivery),
        outcome_name(c->expect), outcome_name(actual),
        cs->status, cs->fired,
        g_conn_alive ? "up" : "down",
        probe_ok ? "ok" : "failed",
        cs->got_id, cs->got_greeting);
} /* run_case */

static void
usage(const char *prog)
{
    fprintf(stderr, "Usage: %s [-r protocol] [-p port]\n", prog);
    exit(1);
} /* usage */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl               *evpl;
    struct evpl_rpc2_program  *programs[1];
    struct evpl_thread_config *tcfg;
    enum evpl_protocol_id      proto    = EVPL_STREAM_SOCKET_TCP;
    const char                *krb5_why = NULL;
    unsigned int               i;
    int                        opt, rc, failed;

    test_evpl_config();

    while ((opt = getopt(argc, argv, "r:p:")) != -1) {
        switch (opt) {
                case 'r':
                    rc = evpl_protocol_lookup(&proto, optarg);
                    if (rc) {
                        fprintf(stderr, "Invalid protocol '%s'\n", optarg);
                        return 1;
                    }
                    break;
                case 'p':
                    port = atoi(optarg);
                    break;
                default:
                    usage(argv[0]);
        } /* switch */
    }

    /* The harness is hand-built record-marked bytes, which is a stream-only
     * concept; there is no way to express these defects over RDMA. */
    if (proto != EVPL_STREAM_SOCKET_TCP) {
        printf("skipping: raw record marking requires a stream transport\n");
        printf("Test PASSED\n");
        return 0;
    }

    pattern_init();

    /*
     * A bounded wait is required, not merely nice: the default (-1) parks
     * evpl_continue in the poller until something happens, and the cases that
     * expect no callback at all would never come back to check their deadline.
     *
     * evpl_create() takes ownership of the config and releases it itself.
     * Exactly one evpl is created for the whole run -- a second create/destroy
     * cycle wedges process exit.
     */
    tcfg = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(tcfg, 1);
    evpl = evpl_create(tcfg);

    HELLO_V1_init(&g_prog);
    programs[0] = &g_prog.rpc2;

    g_listen_fd = listen_raw(port);
    evpl_test_abort_if(g_listen_fd < 0, "failed to listen on port %d", port);

    g_thread = evpl_rpc2_thread_init(evpl, programs, 1, client_notify_cb,
                                     NULL);
    g_endpoint = evpl_endpoint_create("127.0.0.1", port);

    /* The mechanism for the protected cases.  Its absence is not a failure --
     * the rest of the matrix does not need it -- so the GSS cases report as
     * skipped and everything else runs unchanged. */
    g_acc = krb5_local_provider();
    g_kl  = krb5_local_create(&krb5_why);

    if (!g_kl) {
        evpl_test_info("no kerberos: the protected reply cases will be skipped "
                       "(%s)", krb5_why ? krb5_why : "unavailable");
    }

    /* Before the reply matrix, and on a connection nothing has abused yet:
     * these check what the client puts on the wire, so they need a case-free
     * connection more than they need a particular one. */
    evpl_test_info("running %u outbound credential cases",
                   (unsigned int) (sizeof(cred_cases) / sizeof(cred_cases[0])));

    for (i = 0; i < sizeof(cred_cases) / sizeof(cred_cases[0]); i++) {
        check_authsys_call(evpl, &cred_cases[i]);
    }

    evpl_test_info("running %u client reply cases",
                   (unsigned int) CLIENT_NUM_CASES);

    for (i = 0; i < CLIENT_NUM_CASES; i++) {
        run_case(evpl, &client_cases[i]);
    }

    if (g_conn_alive) {
        evpl_rpc2_client_disconnect(g_thread, g_conn);
    }

    if (g_kl) {
        krb5_local_destroy(g_kl);
        g_kl = NULL;
    }

    if (g_peer_fd >= 0) {
        close(g_peer_fd);
    }
    close(g_listen_fd);

    /* Let the loop retire the connections the run left in every state the
     * client knows how to reach before tearing it down. */
    {
        uint64_t drain_deadline = now_ms() + 200;

        while (now_ms() < drain_deadline) {
            evpl_continue(evpl);
        }
    }

    evpl_rpc2_thread_destroy(g_thread);
    evpl_destroy(evpl);

    /* Only now, once no callback can run again, is the call state unreachable. */
    call_states_release();

    printf("outbound credential cases: %d run, %d failed\n",
           g_cred_run, g_cred_failed);
    printf("client reply cases: %d run, %d matched spec, %d known divergences, "
           "%d unexpected, %d skipped (no kerberos)\n",
           g_results.run, g_results.matched, g_results.known,
           g_results.unknown, g_gss_skipped);
    printf("  matched by required outcome: %d callback-ok, %d decode-error, "
           "%d failed, %d dropped\n",
           g_results.matched_by_expect[CEXP_CBSUCCESS],
           g_results.matched_by_expect[CEXP_CBDECODEERROR],
           g_results.matched_by_expect[CEXP_CBFAILED],
           g_results.matched_by_expect[CEXP_CBDROPPED]);

    failed = g_results.unknown != 0 || g_cred_failed != 0;

    printf("Test %s\n", failed ? "FAILED" : "PASSED");
    return failed ? 1 : 0;
} /* main */
