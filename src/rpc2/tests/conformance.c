/*
 * SPDX-FileCopyrightText: 2026 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Model-based XDR/RPC2 conformance test.
 *
 * Two phases, both driven by cases generated from the Quint models in
 * quint/ and compiled in as conformance_cases.h:
 *
 *   1. Values.  Every procedure of CONFORMANCE_PROGRAM (conformance.x) is
 *      called through the generated libevpl client with boundary values for
 *      each field, and the reply is compared to the request.  Every handler
 *      echoes, so round-trip identity is the oracle -- no model prediction is
 *      needed, and both the marshall and unmarshall paths of every generated
 *      codec are exercised in both directions.
 *
 *   2. Defects.  Deliberately malformed calls are written straight onto a TCP
 *      socket, bypassing libevpl's client (which cannot produce a bad RPC
 *      version, a bogus record mark, or an unknown program).  The reply is
 *      classified and compared against the outcome RFC 5531 / RFC 4506
 *      require.
 *
 * The defect model encodes the SPECIFICATION, so a mismatch here is a
 * candidate bug in libevpl rather than a broken test.  Known, reviewed
 * divergences are listed in known_divergences[] with a note; anything not on
 * that list fails the test.  That way the suite stays green while the
 * outstanding gaps stay visible and counted.
 *
 * Phase 2 is TCP-only: record marking does not exist on the RDMA transports.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <math.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/un.h>
#include <stddef.h>

#include "evpl/evpl.h"
#include "evpl/evpl_rpc2.h"

/* Generated from rpcrdma1.x alongside rpc2 itself.  Needed here because the
 * ERR_VERS check builds an RPC-over-RDMA transport header by hand -- the one
 * thing libevpl's own client will never do. */
#include "rpcrdma1_xdr.h"

#include "core/test_log.h"
#include "test_common.h"

#include "gss_stub.h"
#include "evpl/evpl_rpc2_gss.h"

#include "conformance_xdr.h"
#include "conformance_cases.h"

static enum evpl_protocol_id    proto = EVPL_STREAM_SOCKET_TCP;
/* The effective address for this run: a host for IP, a socket name for a
 * name-addressed transport.  Resolved once from test_address(). */
static const char              *g_address = "0.0.0.0";
static int                      port      = 8000;

/* The rpc2 thread the server runs on.  Only the RPCSEC_GSS cases need it, and
 * only to reconfigure the mechanism mid-run: a server with no GSS provider is
 * a state the defect matrix has to be able to reach, and registering one is a
 * per-thread setting rather than something a call can carry. */
static struct evpl_rpc2_thread *g_thread;

#define CONF_PROG             44
#define CONF_VERS             1

/* Procedure numbers, from conformance.x. */
#define PROC_ECHO_SCALARS     1
#define PROC_ECHO_BYTES       2
#define PROC_ECHO_ZBYTES      3
#define PROC_ECHO_ARRAYS      4
#define PROC_ECHO_UNION       5
#define PROC_PROBE_STRICT     6
#define PROC_ECHO_OPTIONAL    7
#define PROC_ECHO_LIST        8
#define PROC_ECHO_NESTED      9

/* Outcomes the driver can observe that the model has no name for. */
#define ACT_STALLED           100 /* no reply and no close before the deadline */
#define ACT_MALFORMED         101 /* reply was not a decodable RPC reply       */
#define ACT_SYSTEM_ERR        102
#define ACT_BADRANGE          103 /* right reply, wrong supported-version range */

/* Wall-clock budget for one raw-socket exchange.  Loopback replies land in
 * microseconds, so anything approaching this is a server that has stopped
 * making progress -- which is exactly what the record-mark cases look for.
 * Kept small because several cases are expected to hit it. */
#define REPLY_TIMEOUT_MS      300

/*
 * Cap on one reassembled RPC message, lowered for the whole run from
 * libevpl's 4 MiB default.
 *
 * The ReassemblyCapExceeded case has to carry a record's running total past
 * the cap using fragments that are each individually legal, which at the
 * default would mean pushing 4 MiB across loopback to learn one bit.  The cap
 * is read from the global config on every fragment, so lowering it tests
 * exactly the same code for a few tens of kilobytes.  It stays an order of
 * magnitude above the largest message anything else here builds -- the
 * pathological-fragmentation case, a little over 2 KiB -- so no other case
 * can tell the difference.
 */
#define CONF_MAX_MESSAGE_SIZE (64 * 1024)

/*
 * test_evpl_config() plus that one knob.  evpl_init consumes the global
 * config and there is no way to revise it afterwards, so the value has to be
 * chosen once, here, on behalf of every phase.
 */
static void
conformance_evpl_config(void)
{
    struct evpl_global_config *config = evpl_global_config_init();

    evpl_global_config_set_tls_verify_peer(config, 0);
    evpl_global_config_set_rpc2_max_message_size(config, CONF_MAX_MESSAGE_SIZE);

    test_evpl_set_core_mech(config);

    evpl_init(config);
} /* conformance_evpl_config */

/* ------------------------------------------------------------------ *
* Shared state
* ------------------------------------------------------------------ */

struct server_ctx {
    struct CONFORMANCE_V1 prog;
};

struct results {
    int value_run;
    int value_failed;
    int defect_run;
    int defect_skipped;
    int defect_matched;
    int defect_known;
    int defect_unknown;
    int rdma_error_checks;
    int value_chunked;
    int rdma_capable;
};

static struct results g_results;

/* Deterministic filler for strings, opaques and array elements. */
#define MAX_PAYLOAD          1024
static uint8_t        g_pattern[MAX_PAYLOAD];

/*
 * ReassemblyCapExceeded: how the running total is walked past the cap.
 *
 * Each fragment is far below the per-fragment limit, so none of them is
 * refusable on its own -- only a receiver that counts across the fragments of
 * one record can stop this, which is exactly the check under test.  The
 * fragment count is a ceiling on how many it can take: every fragment adds
 * its full length, so the total is past the cap after
 * CONF_MAX_MESSAGE_SIZE / REASM_FLOOD_FRAG_LEN of them at the very latest,
 * and the spare two absorb the short leading fragment and the one that
 * finally crosses.  This buffer is never parsed by anything -- the record is
 * refused on its length -- but it is filled with the same pattern as
 * everything else rather than left zeroed, so that a receiver which somehow
 * did parse it would not be being handed a convenient string of NULs.
 */
#define REASM_FLOOD_FRAG_LEN 4096
#define REASM_FLOOD_FRAGS \
        ((CONF_MAX_MESSAGE_SIZE / REASM_FLOOD_FRAG_LEN) + 2)

static uint8_t           g_reasm_filler[REASM_FLOOD_FRAG_LEN];

/* Destination buffer armed for the read-into case.  Ownership is the mirror
 * image of an ordinary reply: libevpl borrows this buffer rather than taking
 * it, so the reply's iovecs point straight at it and the callback must NOT
 * release them -- the single reference is ours and is dropped once, here,
 * after the call completes. */
static struct evpl_iovec g_chunk_dest;
static int               g_chunk_dest_held;

static void
pattern_init(void)
{
    unsigned int i;

    for (i = 0; i < MAX_PAYLOAD; i++) {
        g_pattern[i] = (uint8_t) (i * 7 + 13);
    }
    for (i = 0; i < sizeof(g_reasm_filler); i++) {
        g_reasm_filler[i] = g_pattern[i % MAX_PAYLOAD];
    }
} /* pattern_init */

/* ------------------------------------------------------------------ *
* Known divergences from the specification
*
* Each entry records a case where libevpl's behaviour differs from what the
* model requires, so the suite can stay green while the gap remains visible.
* Removing an entry turns the corresponding case back into a hard failure,
* which is what should happen once the underlying issue is fixed.
* ------------------------------------------------------------------ */

struct known_divergence {
    int         defect;   /* DEF_* */
    int         expect;   /* EXP_*, what the RFC requires */
    int         actual;   /* EXP_ or ACT_ code: what libevpl does today */
    const char *note;
};

/* Connections the driver dialled itself, raw or through the rpc2 client.  The
* server must announce exactly this many accepts -- see conformance_notify. */
static int                           g_connections_opened;

static const struct known_divergence known_divergences[] = {
    /* Add an entry here only for a divergence that has been reviewed and
     * consciously deferred, with a note saying why -- an unlisted one fails
     * the test, which is what keeps a regression from passing silently.
     *
     * The unmatchable first row keeps the array non-empty when every real
     * entry has been retired, which is the state to aim for. */
    { .defect = -1,
      .expect = -1,
      .actual = -1,
      .note   = NULL },

    /* RFC 2203 sec 5.3.3.3: "When the client's sequence number exceeds the
     * maximum the server will allow, the server will reject the request with
     * the reason RPCSEC_GSS_CTXPROBLEM."  This is the one sequence-number
     * outcome the RFC asks for an answer to; the others (below the window, or
     * already seen) are the silent discards sec 5.3.3.1 describes.  libevpl
     * folds all three together in evpl_rpc2_gss_seq_check, which returns -1
     * for seq > RPCSEC_GSS_MAXSEQ and leaves the caller to drop the request
     * without a reply.  A client that walks its seq_num past MAXSEQ therefore
     * gets silence instead of the CTXPROBLEM that would tell it to refresh the
     * context, and retries until it times out. */
    { .defect = DEF_GSSSEQABOVEMAX,
      .expect = EXP_AUTHERROR,
      .actual = EXP_NOREPLY,
      .note   = "seq_num above MAXSEQ is discarded rather than rejected" },

    /* RFC 2203 sec 5.3.3.4.1: "When GSS_GetMIC() is called to sign the call
     * results (service is rpc_gss_svc_integrity), a failure results in no RPC
     * response being sent."  libevpl's evpl_rpc2_send_reply treats a failed
     * evpl_rpc2_gss_wrap_reply_integrity as advisory and falls through with
     * the *unwrapped* body, so the client receives MSG_ACCEPTED/SUCCESS whose
     * results are bare procedure results with no rpc_gss_integ_data around
     * them.  The comment there argues that the client will reject the missing
     * integrity, but that makes correctness depend on the peer noticing, and a
     * client that does notice cannot tell this apart from an attacker having
     * stripped the wrapping.  Both entries are the same code path reached two
     * ways: a mechanism that will not sign, and one that returns a signature
     * too large for the 512-byte checksum headroom. */
    { .defect = DEF_GSSINTEGREPLYMICFAILS,
      .expect = EXP_NOREPLY,
      .actual = EXP_SUCCESS,
      .note   = "unsignable krb5i results are returned unwrapped, not dropped" },
    { .defect = DEF_GSSINTEGREPLYMICOVERSIZE,
      .expect = EXP_NOREPLY,
      .actual = EXP_SUCCESS,
      .note   = "oversized krb5i MIC returns unwrapped results, not a drop" },

    /* The GSS token of a context-creation call travels in the call ARGUMENTS
     * (rpc_gss_init_arg, RFC 2203 sec 5.2.2), so a token that will not decode
     * is undecodable arguments: GARBAGE_ARGS, per RFC 5531 sec 9 and the same
     * reasoning sec 5.3.3.4.2 applies to the integrity service's arguments.
     * libevpl denies instead, and specifically with the one auth_stat that RFC
     * 2203 sec 5.2.3.2 rules out here: "neither of these two
     * [RPCSEC_GSS_CREDPROBLEM and RPCSEC_GSS_CTXPROBLEM] can be returned in
     * responses to context creation requests."  The practical cost is that a
     * client seeing CTXPROBLEM is being told to tear down and rebuild a
     * context over what is really a malformed request. */
    { .defect = DEF_GSSINITTOKENMALFORMED,
      .expect = EXP_GARBAGEARGS,
      .actual = EXP_AUTHERROR,
      .note   = "undecodable init token denied, not GARBAGE_ARGS" },
    { .defect = DEF_GSSCONTINUEINITTOKENMALFORMED,
      .expect = EXP_GARBAGEARGS,
      .actual = EXP_AUTHERROR,
      .note   = "undecodable continue-init token denied, not GARBAGE_ARGS" },
};

static const char *
outcome_name(int o)
{
    switch (o) {
        case EXP_SUCCESS:      return "SUCCESS";
        case EXP_PROGUNAVAIL:  return "PROG_UNAVAIL";
        case EXP_PROGMISMATCH: return "PROG_MISMATCH";
        case EXP_PROCUNAVAIL:  return "PROC_UNAVAIL";
        case EXP_GARBAGEARGS:  return "GARBAGE_ARGS";
        case EXP_RPCMISMATCH:  return "RPC_MISMATCH";
        case EXP_AUTHERROR:    return "AUTH_ERROR";
        case EXP_CLOSED:       return "CONN_CLOSED";
        case EXP_NOREPLY:      return "NO_REPLY";
        case ACT_STALLED:      return "STALLED";
        case ACT_MALFORMED:    return "MALFORMED_REPLY";
        case ACT_SYSTEM_ERR:   return "SYSTEM_ERR";
        case ACT_BADRANGE:     return "BAD_VERSION_RANGE";
        default:               return "?";
    } /* switch */
} /* outcome_name */

static const char *
defect_name(int d)
{
    switch (d) {
        case DEF_NODEFECT:                return "NoDefect";
        case DEF_RPCVERSWRONG:            return "RpcVersWrong";
        case DEF_PROGRAMUNKNOWN:          return "ProgramUnknown";
        case DEF_VERSIONUNSUPPORTED:      return "VersionUnsupported";
        case DEF_PROCEDUREUNKNOWN:        return "ProcedureUnknown";
        case DEF_PROCEDURENULL:           return "ProcedureNull";
        case DEF_AUTHFLAVORUNSUPPORTED:   return "AuthFlavorUnsupported";
        case DEF_CREDBODYOVERLONG:        return "CredBodyOverlong";
        case DEF_ARGSTRUNCATED:           return "ArgsTruncated";
        case DEF_ARGSTRAILINGGARBAGE:     return "ArgsTrailingGarbage";
        case DEF_STRINGLENOVERFLOW:       return "StringLenOverflow";
        case DEF_STRINGLENBEYONDMESSAGE:  return "StringLenBeyondMessage";
        case DEF_STRINGEXCEEDSBOUND:      return "StringExceedsBound";
        case DEF_OPAQUEEXCEEDSBOUND:      return "OpaqueExceedsBound";
        case DEF_ARRAYCOUNTEXCEEDSBOUND:  return "ArrayCountExceedsBound";
        case DEF_ARRAYCOUNTHUGE:          return "ArrayCountHuge";
        case DEF_DISCRIMINANTUNMATCHED:   return "DiscriminantUnmatched";
        case DEF_BOOLNOTZEROORONE:        return "BoolNotZeroOrOne";
        case DEF_ENUMNOTDECLARED:         return "EnumNotDeclared";
        case DEF_RECORDMARKHUGE:          return "RecordMarkHuge";
        case DEF_RECORDMARKZEROLENGTH:    return "RecordMarkZeroLength";
        case DEF_CALLSPLITACROSSFRAGMENTS: return "CallSplitAcrossFragments";
        case DEF_CALLSPLITPATHOLOGICAL:   return "CallSplitPathological";
        case DEF_REASSEMBLYCAPEXCEEDED:   return "ReassemblyCapExceeded";
        case DEF_GSSINITESTABLISHES:      return "GssInitEstablishes";
        case DEF_GSSINITCONTINUES:        return "GssInitContinues";
        case DEF_GSSINITMECHFAILS:        return "GssInitMechFails";
        case DEF_GSSDATAVALID:            return "GssDataValid";
        case DEF_GSSCREDVERSIONWRONG:     return "GssCredVersionWrong";
        case DEF_GSSPROCUNKNOWN:          return "GssProcUnknown";
        case DEF_GSSSERVICEPRIVACY:       return "GssServicePrivacy";
        case DEF_GSSHANDLEUNKNOWN:        return "GssHandleUnknown";
        case DEF_GSSVERIFIERNOTGSS:       return "GssVerifierNotGss";
        case DEF_GSSMICWRONG:             return "GssMicWrong";
        case DEF_GSSSEQREPLAYED:          return "GssSeqReplayed";
        case DEF_AUTHSYSVALID:            return "AuthSysValid";
        case DEF_GSSINTEGDATAVALID:       return "GssIntegDataValid";
        case DEF_GSSINTEGCHECKSUMWRONG:   return "GssIntegChecksumWrong";
        case DEF_GSSINTEGSEQMISMATCH:     return "GssIntegSeqMismatch";
        case DEF_GSSDESTROYCONTEXT:       return "GssDestroyContext";
        case DEF_GSSDESTROYUNAUTHENTICATED: return "GssDestroyUnauthenticated";
        case DEF_GSSSEQABOVEMAX:          return "GssSeqAboveMax";
        case DEF_GSSSEQWINDOWJUMP:        return "GssSeqWindowJump";
        case DEF_GSSSEQTOOOLD:            return "GssSeqTooOld";
        case DEF_GSSSEQOUTOFORDER:        return "GssSeqOutOfOrder";
        case DEF_GSSCREDTRUNCATED:        return "GssCredTruncated";
        case DEF_GSSCREDHANDLEOVERRUNS:   return "GssCredHandleOverruns";
        case DEF_GSSNOMECHANISM:          return "GssNoMechanism";
        case DEF_GSSCONTINUEINITUNKNOWNHANDLE: return "GssContinueInitUnknownHandle";
        case DEF_GSSINITTOKENMALFORMED:   return "GssInitTokenMalformed";
        case DEF_GSSCONTINUEINITTOKENMALFORMED: return "GssContinueInitTokenMalformed";
        case DEF_GSSINITMECHFAILSWITHTOKEN: return "GssInitMechFailsWithToken";
        case DEF_GSSINTEGFRAMINGBAD:      return "GssIntegFramingBad";
        case DEF_GSSINTEGEMPTYARGS:       return "GssIntegEmptyArgs";
        case DEF_GSSINTEGSPLITACROSSFRAGMENTS: return "GssIntegSplitAcrossFragments";
        case DEF_GSSINTEGREPLYMICFAILS:   return "GssIntegReplyMicFails";
        case DEF_GSSINTEGREPLYMICOVERSIZE: return "GssIntegReplyMicOversize";
        default:                          return "?";
    } /* switch */
} /* defect_name */

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

/* ------------------------------------------------------------------ *
* Connection notifications
*
* rpc2 reports connection lifecycle to a callback registered on the thread.
* An application learns from it that a connection it never asked for has
* appeared, and -- more sharply -- that one it holds a pointer to has been
* freed, so a missed or duplicated notification is a use-after-free waiting
* to happen rather than a cosmetic fault.
*
* The bookkeeping here is what turns "the callback ran" into a check: a
* connection must be announced before it can be reported gone, may only be
* announced once, and may only be reported gone once.  Ordering is not an
* assumption -- the accept callback installs the rpc2 conn and the transport
* then reports the bind established, so on the server side ACCEPTED always
* precedes CONNECTED.  A CONNECTED with no accept before it is therefore the
* connection this process dialled, which is how the client's own conn is
* identified without racing the assignment of the pointer it returns.
* ------------------------------------------------------------------ */

/* Sized for the defect phase: each case dials a connection and closes it, but
 * the server retires them lazily, so many can be live at once. */
#define NOTIFY_MAX_LIVE 1024

struct notify_state {
    struct evpl_rpc2_conn *live[NOTIFY_MAX_LIVE];
    int                    num_live;
    int                    accepted;
    int                    connected;
    int                    disconnected;
    /* The conn identified as this process's client connection, and its
     * notification counts, kept apart from the server-side totals. */
    struct evpl_rpc2_conn *client_conn;
    int                    client_connected;
    int                    client_disconnected;
    int                    errors;
};

static struct notify_state g_notify;

/* What evpl_rpc2_server_attach and evpl_rpc2_thread_init were handed. */
static void               *g_server_private;
static void               *g_thread_private;

#define notify_check(cond, ...)             \
        do {                                    \
            if (!(cond)) {                      \
                evpl_test_error(__VA_ARGS__);   \
                g_notify.errors++;              \
            }                                   \
        } while (0)

static int
notify_find(struct evpl_rpc2_conn *conn)
{
    int i;

    for (i = 0; i < g_notify.num_live; i++) {
        if (g_notify.live[i] == conn) {
            return i;
        }
    }
    return -1;
} /* notify_find */

static void
notify_add(struct evpl_rpc2_conn *conn)
{
    evpl_test_abort_if(g_notify.num_live >= NOTIFY_MAX_LIVE,
                       "live connection table exhausted; raise NOTIFY_MAX_LIVE");
    g_notify.live[g_notify.num_live++] = conn;
} /* notify_add */

static void
notify_remove(int idx)
{
    g_notify.live[idx] = g_notify.live[--g_notify.num_live];
} /* notify_remove */

static void
conformance_notify(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_conn   *conn,
    struct evpl_rpc2_notify *notify,
    void                    *private_data)
{
    int idx = notify_find(conn);

    notify_check(conn != NULL, "notification %u carried no connection",
                 notify->notify_type);

    switch (notify->notify_type) {
        case EVPL_RPC2_NOTIFY_ACCEPTED:
            /* Note the asymmetry, which is libevpl's and not a typo here: an
             * accept reports the *server's* private data (what
             * evpl_rpc2_server_attach was given), while the two conn-lifecycle
             * notifications report the *thread's* (what evpl_rpc2_thread_init
             * was given).  Asserted rather than smoothed over, so that
             * changing it is a visible decision. */
            notify_check(private_data == g_server_private,
                         "ACCEPTED carried private data %p, expected the "
                         "server's %p", private_data, g_server_private);
            notify_check(idx < 0,
                         "ACCEPTED for connection %p, which is already live",
                         (void *) conn);
            notify_add(conn);
            g_notify.accepted++;
            break;

        case EVPL_RPC2_NOTIFY_CONNECTED:
            notify_check(private_data == g_thread_private,
                         "CONNECTED carried private data %p, expected the "
                         "thread's %p", private_data, g_thread_private);
            g_notify.connected++;
            if (idx < 0) {
                /* No accept preceded it: this is the connection we dialled. */
                notify_check(g_notify.client_conn == NULL,
                             "a second unaccepted connection %p was reported "
                             "connected", (void *) conn);
                g_notify.client_conn = conn;
                g_notify.client_connected++;
                notify_add(conn);
            }
            break;

        case EVPL_RPC2_NOTIFY_DISCONNECTED:
            notify_check(private_data == g_thread_private,
                         "DISCONNECTED carried private data %p, expected the "
                         "thread's %p", private_data, g_thread_private);
            notify_check(idx >= 0,
                         "DISCONNECTED for connection %p, which was never "
                         "announced (or was already reported gone)",
                         (void *) conn);
            if (idx >= 0) {
                notify_remove(idx);
            }
            g_notify.disconnected++;
            if (conn == g_notify.client_conn) {
                g_notify.client_disconnected++;
            }
            break;

        default:
            notify_check(0, "unknown notification type %u",
                         notify->notify_type);
    } /* switch */
} /* conformance_notify */

/*
 * Check the notification tallies against what the run actually did.  Called
 * once the rpc2 thread is destroyed: that closes every surviving connection
 * and pumps until rpc2 has retired it, so by then nothing further can arrive
 * and every announced connection must have been accounted for.
 */
static void
check_notifications(void)
{
    notify_check(g_notify.num_live == 0,
                 "%d connection(s) were announced but never reported gone",
                 g_notify.num_live);

    /* One accept per connection this process dialled, raw sockets included --
     * the defect phase's connections are announced exactly like any other. */
    notify_check(g_notify.accepted == g_connections_opened,
                 "%d accepts announced for %d connections opened",
                 g_notify.accepted, g_connections_opened);

    /* Each accepted bind is reported established once the transport attaches
     * it, and the client's own connection adds the one accept never saw. */
    notify_check(g_notify.connected == g_notify.accepted + 1,
                 "%d connects announced, expected %d (one per accept, plus "
                 "this process's own client connection)",
                 g_notify.connected, g_notify.accepted + 1);

    notify_check(g_notify.disconnected == g_notify.connected,
                 "%d disconnects for %d connects",
                 g_notify.disconnected, g_notify.connected);

    notify_check(g_notify.client_connected == 1 &&
                 g_notify.client_disconnected == 1,
                 "the client connection was reported connected %d time(s) and "
                 "disconnected %d time(s), expected once each",
                 g_notify.client_connected, g_notify.client_disconnected);
} /* check_notifications */

/* ------------------------------------------------------------------ *
* Server: every procedure echoes its argument
* ------------------------------------------------------------------ */

/*
 * Exercise the connection accessors, and check what they say.
 *
 * These are part of the public rpc2 surface but nothing else in the suite has
 * any reason to call them, so they would otherwise never be executed.  Using
 * the private-data slot as the "seen this connection already" marker means the
 * round trip is actually verified rather than merely performed: the slot must
 * start NULL, and every later request on the same connection must read back
 * exactly what the first one stored.  rpc2 itself never touches the slot, so
 * borrowing it cannot disturb anything.
 */
static const char conn_seen;
#define CONN_SEEN_MARKER ((void *) &conn_seen)

static void
check_conn_accessors(struct evpl_rpc2_conn *conn)
{
    char  local[256]  = "";
    char  remote[256] = "";
    void *seen        = evpl_rpc2_conn_get_private_data(conn);

    if (seen == CONN_SEEN_MARKER) {
        return;
    }

    evpl_test_abort_if(seen != NULL,
                       "connection private data started out as %p, not NULL",
                       seen);

    evpl_rpc2_conn_get_local_address(conn, local, sizeof(local));
    evpl_rpc2_conn_get_remote_address(conn, remote, sizeof(remote));

    evpl_test_abort_if(local[0] == '\0', "local address came back empty");
    evpl_test_abort_if(remote[0] == '\0', "remote address came back empty");

    evpl_rpc2_conn_set_private_data(conn, CONN_SEEN_MARKER);

    evpl_test_abort_if(evpl_rpc2_conn_get_private_data(conn) != CONN_SEEN_MARKER,
                       "connection private data did not round-trip");
} /* check_conn_accessors */

#define ECHO_HANDLER(NAME, TYPE, PROC)                                       \
        static void                                                              \
        server_ ## NAME(                                                         \
            struct evpl *evpl,                                     \
            struct evpl_rpc2_conn *conn,                                     \
            struct evpl_rpc2_cred *cred,                                     \
            struct TYPE *call,                                     \
            struct evpl_rpc2_encoding *encoding,                                 \
            void *private_data)                             \
        {                                                                        \
            struct server_ctx *ctx = private_data;                               \
            int                rc;                                               \
                                                                             \
            check_conn_accessors(conn);                                          \
                                                                             \
            rc = ctx->prog.send_reply_ ## PROC(evpl, NULL, call, encoding);      \
            evpl_test_abort_if(rc, "send_reply_" #PROC " failed: %d", rc);       \
        }

ECHO_HANDLER(echo_scalars, scalars, ECHO_SCALARS)
ECHO_HANDLER(echo_bytes, bytes, ECHO_BYTES)
ECHO_HANDLER(echo_arrays, arrays, ECHO_ARRAYS)
ECHO_HANDLER(echo_union, tagged, ECHO_UNION)
ECHO_HANDLER(echo_optional, opt_msg, ECHO_OPTIONAL)
ECHO_HANDLER(echo_list, list_msg, ECHO_LIST)
ECHO_HANDLER(echo_nested, nested, ECHO_NESTED)

/*
 * zcopaque is the one field type that is never copied, so echoing it would
 * hand the reply marshaller iovecs the request still owns.  Rather than take
 * a position on that ownership transfer, report the length that was decoded
 * and return an empty payload: the decode path -- the direction that sees
 * untrusted input -- is still fully exercised, and the client verifies the
 * server saw the right length.
 */
static void
server_echo_zbytes(
    struct evpl               *evpl,
    struct evpl_rpc2_conn     *conn,
    struct evpl_rpc2_cred     *cred,
    struct zbytes             *call,
    struct evpl_rpc2_encoding *encoding,
    void                      *private_data)
{
    struct server_ctx *ctx = private_data;
    struct zbytes      reply;
    int                i, rc;

    /* A true echo: the zcopaque payload is handed straight back.  The
     * marshaller moves these references onward, so they must not be released
     * here -- only the ones the decoder cloned are ours to drop, below. */
    /*
     * Take ownership of the decoded zero-copy payload before doing anything
     * with it.  On a stream transport this is a no-op and the iovecs are
     * clones the receiver already owns; on an RDMA transport it moves them out
     * of the request's read chunk so that request teardown will not release
     * them a second time.  Calling it unconditionally is what makes a handler
     * transport-agnostic -- see rdma_ddp.c and chimera's nfs3_proc_write.c,
     * which use the same idiom.
     */
    evpl_rpc2_encoding_take_read_chunk(encoding, NULL, NULL);

    memset(&reply, 0, sizeof(reply));
    reply.head = call->z.length;
    reply.tail = call->tail;
    reply.z    = call->z;

    rc = ctx->prog.send_reply_ECHO_ZBYTES(evpl, NULL, &reply, encoding);
    evpl_test_abort_if(rc, "send_reply_ECHO_ZBYTES failed: %d", rc);

    (void) i;
} /* server_echo_zbytes */

/*
 * "strict" has no default arm, so a discriminant that matches no case leaves
 * the arm untouched.  Echoing it would re-marshall whatever the decoder left
 * behind, so report the discriminant instead.
 */
static void
server_probe_strict(
    struct evpl               *evpl,
    struct evpl_rpc2_conn     *conn,
    struct evpl_rpc2_cred     *cred,
    struct strict             *call,
    struct evpl_rpc2_encoding *encoding,
    void                      *private_data)
{
    struct server_ctx  *ctx = private_data;
    struct probe_result reply;
    int                 rc;

    memset(&reply, 0, sizeof(reply));
    reply.seen_k = call->k;
    reply.seen_i = (call->k == K_INT) ? call->i : 0;

    rc = ctx->prog.send_reply_PROBE_STRICT(evpl, NULL, &reply, encoding);
    evpl_test_abort_if(rc, "send_reply_PROBE_STRICT failed: %d", rc);
} /* server_probe_strict */

static void
conformance_program_init(struct server_ctx *ctx)
{
    CONFORMANCE_V1_init(&ctx->prog);
    ctx->prog.recv_call_ECHO_SCALARS  = server_echo_scalars;
    ctx->prog.recv_call_ECHO_BYTES    = server_echo_bytes;
    ctx->prog.recv_call_ECHO_ZBYTES   = server_echo_zbytes;
    ctx->prog.recv_call_ECHO_ARRAYS   = server_echo_arrays;
    ctx->prog.recv_call_ECHO_UNION    = server_echo_union;
    ctx->prog.recv_call_PROBE_STRICT  = server_probe_strict;
    ctx->prog.recv_call_ECHO_OPTIONAL = server_echo_optional;
    ctx->prog.recv_call_ECHO_LIST     = server_echo_list;
    ctx->prog.recv_call_ECHO_NESTED   = server_echo_nested;
} /* conformance_program_init */

/*
 * Deadline helper for the raw-socket phase, which cannot block: the server
 * shares this thread's event loop, so waiting on recv() would deadlock.
 */
static uint64_t
now_ms(void)
{
    struct timespec ts;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
} /* now_ms */

/* ------------------------------------------------------------------ *
* Class -> value mapping
* ------------------------------------------------------------------ */

static int32_t
int_value(uint8_t cls)
{
    switch (cls) {
        case CLS_I32MIN:  return INT32_MIN;
        case CLS_I32NEG1: return -1;
        case CLS_I32ZERO: return 0;
        case CLS_I32ONE:  return 1;
        default:          return INT32_MAX;
    } /* switch */
} /* int_value */

static uint32_t
uint_value(uint8_t cls)
{
    switch (cls) {
        case CLS_U32ZERO: return 0;
        case CLS_U32ONE:  return 1;
        default:          return UINT32_MAX;
    } /* switch */
} /* uint_value */

static int64_t
long_value(uint8_t cls)
{
    switch (cls) {
        case CLS_I64MIN:  return INT64_MIN;
        case CLS_I64NEG1: return -1;
        case CLS_I64ZERO: return 0;
        default:          return INT64_MAX;
    } /* switch */
} /* long_value */

static uint64_t
ulong_value(uint8_t cls)
{
    switch (cls) {
        case CLS_U64ZERO: return 0;
        case CLS_U64ONE:  return 1;
        default:          return UINT64_MAX;
    } /* switch */
} /* ulong_value */

static float
float_value(uint8_t cls)
{
    switch (cls) {
        case CLS_FZERO:    return 0.0f;
        case CLS_FNEGZERO: return -0.0f;
        case CLS_FONE:     return 1.0f;
        case CLS_FNEGONE:  return -1.0f;
        case CLS_FLARGE:   return 3.4e38f;
        default:           return nanf("");
    } /* switch */
} /* float_value */

static double
double_value(uint8_t cls)
{
    switch (cls) {
        case CLS_FZERO:    return 0.0;
        case CLS_FNEGZERO: return -0.0;
        case CLS_FONE:     return 1.0;
        case CLS_FNEGONE:  return -1.0;
        case CLS_FLARGE:   return 1.7e308;
        default:           return nan("");
    } /* switch */
} /* double_value */

/* Byte length for a counted byte field. */
static uint32_t
len_bytes(uint8_t cls)
{
    switch (cls) {
        case CLS_LEMPTY:     return 0;
        case CLS_LONE:       return 1;
        case CLS_LUNALIGNED: return 5;
        case CLS_LALIGNED:   return 4;
        case CLS_LATBOUND:   return BOUNDED_MAX;
        default:             return 1000;
    } /* switch */
} /* len_bytes */

/* Element count for an array, list length, or recursion depth.  Bounded well
 * below the per-message dbuf so a "large" case tests breadth, not exhaustion
 * (exhaustion is the ArrayCountHuge defect's job). */
static uint32_t
len_count(uint8_t cls)
{
    switch (cls) {
        case CLS_LEMPTY:     return 0;
        case CLS_LONE:       return 1;
        case CLS_LUNALIGNED: return 5;
        case CLS_LALIGNED:   return 4;
        case CLS_LATBOUND:   return BOUNDED_MAX;
        default:             return 64;
    } /* switch */
} /* len_count */

static color
color_value(uint8_t cls)
{
    switch (cls) {
        case CLS_COLRED:   return RED;
        case CLS_COLGREEN: return GREEN;
        default:           return BLUE;
    } /* switch */
} /* color_value */

/* ------------------------------------------------------------------ *
* Deep comparison helpers
* ------------------------------------------------------------------ */

static int
scalars_equal(
    const struct scalars *a,
    const struct scalars *b)
{
    /* Floats are compared bitwise: a value comparison would report NaN as
     * unequal to itself and -0.0 as equal to 0.0, and the round trip must
     * preserve both exactly. */
    return a->s32 == b->s32 && a->u32 == b->u32 &&
           a->s64 == b->s64 && a->u64 == b->u64 &&
           memcmp(&a->f32, &b->f32, sizeof(a->f32)) == 0 &&
           memcmp(&a->f64, &b->f64, sizeof(a->f64)) == 0 &&
           a->b == b->b && a->c == b->c;
} /* scalars_equal */

static int
bytes_equal(
    const struct bytes *a,
    const struct bytes *b)
{
    if (a->s.len != b->s.len ||
        (a->s.len && memcmp(a->s.str, b->s.str, a->s.len))) {
        return 0;
    }
    if (a->bounded_s.len != b->bounded_s.len ||
        (a->bounded_s.len &&
         memcmp(a->bounded_s.str, b->bounded_s.str, a->bounded_s.len))) {
        return 0;
    }
    if (a->v.len != b->v.len ||
        (a->v.len && memcmp(a->v.data, b->v.data, a->v.len))) {
        return 0;
    }
    if (a->bounded.len != b->bounded.len ||
        (a->bounded.len && memcmp(a->bounded.data, b->bounded.data, a->bounded.len))) {
        return 0;
    }
    return memcmp(a->f, b->f, FIXED_OPAQUE_LEN) == 0;
} /* bytes_equal */

static int
point_equal(
    const struct point *a,
    const struct point *b)
{
    return a->x == b->x && a->y == b->y;
} /* point_equal */

static int
arrays_equal(
    const struct arrays *a,
    const struct arrays *b)
{
    unsigned int i;

    if (memcmp(a->fixed_u32, b->fixed_u32, sizeof(a->fixed_u32))) {
        return 0;
    }
    if (a->num_var_u32 != b->num_var_u32) {
        return 0;
    }
    for (i = 0; i < a->num_var_u32; i++) {
        if (a->var_u32[i] != b->var_u32[i]) {
            return 0;
        }
    }
    if (a->num_bounded_u32 != b->num_bounded_u32) {
        return 0;
    }
    for (i = 0; i < a->num_bounded_u32; i++) {
        if (a->bounded_u32[i] != b->bounded_u32[i]) {
            return 0;
        }
    }
    for (i = 0; i < 2; i++) {
        if (!point_equal(&a->fixed_pt[i], &b->fixed_pt[i])) {
            return 0;
        }
    }
    if (a->num_var_pt != b->num_var_pt) {
        return 0;
    }
    for (i = 0; i < a->num_var_pt; i++) {
        if (!point_equal(&a->var_pt[i], &b->var_pt[i])) {
            return 0;
        }
    }
    return 1;
} /* arrays_equal */

static int
tagged_equal(
    const struct tagged *a,
    const struct tagged *b)
{
    if (a->k != b->k) {
        return 0;
    }
    switch (a->k) {
        case K_INT:
            return a->i == b->i;
        case K_STR:
            return a->s.len == b->s.len &&
                   (a->s.len == 0 || memcmp(a->s.str, b->s.str, a->s.len) == 0);
        case K_PT:
            return point_equal(&a->p, &b->p);
        default:
            return 1;  /* K_NONE and the default arm carry nothing */
    } /* switch */
} /* tagged_equal */

static int
opt_msg_equal(
    const struct opt_msg *a,
    const struct opt_msg *b)
{
    if (a->head != b->head || a->tail != b->tail) {
        return 0;
    }
    if ((a->opt == NULL) != (b->opt == NULL)) {
        return 0;
    }
    return a->opt == NULL || point_equal(a->opt, b->opt);
} /* opt_msg_equal */

static int
list_msg_equal(
    const struct list_msg *a,
    const struct list_msg *b)
{
    const struct lnode *x = a->head, *y = b->head;

    if (a->trailer != b->trailer) {
        return 0;
    }
    while (x && y) {
        if (x->value != y->value) {
            return 0;
        }
        x = x->nextnode;
        y = y->nextnode;
    }
    return x == NULL && y == NULL;
} /* list_msg_equal */

static int
rec_equal(
    const struct rec *a,
    const struct rec *b)
{
    while (a && b) {
        if (a->depth != b->depth) {
            return 0;
        }
        a = a->chain;
        b = b->chain;
    }
    return a == NULL && b == NULL;
} /* rec_equal */

static int
nested_equal(
    const struct nested *a,
    const struct nested *b)
{
    return point_equal(&a->inner_pt, &b->inner_pt) &&
           scalars_equal(&a->inner_scalars, &b->inner_scalars) &&
           a->tail == b->tail &&
           rec_equal(a->chain, b->chain);
} /* nested_equal */

/* ------------------------------------------------------------------ *
* Value phase
* ------------------------------------------------------------------ */

struct value_state {
    volatile int done;
    int          matched;
    int          status;
    const void  *expect;
    uint32_t     zbytes_len;
    uint32_t     zbytes_tail;
    int          owns_reply_payload;
};

#define REPLY_CALLBACK(NAME, TYPE, CMP)                                      \
        static void                                                              \
        client_reply_ ## NAME(                                                   \
            struct evpl *evpl,                                   \
            const struct evpl_rpc2_verf *verf,                                   \
            struct TYPE *reply,                                  \
            int status,                                 \
            void *private_data)                           \
        {                                                                        \
            struct value_state *st = private_data;                               \
                                                                             \
            st->status  = status;                                                \
            st->matched = (status == 0) && reply &&                              \
                CMP(reply, (const struct TYPE *) st->expect);                    \
            st->done = 1;                                                     \
        }

REPLY_CALLBACK(scalars, scalars, scalars_equal)
REPLY_CALLBACK(bytes, bytes, bytes_equal)
REPLY_CALLBACK(arrays, arrays, arrays_equal)
REPLY_CALLBACK(tagged, tagged, tagged_equal)
REPLY_CALLBACK(opt_msg, opt_msg, opt_msg_equal)
REPLY_CALLBACK(list_msg, list_msg, list_msg_equal)
REPLY_CALLBACK(nested, nested, nested_equal)

/*
 * Compare the bytes of a decoded zcopaque payload against the pattern the
 * request carried.
 *
 * Checking the length alone was enough while every payload travelled inline,
 * because then the length and the bytes come from the same decode.  Once the
 * responder places the payload by RDMA the two are independent: the length
 * arrives in the transport header's Write list while the bytes are written
 * straight into the destination buffer, so a payload placed at the wrong
 * offset, truncated, or never written at all still reports the right length.
 * Only comparing the bytes distinguishes those.
 *
 * The iovecs may describe more than `len` bytes -- a read-into destination is
 * as large as the caller advertised, not as large as the reply -- so each one
 * is clamped to what is left rather than trusted whole.
 */
static int
zpayload_matches(
    const struct zbytes *reply,
    uint32_t             len)
{
    uint32_t off = 0;
    uint32_t n;
    int      i;

    for (i = 0; i < reply->z.niov && off < len; i++) {
        n = reply->z.iov[i].length;

        if (n > len - off) {
            n = len - off;
        }

        if (memcmp(evpl_iovec_data(&reply->z.iov[i]), g_pattern + off, n)) {
            return 0;
        }

        off += n;
    }

    return off == len;
} /* zpayload_matches */

static void
client_reply_zbytes(
    struct evpl                 *evpl,
    const struct evpl_rpc2_verf *verf,
    struct zbytes               *reply,
    int                          status,
    void                        *private_data)
{
    struct value_state *st = private_data;
    int                 i;

    /* head carries back the zcopaque length the server decoded, and the
     * echoed payload must come back with it. */
    st->status  = status;
    st->matched = (status == 0) && reply &&
        reply->head == st->zbytes_len &&
        reply->tail == st->zbytes_tail &&
        reply->z.length == st->zbytes_len &&
        zpayload_matches(reply, st->zbytes_len);
    st->done = 1;

    if (!st->matched && status == 0 && reply) {
        evpl_test_error(
            "zbytes mismatch: head=%u (want %u) tail=%u (want %u) z.length=%u (want %u) z.niov=%d bytes=%s",
            reply->head, st->zbytes_len, reply->tail, st->zbytes_tail,
            reply->z.length, st->zbytes_len, reply->z.niov,
            zpayload_matches(reply, st->zbytes_len) ? "ok" : "WRONG");
    }

    /* Decoding a zcopaque field means owning the references the decoder
     * cloned into it, on a reply exactly as much as on a call, so drop them
     * before the reply goes out of scope.  The decoder hands back one iovec
     * even for a zero-length payload, so this is not conditional on there
     * being any bytes. */
    /* Ownership depends on whether direct placement actually happened.  With a
     * buffer armed on an RDMA transport the reply is written into it and the
     * iovecs merely reference it -- the caller holds the one reference and
     * drops it after the call.  Everywhere else (including the same request on
     * a stream transport, where rpc2.c ignores the chunk arguments entirely)
     * the decoder cloned them and they are ours to release.  Releasing in the
     * borrowed case corrupts the allocator free list into a cycle, which
     * surfaces as a hang in evpl_allocator_destroy at exit. */
    if (reply && st->owns_reply_payload) {
        for (i = 0; i < reply->z.niov; i++) {
            evpl_iovec_release(evpl, &reply->z.iov[i]);
        }
    }
} /* client_reply_zbytes */

static int
wait_for_reply(
    struct evpl        *evpl,
    struct value_state *st)
{
    int spins = 0;

    while (!st->done) {
        evpl_continue(evpl);
        if (++spins > 100000000) {
            return -1;
        }
    }
    return 0;
} /* wait_for_reply */

/* Deliberately far below the reply the ERR_CHUNK check provokes, and below
 * the 512-byte floor rpc2 applies before it will use a Reply chunk at all,
 * so the responder is forced to refuse rather than quietly go inline. */
#define REPLY_CHUNK_TOO_SMALL_BYTES 600

/*
 * A Reply chunk too small for the Reply must be answered with RDMA_ERROR /
 * ERR_CHUNK (RFC 8166 sec 4.5), not by truncating the Reply and not by
 * silently falling back to an inline one.
 *
 * Driven directly rather than from the value model because the model's oracle
 * is round-trip equality -- a call that is *supposed* to fail has no reply to
 * compare.  Both halves of the exchange are under test here: the Responder
 * must detect that the chunk cannot hold the Reply and say so, and the
 * Requester must turn that into a failed call rather than waiting for a reply
 * that will never come.
 *
 * RDMA only: on TCP there are no chunks to get wrong.
 */
static void
check_reply_chunk_too_small(
    struct evpl           *evpl,
    struct CONFORMANCE_V1 *prog,
    struct evpl_rpc2_conn *conn)
{
    struct value_state st;
    struct bytes       arg;

    if (!conn->rdma) {
        return;
    }

    memset(&st, 0, sizeof(st));
    memset(&arg, 0, sizeof(arg));

    /* A reply comfortably over the 512-byte floor below which rpc2 does not
     * bother with a Reply chunk at all, and comfortably over what we offer. */
    arg.s.len         = MAX_PAYLOAD;
    arg.s.str         = (char *) g_pattern;
    arg.bounded_s.len = BOUNDED_MAX;
    arg.bounded_s.str = (char *) g_pattern;
    arg.v.len         = MAX_PAYLOAD;
    arg.v.data        = g_pattern;
    arg.bounded.len   = BOUNDED_MAX;
    arg.bounded.data  = g_pattern;
    memcpy(arg.f, g_pattern, FIXED_OPAQUE_LEN);

    st.expect = &arg;

    prog->send_call_ECHO_BYTES(&prog->rpc2, evpl, conn, NULL, &arg,
                               1, 0, NULL, 0, REPLY_CHUNK_TOO_SMALL_BYTES,
                               client_reply_bytes, &st);

    evpl_test_abort_if(wait_for_reply(evpl, &st),
                       "reply-chunk-too-small: no completion arrived");

    evpl_test_abort_if(st.status != EVPL_RPC2_REPLY_RDMA_ERROR,
                       "reply-chunk-too-small: expected EVPL_RPC2_REPLY_RDMA_ERROR (%d), got %d",
                       EVPL_RPC2_REPLY_RDMA_ERROR, st.status);

    g_results.rdma_error_checks++;

    /* ERR_CHUNK is a per-request refusal, not a transport failure: the
     * connection must still carry an ordinary call afterwards.  Without this
     * the test would pass just as well against an implementation that dropped
     * the connection. */
    memset(&st, 0, sizeof(st));
    memset(&arg, 0, sizeof(arg));
    arg.s.len         = 4;
    arg.s.str         = (char *) g_pattern;
    arg.bounded_s.len = 4;
    arg.bounded_s.str = (char *) g_pattern;
    arg.v.len         = 4;
    arg.v.data        = g_pattern;
    arg.bounded.len   = 4;
    arg.bounded.data  = g_pattern;
    memcpy(arg.f, g_pattern, FIXED_OPAQUE_LEN);
    st.expect = &arg;

    prog->send_call_ECHO_BYTES(&prog->rpc2, evpl, conn, NULL, &arg,
                               0, 0, NULL, 0, 0, client_reply_bytes, &st);

    evpl_test_abort_if(wait_for_reply(evpl, &st),
                       "reply-chunk-too-small: the connection did not survive");
    evpl_test_abort_if(st.status != 0 || !st.matched,
                       "reply-chunk-too-small: follow-up call failed (status %d, matched %d)",
                       st.status, st.matched);

    g_results.rdma_error_checks++;
} /* check_reply_chunk_too_small */

/*
 * State for the ERR_VERS check below.
 */
struct vers_probe {
    volatile int done;
    int          got_rdma_error;
    int          err;
    uint32_t     vers_low;
    uint32_t     vers_high;
};

static void
vers_probe_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct vers_probe *vp = private_data;
    struct rdma_msg    reply;
    xdr_dbuf          *dbuf;

    if (notify->notify_type != EVPL_NOTIFY_RECV_MSG) {
        return;
    }

    dbuf = xdr_dbuf_alloc(4096);

    if (dbuf &&
        unmarshall_rdma_msg(&reply, notify->recv_msg.iovec,
                            notify->recv_msg.niov, NULL, dbuf) > 0 &&
        reply.rdma_body.proc == RDMA_ERROR) {
        vp->got_rdma_error = 1;
        vp->err            = reply.rdma_body.rdma_error.err;

        if (reply.rdma_body.rdma_error.err == ERR_VERS) {
            vp->vers_low  = reply.rdma_body.rdma_error.range.rdma_vers_low;
            vp->vers_high = reply.rdma_body.rdma_error.range.rdma_vers_high;
        }
    }

    if (dbuf) {
        xdr_dbuf_free(dbuf);
    }

    evpl_iovecs_release(evpl, notify->recv_msg.iovec, notify->recv_msg.niov);

    vp->done = 1;
} /* vers_probe_callback */

/*
 * A transport header naming a version we do not speak must be answered with
 * RDMA_ERROR / ERR_VERS carrying the range we do (RFC 8166 sec 4.5).
 *
 * libevpl's own client always stamps version 1, so this cannot be provoked
 * through the rpc2 client API: it needs a peer that builds the transport
 * header itself.  A plain bind on the same transport is exactly that -- the
 * transport still does its own framing, so what is under test is the
 * RPC-over-RDMA header handling and nothing else.
 *
 * RDMA only, and skipped if a plain bind cannot be established.
 */
static void
check_rdma_version_mismatch(
    struct evpl          *evpl,
    struct evpl_endpoint *endpoint,
    int                   proto,
    int                   rdma)
{
    struct vers_probe vp;
    struct rdma_msg   bad;
    struct evpl_bind *bind;
    struct evpl_iovec iov, out_iov;
    int               len, niov, out_niov = 0, spins = 0;

    if (!rdma) {
        return;
    }

    memset(&vp, 0, sizeof(vp));
    memset(&bad, 0, sizeof(bad));

    bind = evpl_connect(evpl, proto, NULL, endpoint, vers_probe_callback,
                        NULL, &vp);

    evpl_test_abort_if(!bind, "version probe: failed to connect a plain bind");

    /* This is a connection the driver dialled like any other, so it has to be
     * counted or check_notifications will see an accept it cannot account
     * for. */
    g_connections_opened++;

    /* Everything but the version is well formed, so the only thing that can
     * make the server refuse it is the version itself.  The first three
     * fields are at fixed positions in every version (RFC 8166 sec 4.2), so
     * a responder is always able to read the xid and answer. */
    bad.rdma_xid       = 0x56455253;
    bad.rdma_vers      = 2;
    bad.rdma_credit    = 1;
    bad.rdma_body.proc = RDMA_MSG;

    bad.rdma_body.rdma_msg.rdma_reads  = NULL;
    bad.rdma_body.rdma_msg.rdma_writes = NULL;
    bad.rdma_body.rdma_msg.rdma_reply  = NULL;

    len  = marshall_length_rdma_msg(&bad);
    niov = evpl_iovec_alloc(evpl, len, 0, 1, 0, &iov);

    evpl_test_abort_if(niov != 1, "version probe: iovec alloc failed");

    marshall_rdma_msg(&bad, &iov, &out_iov, &out_niov, NULL, 0);

    if (out_niov > 0) {
        evpl_iovec_release(evpl, &out_iov);
    }

    evpl_iovec_set_length(&iov, len);

    evpl_sendv(evpl, bind, &iov, 1, len, EVPL_SEND_FLAG_TAKE_REF);

    while (!vp.done && ++spins < 100000000) {
        evpl_continue(evpl);
    }

    evpl_test_abort_if(!vp.done, "version probe: no answer to a bad version");
    evpl_test_abort_if(!vp.got_rdma_error,
                       "version probe: answer was not an RDMA_ERROR");
    evpl_test_abort_if(vp.err != ERR_VERS,
                       "version probe: expected ERR_VERS (%d), got %d",
                       ERR_VERS, vp.err);
    evpl_test_abort_if(vp.vers_low != 1 || vp.vers_high != 1,
                       "version probe: reported range %u-%u, expected 1-1",
                       vp.vers_low, vp.vers_high);

    g_results.rdma_error_checks++;

    evpl_close(evpl, bind);
} /* check_rdma_version_mismatch */

/* ------------------------------------------------------------------ *
* RPC-over-RDMA data placement
*
* Every generated send_call_* takes (ddp, max_rdma_write_chunk,
* write_chunk_iov, write_chunk_niov, max_rdma_reply_chunk).  rpc2.c gates all
* of it on conn->rdma, so these are inert on the stream transport and select
* real chunk-negotiation paths on RDMA-on-TCP -- which is why the same case
* table is run over both.
* ------------------------------------------------------------------ */

#define CHUNK_BUF_BYTES       MAX_PAYLOAD

/*
 * A reply chunk has to hold the entire RPC reply message, not just a payload,
 * and the largest reply in the matrix (ECHO_BYTES with two 1000-byte fields)
 * runs past 2 KiB.  Sized well clear of that: a responder handed a reply chunk
 * too small for the reply truncates it silently rather than reporting
 * ERR_CHUNK, so an undersized buffer here would look like a decode failure
 * with no hint as to why.  See CONFORMANCE.md.
 */
#define REPLY_CHUNK_BUF_BYTES 8192

struct chunk_params {
    int                ddp;
    int                max_write;
    struct evpl_iovec *iov;
    int                niov;
    int                max_reply;
};

static void
chunk_params_init(
    struct evpl                  *evpl,
    struct chunk_params          *cp,
    const struct conf_value_case *c)
{
    memset(cp, 0, sizeof(*cp));

    switch (c->chunk) {
        case CLS_CHUNKNONE:
            break;
        case CLS_CHUNKDDP:
            cp->ddp = 1;
            break;
        case CLS_CHUNKREPLY:
            cp->ddp       = 1;
            cp->max_reply = REPLY_CHUNK_BUF_BYTES;
            break;
        case CLS_CHUNKWRITEALLOC:
            /* A write chunk with no buffer supplied: libevpl allocates the
             * destination itself and the decoded reply points into it, so the
             * references are the client's to release like any other decode. */
            cp->max_write = CHUNK_BUF_BYTES;
            break;
        case CLS_CHUNKWRITEEXACT:
            /* Offer room for exactly the payload the reply will carry, so the
             * responder consumes the segment to its last byte instead of
             * capping it short.  Only ECHO_ZBYTES reaches here (the model
             * confines the write-chunk classes to it), so the reply's payload
             * length is the request's.  A zero-length payload asks for no
             * chunk at all, which is the honest reading of "exactly zero
             * bytes" and leaves the case equivalent to the inline one. */
            cp->max_write = len_bytes(c->opaque_len);
            break;
        default:  /* CLS_CHUNKREADINTO */
            evpl_test_abort_if(
                evpl_iovec_alloc(evpl, CHUNK_BUF_BYTES, 1, 1, 0, &g_chunk_dest) != 1,
                "evpl_iovec_alloc failed for the read-into destination");
            memset(evpl_iovec_data(&g_chunk_dest), 0, CHUNK_BUF_BYTES);
            g_chunk_dest_held = 1;
            cp->max_write     = CHUNK_BUF_BYTES;
            cp->iov           = &g_chunk_dest;
            cp->niov          = 1;
            break;
    } /* switch */
} /* chunk_params_init */

static void
chunk_params_release(struct evpl *evpl)
{
    if (g_chunk_dest_held) {
        evpl_iovec_release(evpl, &g_chunk_dest);
        g_chunk_dest_held = 0;
    }
} /* chunk_params_release */

/* Scratch storage for request construction. */
static struct evpl_iovec g_ziov;
static uint32_t          g_u32_scratch[128];
static struct point      g_pt_scratch[128];
static struct lnode      g_node_scratch[128];
static struct rec        g_rec_scratch[128];

static void
fill_scalars(
    struct scalars               *s,
    const struct conf_value_case *c)
{
    s->s32 = int_value(c->i);
    s->u32 = uint_value(c->u);
    s->s64 = long_value(c->l);
    s->u64 = ulong_value(c->ul);
    s->f32 = float_value(c->f);
    s->f64 = double_value(c->f);
    s->b   = (c->b == CLS_BTRUE);
    s->c   = color_value(c->col);
} /* fill_scalars */

static void
run_value_case(
    struct evpl                  *evpl,
    struct CONFORMANCE_V1        *prog,
    struct evpl_rpc2_conn        *conn,
    const struct conf_value_case *c)
{
    struct value_state  st;
    struct chunk_params cp;
    unsigned int        i, n;
    int                 rc;

    memset(&st, 0, sizeof(st));
    chunk_params_init(evpl, &cp, c);

    /* Who owns the iovecs a decoded zcopaque reply points at.
    *
    * Normally the decoder clones into the reply and the client releases what
    * it decoded.  The one exception is a case that armed its own destination
    * buffer (ChunkReadInto) on a transport that honours it: there the
    * responder RDMA-wrote into that buffer, rpc2.c moved the borrowed iovec
    * into the request's read chunk, and the unmarshaller short-circuited the
    * reply's payload to alias it.  No reference was taken anywhere along that
    * path, so the single reference is the one this driver allocated and it is
    * dropped exactly once, by chunk_params_release.  Releasing it again from
    * the callback corrupts the allocator free list into a cycle, which
    * surfaces as a hang in evpl_allocator_destroy at exit. */
    st.owns_reply_payload = !(c->chunk == CLS_CHUNKREADINTO && conn->rdma);

    switch (c->proc) {
        case CLS_ECHOSCALARS: {
            static struct scalars arg;

            fill_scalars(&arg, c);
            st.expect = &arg;
            prog->send_call_ECHO_SCALARS(&prog->rpc2, evpl, conn, NULL, &arg,
                                         cp.ddp, cp.max_write, cp.iov, cp.niov, cp.max_reply,
                                         client_reply_scalars, &st);
            break;
        }

        case CLS_ECHOBYTES: {
            static struct bytes arg;

            arg.s.len = len_bytes(c->str_len);
            arg.s.str = (char *) g_pattern;
            /* Bounded, so it takes the bounded-length class rather than the
             * string one, which may exceed the declared bound. */
            arg.bounded_s.len = len_bytes(c->bounded_len);
            arg.bounded_s.str = (char *) g_pattern;
            arg.v.len         = len_bytes(c->opaque_len);
            arg.v.data        = g_pattern;
            arg.bounded.len   = len_bytes(c->bounded_len);
            arg.bounded.data  = g_pattern;
            memcpy(arg.f, g_pattern, FIXED_OPAQUE_LEN);
            st.expect = &arg;
            prog->send_call_ECHO_BYTES(&prog->rpc2, evpl, conn, NULL, &arg,
                                       cp.ddp, cp.max_write, cp.iov, cp.niov, cp.max_reply,
                                       client_reply_bytes, &st);
            break;
        }

        case CLS_ECHOZBYTES: {
            static struct zbytes arg;
            uint32_t             zlen = len_bytes(c->opaque_len);

            memset(&arg, 0, sizeof(arg));
            arg.head = uint_value(c->u);
            arg.tail = ~uint_value(c->u);

            if (zlen) {
                /*
                 * Ownership: __marshall_opaque_zerocopy MOVES this reference
                 * into the send path (xdr_iovec_move_private), so the sender
                 * must not release it afterwards -- doing so double-frees and
                 * corrupts the allocator's free list.  The receiving side is
                 * the opposite: the unmarshaller clones, so a handler that
                 * decodes a zcopaque field does have to release it.
                 */
                evpl_test_abort_if(evpl_iovec_alloc(evpl, zlen, 1, 1, 0, &g_ziov) != 1,
                                   "evpl_iovec_alloc failed for %u bytes", zlen);
                memcpy(evpl_iovec_data(&g_ziov), g_pattern, zlen);
                arg.z.iov    = &g_ziov;
                arg.z.niov   = 1;
                arg.z.length = zlen;
            }

            st.zbytes_len  = zlen;
            st.zbytes_tail = arg.tail;
            prog->send_call_ECHO_ZBYTES(&prog->rpc2, evpl, conn, NULL, &arg,
                                        cp.ddp, cp.max_write, cp.iov, cp.niov, cp.max_reply,
                                        client_reply_zbytes, &st);
            break;
        }

        case CLS_ECHOARRAYS: {
            static struct arrays arg;

            memset(&arg, 0, sizeof(arg));
            for (i = 0; i < FIXED_ARRAY_LEN; i++) {
                arg.fixed_u32[i] = uint_value(c->u) ^ i;
            }
            n = len_count(c->arr_len);
            for (i = 0; i < n; i++) {
                g_u32_scratch[i] = i * 3 + 1;
            }
            arg.num_var_u32 = n;
            arg.var_u32     = g_u32_scratch;

            arg.num_bounded_u32 = len_count(c->bounded_len);
            arg.bounded_u32     = g_u32_scratch;

            for (i = 0; i < 2; i++) {
                arg.fixed_pt[i].x = (int32_t) i;
                arg.fixed_pt[i].y = -(int32_t) i;
            }
            n = len_count(c->arr_len);
            for (i = 0; i < n; i++) {
                g_pt_scratch[i].x = (int32_t) i;
                g_pt_scratch[i].y = (int32_t) (i * 2);
            }
            arg.num_var_pt = n;
            arg.var_pt     = g_pt_scratch;

            st.expect = &arg;
            prog->send_call_ECHO_ARRAYS(&prog->rpc2, evpl, conn, NULL, &arg,
                                        cp.ddp, cp.max_write, cp.iov, cp.niov, cp.max_reply,
                                        client_reply_arrays, &st);
            break;
        }

        case CLS_ECHOUNION: {
            static struct tagged arg;

            memset(&arg, 0, sizeof(arg));
            switch (c->arm) {
                case CLS_ARMNONE:
                    arg.k = K_NONE;
                    break;
                case CLS_ARMINT:
                    arg.k = K_INT;
                    arg.i = int_value(c->i);
                    break;
                case CLS_ARMSTR:
                    arg.k     = K_STR;
                    arg.s.len = len_bytes(c->str_len);
                    arg.s.str = (char *) g_pattern;
                    break;
                default:
                    arg.k   = K_PT;
                    arg.p.x = int_value(c->i);
                    arg.p.y = -int_value(c->i);
                    break;
            } /* switch */
            st.expect = &arg;
            prog->send_call_ECHO_UNION(&prog->rpc2, evpl, conn, NULL, &arg,
                                       cp.ddp, cp.max_write, cp.iov, cp.niov, cp.max_reply,
                                       client_reply_tagged, &st);
            break;
        }

        case CLS_ECHOOPTIONAL: {
            static struct opt_msg arg;
            static struct point   pt;

            pt.x     = int_value(c->i);
            pt.y     = -int_value(c->i);
            arg.head = uint_value(c->u);
            arg.tail = ~uint_value(c->u);
            arg.opt  = (c->opt_present == CLS_OPTPRESENT) ? &pt : NULL;

            st.expect = &arg;
            prog->send_call_ECHO_OPTIONAL(&prog->rpc2, evpl, conn, NULL, &arg,
                                          cp.ddp, cp.max_write, cp.iov, cp.niov, cp.max_reply,
                                          client_reply_opt_msg, &st);
            break;
        }

        case CLS_ECHOLIST: {
            static struct list_msg arg;

            n           = len_count(c->depth);
            arg.trailer = uint_value(c->u);
            arg.head    = NULL;
            for (i = 0; i < n; i++) {
                g_node_scratch[i].value    = i * 11 + 5;
                g_node_scratch[i].nextnode = (i + 1 < n) ? &g_node_scratch[i + 1] : NULL;
            }
            if (n) {
                arg.head = &g_node_scratch[0];
            }

            st.expect = &arg;
            prog->send_call_ECHO_LIST(&prog->rpc2, evpl, conn, NULL, &arg,
                                      cp.ddp, cp.max_write, cp.iov, cp.niov, cp.max_reply,
                                      client_reply_list_msg, &st);
            break;
        }

        default: {
            static struct nested arg;

            memset(&arg, 0, sizeof(arg));
            arg.inner_pt.x = int_value(c->i);
            arg.inner_pt.y = -int_value(c->i);
            fill_scalars(&arg.inner_scalars, c);
            arg.tail = uint_value(c->u);

            n = len_count(c->depth);
            for (i = 0; i < n; i++) {
                g_rec_scratch[i].depth = i;
                g_rec_scratch[i].chain = (i + 1 < n) ? &g_rec_scratch[i + 1] : NULL;
            }
            arg.chain = n ? &g_rec_scratch[0] : NULL;

            st.expect = &arg;
            prog->send_call_ECHO_NESTED(&prog->rpc2, evpl, conn, NULL, &arg,
                                        cp.ddp, cp.max_write, cp.iov, cp.niov, cp.max_reply,
                                        client_reply_nested, &st);
            break;
        }
    } /* switch */

    g_results.value_run++;

    rc = wait_for_reply(evpl, &st);

    chunk_params_release(evpl);

    if (rc) {
        evpl_test_error("value case proc=%u: no reply", c->proc);
        g_results.value_failed++;
        return;
    }

    if (!st.matched) {
        evpl_test_error(
            "value case proc=%u status=%d: round trip did not preserve the value "
            "(classes i=%u u=%u l=%u ul=%u f=%u b=%u col=%u str=%u opq=%u bnd=%u arr=%u opt=%u arm=%u depth=%u chunk=%u)",
            c->proc, st.status, c->i, c->u, c->l, c->ul, c->f, c->b, c->col,
            c->str_len, c->opaque_len, c->bounded_len, c->arr_len,
            c->opt_present, c->arm, c->depth, c->chunk);
        g_results.value_failed++;
    }
} /* run_value_case */

/*
 * The value phase runs the server and the client in a single event loop, the
 * way hello_world does: evpl_continue drives both sides, so a call and its
 * reply complete without a second thread.  Two concurrently live evpl
 * instances are deliberately avoided -- evpl_destroy tears down process-wide
 * allocator state, so overlapping lifetimes do not compose.
 */
static void
run_value_phase(
    struct evpl           *evpl,
    struct CONFORMANCE_V1 *prog,
    struct evpl_rpc2_conn *conn)
{
    unsigned int i;

    g_results.rdma_capable = conn->rdma;

    for (i = 0; i < CONF_NUM_VALUE_CASES; i++) {
        /* A case asking for a chunk exercises direct placement on a transport
         * that reports RDMA and the inline fallback on one that does not, so
         * the same case is two different tests depending on where it runs.
         * Counted here so the summary says which of the two this run was. */
        if (conf_value_cases[i].chunk != CLS_CHUNKNONE) {
            g_results.value_chunked++;
        }
        run_value_case(evpl, prog, conn, &conf_value_cases[i]);
    }

    /* Not a model case -- see the comment on the function. */
    check_reply_chunk_too_small(evpl, prog, conn);
} /* run_value_phase */

/* ------------------------------------------------------------------ *
* Defect phase: hand-built wire messages over a raw TCP socket
* ------------------------------------------------------------------ */

struct wirebuf {
    uint8_t  data[4096];
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

/*
 * Offsets of the fields the payload defects target, within each baseline
 * argument encoding below.  Kept as named constants so that a change to a
 * baseline is an obvious compile-time-adjacent edit rather than a silent
 * mis-aimed poke.
 */
#define BYTES_OFF_STRING_LEN   0    /* bytes.s.len                             */
#define BYTES_OFF_BOUNDED_STR  8    /* bytes.bounded_s.len (after s)           */
#define BYTES_OFF_BOUNDED_LEN  24   /* bytes.bounded.len (after s, bounded_s, v) */
#define ARRAYS_OFF_VAR_COUNT   16   /* arrays.num_var_u32 (after fixed)   */
#define ARRAYS_OFF_BOUNDED_CNT 28   /* arrays.num_bounded_u32             */
#define SCALARS_OFF_BOOL       36   /* scalars.b                          */
#define SCALARS_OFF_ENUM       40   /* scalars.c                          */
#define STRICT_OFF_DISCRIM     0    /* strict.k                           */

static int
target_proc(uint8_t target)
{
    switch (target) {
        case TGT_TSCALARS: return PROC_ECHO_SCALARS;
        case TGT_TBYTES:   return PROC_ECHO_BYTES;
        case TGT_TARRAYS:  return PROC_ECHO_ARRAYS;
        default:           return PROC_PROBE_STRICT;
    } /* switch */
} /* target_proc */

/* Build a valid argument encoding for the given target. */
static void
build_args(
    struct wirebuf *b,
    uint8_t         target)
{
    uint32_t i;

    b->len = 0;

    switch (target) {
        case TGT_TSCALARS:
            put32(b, 1);            /* s32 */
            put32(b, 2);            /* u32 */
            put32(b, 0); put32(b, 3); /* s64 */
            put32(b, 0); put32(b, 4); /* u64 */
            put32(b, 0x3f800000);   /* f32 = 1.0 */
            put32(b, 0x3ff00000); put32(b, 0); /* f64 = 1.0 */
            put32(b, 1);            /* b = TRUE */
            put32(b, GREEN);        /* c */
            break;

        case TGT_TBYTES:
            put32(b, 4);            /* s.len          */
            put_bytes(b, g_pattern, 4);
            put32(b, 4);            /* bounded_s.len  */
            put_bytes(b, g_pattern, 4);
            put32(b, 4);            /* v.len          */
            put_bytes(b, g_pattern, 4);
            put32(b, 4);            /* bounded.len */
            put_bytes(b, g_pattern, 4);
            put_bytes(b, g_pattern, FIXED_OPAQUE_LEN);
            break;

        case TGT_TARRAYS:
            for (i = 0; i < FIXED_ARRAY_LEN; i++) {
                put32(b, i);        /* fixed_u32[4] */
            }
            put32(b, 2);            /* num_var_u32  */
            put32(b, 10); put32(b, 11);
            put32(b, 2);            /* num_bounded_u32 */
            put32(b, 20); put32(b, 21);
            put32(b, 1); put32(b, 2);       /* fixed_pt[0] */
            put32(b, 3); put32(b, 4);       /* fixed_pt[1] */
            put32(b, 1);            /* num_var_pt  */
            put32(b, 5); put32(b, 6);
            break;

        default:
            put32(b, K_INT);        /* strict.k */
            put32(b, 7);            /* strict.i */
            break;
    } /* switch */
} /* build_args */

/*
 * A valid `bytes` call whose unbounded opaque carries a large blob.
 *
 * The pathological-fragmentation case needs a message it can divide into more
 * record-mark fragments than the receiver's payload iovec ceiling.  The
 * fragment loop floors a fragment at 4 bytes, so reaching several hundred
 * fragments takes a payload of a few KiB -- far more than the ordinary
 * targets, whose calls run to a hundred bytes or so.  Everything else about
 * the encoding is exactly what build_args(TGT_TBYTES) produces, so the only
 * thing under test is the framing.
 */
#define PATHOLOGICAL_BLOB_LEN  (2 * MAX_PAYLOAD)

/*
 * Fragment count for that case.  Must exceed the receiver's payload iovec
 * ceiling (EVPL_RPC2_MAX_PAYLOAD_NIOV, 256) for the flattening path to be
 * reached at all; the surplus is margin so the case keeps its meaning if that
 * ceiling is raised a little.
 */
#define PATHOLOGICAL_FRAGMENTS 400

static void
build_args_large_bytes(struct wirebuf *b)
{
    uint32_t i;

    b->len = 0;

    put32(b, 4);                              /* s.len              */
    put_bytes(b, g_pattern, 4);
    put32(b, 4);                              /* bounded_s.len      */
    put_bytes(b, g_pattern, 4);

    /* Written as pattern-sized chunks; MAX_PAYLOAD is a multiple of 4, so no
     * padding lands in the middle of the blob. */
    put32(b, PATHOLOGICAL_BLOB_LEN);          /* v.len -- opaque<>  */
    for (i = 0; i < PATHOLOGICAL_BLOB_LEN; i += MAX_PAYLOAD) {
        put_bytes(b, g_pattern, MAX_PAYLOAD);
    }

    put32(b, 4);                              /* bounded.len        */
    put_bytes(b, g_pattern, 4);
    put_bytes(b, g_pattern, FIXED_OPAQUE_LEN);
} /* build_args_large_bytes */

/*
 * Over-bound argument encodings that stay length-consistent.
 *
 * Poking an over-bound length into an otherwise normal message also breaks
 * the total length, so the dispatcher's whole-message check would reject it
 * whether or not the declared bound is enforced -- the case would pass for
 * the wrong reason.  These builders supply the bytes the over-bound length
 * claims, leaving the message perfectly well formed except for exceeding the
 * bound, so only a real bound check can reject it.
 */
static void
build_bytes_over_bound(
    struct wirebuf *b,
    uint32_t        str_len,
    uint32_t        opaque_len)
{
    b->len = 0;
    put32(b, 4);                                /* s.len          */
    put_bytes(b, g_pattern, 4);
    put32(b, str_len);                          /* bounded_s.len  */
    put_bytes(b, g_pattern, str_len);
    put32(b, 4);                                /* v.len          */
    put_bytes(b, g_pattern, 4);
    put32(b, opaque_len);                       /* bounded.len    */
    put_bytes(b, g_pattern, opaque_len);
    put_bytes(b, g_pattern, FIXED_OPAQUE_LEN);  /* f              */
} /* build_bytes_over_bound */

static void
build_arrays_over_bound(
    struct wirebuf *b,
    uint32_t        bounded_count)
{
    uint32_t i;

    b->len = 0;
    for (i = 0; i < FIXED_ARRAY_LEN; i++) {
        put32(b, i);                            /* fixed_u32[4]      */
    }
    put32(b, 2);                                /* num_var_u32       */
    put32(b, 10); put32(b, 11);
    put32(b, bounded_count);                    /* num_bounded_u32   */
    for (i = 0; i < bounded_count; i++) {
        put32(b, 20 + i);
    }
    put32(b, 1); put32(b, 2);                   /* fixed_pt[0]       */
    put32(b, 3); put32(b, 4);                   /* fixed_pt[1]       */
    put32(b, 1);                                /* num_var_pt        */
    put32(b, 5); put32(b, 6);
} /* build_arrays_over_bound */

static void
poke32(
    struct wirebuf *b,
    uint32_t        off,
    uint32_t        v)
{
    evpl_test_abort_if(off + 4 > b->len, "poke past end of args");
    b->data[off]     = (uint8_t) (v >> 24);
    b->data[off + 1] = (uint8_t) (v >> 16);
    b->data[off + 2] = (uint8_t) (v >> 8);
    b->data[off + 3] = (uint8_t) v;
} /* poke32 */

/* Is this defect meaningful against this target?  The RPCSEC_GSS cases are
 * absent here on purpose: they act on the RPC header rather than on procedure
 * arguments, so they are meaningful against every target and useful against
 * exactly one.  run_defect_case picks that one -- see defect_case_first_time. */
static int
defect_applies(
    uint8_t defect,
    uint8_t target)
{
    switch (defect) {
        case DEF_STRINGLENOVERFLOW:
        case DEF_STRINGLENBEYONDMESSAGE:
        case DEF_STRINGEXCEEDSBOUND:
        case DEF_OPAQUEEXCEEDSBOUND:
            return target == TGT_TBYTES;
        case DEF_ARRAYCOUNTEXCEEDSBOUND:
        case DEF_ARRAYCOUNTHUGE:
            return target == TGT_TARRAYS;
        case DEF_DISCRIMINANTUNMATCHED:
            return target == TGT_TSTRICT;
        case DEF_BOOLNOTZEROORONE:
        case DEF_ENUMNOTDECLARED:
            return target == TGT_TSCALARS;
        /* Needs a payload big enough to divide into hundreds of fragments,
        * and is meant to run once rather than across the target matrix. */
        case DEF_CALLSPLITPATHOLOGICAL:
            return target == TGT_TBYTES;
        default:
            return 1;
    } /* switch */
} /* defect_applies */

static int
connect_raw(void)
{
    struct sockaddr_storage ss;
    struct sockaddr_in     *in;
    struct sockaddr_un     *un;
    socklen_t               len;
    int                     fd, flag = 1, family;

    memset(&ss, 0, sizeof(ss));

    /* The defect phase writes record-marked bytes onto a socket of its own,
     * so it follows whichever stream transport the run is using.  Record
     * marking is a property of the framing rather than of the address family,
     * so the same defects are expressible over AF_UNIX as over TCP. */
    if (evpl_protocol_is_local(proto)) {
        family = AF_UNIX;
        un     = (struct sockaddr_un *) &ss;

        un->sun_family = AF_UNIX;
        snprintf(un->sun_path, sizeof(un->sun_path), "%s", g_address);

        /* An abstract name is a leading NUL followed by the name, not a
         * NUL-terminated path. */
        if (g_address[0] == '@') {
            un->sun_path[0] = '\0';
            len             = offsetof(struct sockaddr_un, sun_path) +
                1 + strlen(g_address + 1);
        } else {
            len = sizeof(*un);
        }
    } else {
        family = AF_INET;
        in     = (struct sockaddr_in *) &ss;

        in->sin_family      = AF_INET;
        in->sin_port        = htons(port);
        in->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        len                 = sizeof(*in);
    }

    fd = socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (fd < 0) {
        return -1;
    }

    /* Loopback connect completes into the listen backlog without the server
     * having accepted yet, so EINPROGRESS here is success as far as writing
     * the request goes. */
    if (connect(fd, (struct sockaddr *) &ss, len) < 0 &&
        errno != EINPROGRESS) {
        close(fd);
        return -1;
    }

    if (family == AF_INET) {
        setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &flag, sizeof(flag));
    }

    g_connections_opened++;

    return fd;
} /* connect_raw */

static int
send_all(
    struct evpl *evpl,
    int          fd,
    const void  *buf,
    size_t       len)
{
    const uint8_t *p        = buf;
    uint64_t       deadline = now_ms() + REPLY_TIMEOUT_MS;
    ssize_t        n;

    while (len) {
        n = send(fd, p, len, MSG_NOSIGNAL);
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

/*
 * Write one record-mark fragment: the 4-byte mark, terminal bit set only for
 * the last of a record, followed by the payload.  Returns -1 if either write
 * could not be completed, which on a connection the server has already
 * dropped is an outcome rather than an error.
 */
static int
send_fragment(
    struct evpl *evpl,
    int          fd,
    const void  *data,
    uint32_t     len,
    int          last)
{
    uint8_t  hdr[4];
    uint32_t m = (last ? 0x80000000u : 0u) | len;

    hdr[0] = (uint8_t) (m >> 24);
    hdr[1] = (uint8_t) (m >> 16);
    hdr[2] = (uint8_t) (m >> 8);
    hdr[3] = (uint8_t) m;

    if (send_all(evpl, fd, hdr, 4)) {
        return -1;
    }

    return len ? send_all(evpl, fd, data, len) : 0;
} /* send_fragment */

/*
 * Read one record-marked reply and classify it.  Returns an EXP_ or ACT_ code.
 */
static int
read_outcome_full(
    struct evpl *evpl,
    int          fd,
    uint32_t    *out_lo,
    uint32_t    *out_hi,
    uint8_t     *results,
    uint32_t    *results_len)
{
    uint8_t  buf[4096];
    uint32_t mark, want, off = 0;
    uint64_t deadline = now_ms() + REPLY_TIMEOUT_MS;
    ssize_t  n;
    uint32_t xid, mtype, rstat, pos;

    *out_lo = *out_hi = 0;

    /* Record mark.  evpl_continue drives the server, which shares this
     * thread, so the reply can only arrive while we are pumping. */
    while (off < 4) {
        n = recv(fd, buf + off, 4 - off, 0);
        if (n == 0) {
            return EXP_CLOSED;
        }
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                return EXP_CLOSED;
            }
            evpl_continue(evpl);
            if (now_ms() > deadline) {
                return ACT_STALLED;
            }
            continue;
        }
        off += n;
    }

    mark = get32(buf);
    want = mark & 0x7fffffff;
    if (want > sizeof(buf)) {
        return ACT_MALFORMED;
    }

    off = 0;
    while (off < want) {
        n = recv(fd, buf + off, want - off, 0);
        if (n == 0) {
            return EXP_CLOSED;
        }
        if (n < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK) {
                return EXP_CLOSED;
            }
            evpl_continue(evpl);
            if (now_ms() > deadline) {
                return ACT_STALLED;
            }
            continue;
        }
        off += n;
    }

    if (want < 12) {
        return ACT_MALFORMED;
    }

    xid   = get32(buf);
    mtype = get32(buf + 4);
    rstat = get32(buf + 8);
    (void) xid;

    if (mtype != 1) {  /* REPLY */
        return ACT_MALFORMED;
    }

    if (rstat == 0) {  /* MSG_ACCEPTED */
        uint32_t verf_len, astat;

        if (want < 20) {
            return ACT_MALFORMED;
        }
        verf_len = get32(buf + 16);
        pos      = 20 + ((verf_len + 3) & ~3u);
        if (pos + 4 > want) {
            return ACT_MALFORMED;
        }
        astat = get32(buf + pos);
        pos  += 4;

        if (results && results_len) {
            uint32_t avail = want - pos;

            if (avail > *results_len) {
                avail = *results_len;
            }
            memcpy(results, buf + pos, avail);
            *results_len = avail;
        }

        switch (astat) {
            case 0: return EXP_SUCCESS;
            case 1: return EXP_PROGUNAVAIL;
            case 2:
                if (pos + 8 <= want) {
                    *out_lo = get32(buf + pos);
                    *out_hi = get32(buf + pos + 4);
                }
                return EXP_PROGMISMATCH;
            case 3: return EXP_PROCUNAVAIL;
            case 4: return EXP_GARBAGEARGS;
            case 5: return ACT_SYSTEM_ERR;
            default: return ACT_MALFORMED;
        } /* switch */
    }

    if (rstat == 1) {  /* MSG_DENIED */
        uint32_t jstat;

        if (want < 16) {
            return ACT_MALFORMED;
        }
        jstat = get32(buf + 12);
        if (jstat == 0) {  /* RPC_MISMATCH */
            if (want >= 24) {
                *out_lo = get32(buf + 16);
                *out_hi = get32(buf + 20);
            }
            return EXP_RPCMISMATCH;
        }
        return EXP_AUTHERROR;
    }

    return ACT_MALFORMED;
} /* read_outcome */

static int
read_outcome(
    struct evpl *evpl,
    int          fd,
    uint32_t    *out_lo,
    uint32_t    *out_hi)
{
    return read_outcome_full(evpl, fd, out_lo, out_hi, NULL, NULL);
} /* read_outcome */

static int
read_outcome_body(
    struct evpl *evpl,
    int          fd,
    uint8_t     *results,
    uint32_t    *results_len)
{
    uint32_t lo, hi;

    return read_outcome_full(evpl, fd, &lo, &hi, results, results_len);
} /* read_outcome_body */

/* Append an argument encoding to a message already under construction. */
static void
build_args_into(
    struct wirebuf *b,
    uint8_t         target)
{
    struct wirebuf tmp;

    build_args(&tmp, target);
    evpl_test_abort_if(b->len + tmp.len > sizeof(b->data),
                       "wire buffer overflow");
    memcpy(b->data + b->len, tmp.data, tmp.len);
    b->len += tmp.len;
} /* build_args_into */

/*
 * A well-formed AUTH_SYS credential body (RFC 5531 sec 8.2): stamp,
 * machinename<255>, uid, gid, gids<16>.  The other AUTH_SYS case in the matrix
 * declares a length that runs off the end of the message, so without this one
 * the flavor's accepted path -- the whole of the credential decode -- would
 * never be reached by anything.
 */
static void
build_authsys_cred(struct wirebuf *b)
{
    static const char machine[] = "conformance";
    uint32_t          i;

    b->len = 0;
    put32(b, 0x53595300);                        /* stamp        */
    put32(b, (uint32_t) (sizeof(machine) - 1));  /* machinename  */
    put_bytes(b, machine, sizeof(machine) - 1);
    put32(b, 1000);                              /* uid          */
    put32(b, 100);                               /* gid          */
    put32(b, 3);                                 /* gids<16>     */
    for (i = 0; i < 3; i++) {
        put32(b, 200 + i);
    }
} /* build_authsys_cred */

/* ------------------------------------------------------------------ *
* RPCSEC_GSS (RFC 2203)
*
* libevpl owns the RPCSEC_GSS framing but links no mechanism, so these cases
* run against the deterministic provider in gss_stub.c.  Because the stub's
* MIC is reproducible here, the driver can present verifiers the server
* accepts -- which is what makes the success paths reachable instead of only
* the rejections.
* ------------------------------------------------------------------ */

#define RPCSEC_GSS_FLAVOR    6
#define RPCSEC_GSS_VERS_1    1

#define RPCSEC_GSS_DATA      0
#define RPCSEC_GSS_INIT      1
#define RPCSEC_GSS_CONT_INIT 2
#define RPCSEC_GSS_DESTROY   3

#define GSS_SVC_NONE         1
#define GSS_SVC_INTEGRITY    2
#define GSS_SVC_PRIVACY      3

/* Bytes the client signs: the header from the xid through the credential,
 * i.e. xid..proc (24) + the credential's flavor and length (8) + the
 * credential body, padded.  Mirrors rpc2.c's signed_len computation. */
static uint32_t
gss_signed_len(uint32_t cred_len)
{
    return 24 + 8 + ((cred_len + 3) & ~3u);
} /* gss_signed_len */

/* Append an RPCSEC_GSS credential and return its unpadded body length. */
static uint32_t
put_gss_cred(
    struct wirebuf *b,
    uint32_t        version,
    uint32_t        gss_proc,
    uint32_t        seq,
    uint32_t        service,
    const uint32_t *handle)
{
    uint32_t body_len = 4 * 4 + 4 + (handle ? 4 : 0);

    put32(b, RPCSEC_GSS_FLAVOR);
    put32(b, body_len);
    put32(b, version);
    put32(b, gss_proc);
    put32(b, seq);
    put32(b, service);
    if (handle) {
        put32(b, 4);
        put32(b, *handle);
    } else {
        put32(b, 0);
    }
    return body_len;
} /* put_gss_cred */

/* Send one framed message and read the reply's accept/reject classification,
 * optionally handing back the results body so a caller can parse it. */
static int
gss_exchange(
    struct evpl    *evpl,
    int             fd,
    struct wirebuf *msg,
    uint8_t        *results,
    uint32_t       *results_len)
{
    uint8_t  hdr[4];
    uint32_t m = 0x80000000u | msg->len;

    hdr[0] = (uint8_t) (m >> 24);
    hdr[1] = (uint8_t) (m >> 16);
    hdr[2] = (uint8_t) (m >> 8);
    hdr[3] = (uint8_t) m;

    if (send_all(evpl, fd, hdr, 4) || send_all(evpl, fd, msg->data, msg->len)) {
        return ACT_MALFORMED;
    }

    return read_outcome_body(evpl, fd, results, results_len);
} /* gss_exchange */

/*
 * The same exchange, but with the call delivered as two record fragments split
 * at `split_at` bytes.  RFC 5531 sec 10 puts no constraint on where a fragment
 * boundary falls, and the security flavor is not supposed to notice: the
 * server has to reassemble first and verify afterwards.  The interesting
 * consequence is that the reassembled message reaches the GSS layer as several
 * buffers rather than one, so every byte range it needs -- the signed header,
 * the databody, the checksum -- has to be gathered across them.
 */
static int
gss_exchange_split(
    struct evpl    *evpl,
    int             fd,
    struct wirebuf *msg,
    uint32_t        split_at,
    uint8_t        *results,
    uint32_t       *results_len)
{
    uint8_t  hdr[4];
    uint32_t part[2], off = 0;
    int      i;

    evpl_test_abort_if(split_at == 0 || split_at >= msg->len,
                       "gss fragment split point outside the message");

    part[0] = split_at;
    part[1] = msg->len - split_at;

    for (i = 0; i < 2; i++) {
        uint32_t m = (i == 1 ? 0x80000000u : 0u) | part[i];

        hdr[0] = (uint8_t) (m >> 24);
        hdr[1] = (uint8_t) (m >> 16);
        hdr[2] = (uint8_t) (m >> 8);
        hdr[3] = (uint8_t) m;

        if (send_all(evpl, fd, hdr, 4) ||
            send_all(evpl, fd, msg->data + off, part[i])) {
            return ACT_MALFORMED;
        }
        off += part[i];
    }

    return read_outcome_body(evpl, fd, results, results_len);
} /* gss_exchange_split */

/* How the GSS token in an rpc_gss_init_arg should be encoded. */
#define INIT_TOKEN_GOOD    0   /* a well-formed opaque<>                    */
#define INIT_TOKEN_ABSENT  1   /* no arguments at all: not even a length    */
#define INIT_TOKEN_OVERRUN 2   /* a length that runs past the message       */

/*
 * Build one leg of the context-establishment handshake.  The handshake rides
 * on the program's NULL procedure and its arguments are an rpc_gss_init_arg,
 * i.e. a lone opaque token (RFC 2203 sec 5.2.2).
 */
static void
build_gss_init_call(
    struct wirebuf *msg,
    uint32_t        xid,
    uint32_t        gss_proc,
    const uint32_t *handle,
    int             token_mode)
{
    msg->len = 0;
    put32(msg, xid);
    put32(msg, 0);                      /* CALL */
    put32(msg, 2);
    put32(msg, CONF_PROG);
    put32(msg, CONF_VERS);
    put32(msg, 0);                      /* NULL procedure */
    put_gss_cred(msg, RPCSEC_GSS_VERS_1, gss_proc, 0, GSS_SVC_NONE, handle);
    put32(msg, 0);                      /* verf AUTH_NONE */
    put32(msg, 0);

    switch (token_mode) {
        case INIT_TOKEN_ABSENT:
            break;
        case INIT_TOKEN_OVERRUN:
            put32(msg, 0x10000);        /* token<> longer than the message */
            put_bytes(msg, "INIT", 4);
            break;
        default:
            put32(msg, 4);              /* token<> */
            put_bytes(msg, "INIT", 4);
            break;
    } /* switch */
} /* build_gss_init_call */

/*
 * Drive the context-establishment handshake and return the handle the server
 * assigned.  The handshake rides on the program's NULL procedure, so this also
 * exercises the interaction between RPCSEC_GSS and the generated proc 0.
 */
static int
gss_establish(
    struct evpl *evpl,
    int          fd,
    uint32_t    *out_handle,
    int          legs)
{
    struct wirebuf msg;
    uint8_t        results[512];
    uint32_t       results_len, hlen;
    int            outcome, leg;

    for (leg = 0; leg < legs; leg++) {
        build_gss_init_call(&msg, 0x47535331 + leg,
                            leg == 0 ? RPCSEC_GSS_INIT : RPCSEC_GSS_CONT_INIT,
                            leg == 0 ? NULL : out_handle,
                            INIT_TOKEN_GOOD);

        results_len = sizeof(results);
        outcome     = gss_exchange(evpl, fd, &msg, results, &results_len);

        if (outcome != EXP_SUCCESS) {
            return outcome;
        }

        /* rpc_gss_init_res: handle<>, major, minor, seq_window, token<> */
        if (results_len < 12) {
            return ACT_MALFORMED;
        }
        hlen = get32(results);
        if (hlen != 4) {
            return ACT_MALFORMED;
        }
        *out_handle = get32(results + 4);
    }

    return EXP_SUCCESS;
} /* gss_establish */

/* Build a DATA call carrying a correctly computed header MIC. */
static void
build_gss_data_call(
    struct wirebuf *msg,
    uint32_t        xid,
    uint32_t        handle,
    uint32_t        seq,
    uint32_t        service,
    int             good_mic,
    int             gss_verf)
{
    uint8_t  mic[GSS_STUB_MIC_LEN];
    uint32_t cred_len;

    msg->len = 0;
    put32(msg, xid);
    put32(msg, 0);                          /* CALL */
    put32(msg, 2);
    put32(msg, CONF_PROG);
    put32(msg, CONF_VERS);
    put32(msg, PROC_ECHO_SCALARS);
    cred_len = put_gss_cred(msg, RPCSEC_GSS_VERS_1, RPCSEC_GSS_DATA,
                            seq, service, &handle);

    if (gss_verf) {
        gss_stub_mic(msg->data, gss_signed_len(cred_len), mic);
        if (!good_mic) {
            mic[0] ^= 0xff;
        }
        put32(msg, RPCSEC_GSS_FLAVOR);
        put32(msg, GSS_STUB_MIC_LEN);
        put_bytes(msg, mic, GSS_STUB_MIC_LEN);
    } else {
        put32(msg, 0);                      /* verf AUTH_NONE */
        put32(msg, 0);
    }

    build_args_into(msg, TGT_TSCALARS);
} /* build_gss_data_call */

/*
 * Build an integrity-service (krb5i) DATA call.  RFC 2203 sec 5.3.2.2 puts the
 * arguments on the wire as
 *   rpc_gss_integ_data { opaque databody<>; opaque checksum<>; }
 * where databody is seq_num || proc_args and checksum is a MIC over it.
 *
 * body_seq is taken separately from the credential's seq so that a case can
 * make the two disagree -- the one thing the RFC forbids about an otherwise
 * well-formed databody -- while still presenting a checksum that verifies.
 *
 * with_args selects between a procedure that takes arguments and NULLPROC,
 * whose databody is nothing but the seq_num.  A zero-length inner call is not
 * an edge case dreamt up for the test: proc 0 is mandatory (RFC 5531 sec 11.1)
 * and clients use it as a ping, so it is the first krb5i call a real client
 * makes.
 */
static void
build_gss_integ_call(
    struct wirebuf *msg,
    uint32_t        xid,
    uint32_t        handle,
    uint32_t        seq,
    uint32_t        body_seq,
    int             good_checksum,
    int             with_args)
{
    struct wirebuf databody;
    uint8_t        mic[GSS_STUB_MIC_LEN];
    uint32_t       cred_len;

    msg->len = 0;
    put32(msg, xid);
    put32(msg, 0);                          /* CALL */
    put32(msg, 2);
    put32(msg, CONF_PROG);
    put32(msg, CONF_VERS);
    put32(msg, with_args ? PROC_ECHO_SCALARS : 0);
    cred_len = put_gss_cred(msg, RPCSEC_GSS_VERS_1, RPCSEC_GSS_DATA,
                            seq, GSS_SVC_INTEGRITY, &handle);

    /* The header MIC covers the message up to and including the credential,
     * so it has to be taken before the verifier or the arguments land. */
    gss_stub_mic(msg->data, gss_signed_len(cred_len), mic);
    put32(msg, RPCSEC_GSS_FLAVOR);
    put32(msg, GSS_STUB_MIC_LEN);
    put_bytes(msg, mic, GSS_STUB_MIC_LEN);

    databody.len = 0;
    put32(&databody, body_seq);
    if (with_args) {
        build_args_into(&databody, TGT_TSCALARS);
    }

    put32(msg, databody.len);
    put_bytes(msg, databody.data, databody.len);

    /* The checksum covers the unpadded databody, which is what the server
     * gathers back out of the message. */
    gss_stub_mic(databody.data, databody.len, mic);
    if (!good_checksum) {
        mic[0] ^= 0xff;
    }
    put32(msg, GSS_STUB_MIC_LEN);
    put_bytes(msg, mic, GSS_STUB_MIC_LEN);
} /* build_gss_integ_call */

/* Ways an rpc_gss_integ_data can fail to decode.  Each one keeps the
 * credential, the header MIC and the sequence number valid, so the caller is
 * authenticated and only the argument framing is at fault -- which is what
 * makes GARBAGE_ARGS rather than a denial the required answer (RFC 2203
 * sec 5.3.3.4.2). */
#define INTEG_BAD_NO_LENGTH   0   /* arguments too short to hold a length   */
#define INTEG_BAD_SHORT_BODY  1   /* databody shorter than its own seq_num  */
#define INTEG_BAD_LONG_BODY   2   /* databody length past the message       */
#define INTEG_BAD_NO_CHECKSUM 3   /* message ends where the checksum begins */
#define INTEG_BAD_LONG_CKSUM  4   /* checksum length past the message       */

static void
build_gss_integ_bad_call(
    struct wirebuf *msg,
    uint32_t        xid,
    uint32_t        handle,
    uint32_t        seq,
    int             mode)
{
    struct wirebuf databody;
    uint8_t        mic[GSS_STUB_MIC_LEN];
    uint32_t       cred_len;

    msg->len = 0;
    put32(msg, xid);
    put32(msg, 0);                          /* CALL */
    put32(msg, 2);
    put32(msg, CONF_PROG);
    put32(msg, CONF_VERS);
    put32(msg, PROC_ECHO_SCALARS);
    cred_len = put_gss_cred(msg, RPCSEC_GSS_VERS_1, RPCSEC_GSS_DATA,
                            seq, GSS_SVC_INTEGRITY, &handle);

    gss_stub_mic(msg->data, gss_signed_len(cred_len), mic);
    put32(msg, RPCSEC_GSS_FLAVOR);
    put32(msg, GSS_STUB_MIC_LEN);
    put_bytes(msg, mic, GSS_STUB_MIC_LEN);

    if (mode == INTEG_BAD_NO_LENGTH) {
        /* Two bytes of arguments: not enough for the databody's length
         * prefix, let alone a databody. */
        msg->data[msg->len++] = 0;
        msg->data[msg->len++] = 0;
        return;
    }

    if (mode == INTEG_BAD_SHORT_BODY) {
        /* A databody too short to carry the seq_num it must begin with. */
        put32(msg, 2);
        put_bytes(msg, "\0\0", 2);
        put32(msg, GSS_STUB_MIC_LEN);
        put_bytes(msg, mic, GSS_STUB_MIC_LEN);
        return;
    }

    databody.len = 0;
    put32(&databody, seq);
    build_args_into(&databody, TGT_TSCALARS);

    if (mode == INTEG_BAD_LONG_BODY) {
        put32(msg, databody.len + 4096);
        put_bytes(msg, databody.data, databody.len);
        put32(msg, GSS_STUB_MIC_LEN);
        put_bytes(msg, mic, GSS_STUB_MIC_LEN);
        return;
    }

    put32(msg, databody.len);
    put_bytes(msg, databody.data, databody.len);

    if (mode == INTEG_BAD_NO_CHECKSUM) {
        return;                             /* no checksum opaque at all */
    }

    /* INTEG_BAD_LONG_CKSUM */
    gss_stub_mic(databody.data, databody.len, mic);
    put32(msg, 4096);
    put_bytes(msg, mic, GSS_STUB_MIC_LEN);
} /* build_gss_integ_bad_call */

/*
 * Build a DATA call whose RPCSEC_GSS credential is deliberately undecodable.
 * Everything after it is well formed, so the credential is the only thing
 * wrong with the call and the auth_stat cannot be blamed on anything else.
 */
static void
build_gss_bad_cred_call(
    struct wirebuf *msg,
    uint32_t        xid,
    int             overrun)
{
    msg->len = 0;
    put32(msg, xid);
    put32(msg, 0);                          /* CALL */
    put32(msg, 2);
    put32(msg, CONF_PROG);
    put32(msg, CONF_VERS);
    put32(msg, PROC_ECHO_SCALARS);

    put32(msg, RPCSEC_GSS_FLAVOR);
    if (overrun) {
        /* Complete through the fixed fields, then a handle<> whose length
         * runs off the end of the credential body. */
        put32(msg, 20);
        put32(msg, RPCSEC_GSS_VERS_1);
        put32(msg, RPCSEC_GSS_DATA);
        put32(msg, 1);                      /* seq     */
        put32(msg, GSS_SVC_NONE);
        put32(msg, 64);                     /* handle<> length */
    } else {
        /* Stops after the fixed fields: the handle<> length is simply not
         * there. */
        put32(msg, 16);
        put32(msg, RPCSEC_GSS_VERS_1);
        put32(msg, RPCSEC_GSS_DATA);
        put32(msg, 1);                      /* seq     */
        put32(msg, GSS_SVC_NONE);
    }

    put32(msg, 0);                          /* verf AUTH_NONE */
    put32(msg, 0);
    build_args_into(msg, TGT_TSCALARS);
} /* build_gss_bad_cred_call */

/*
 * Check that a reply came back wrapped for the integrity service: the results
 * must be an rpc_gss_integ_data whose databody is the request's seq_num
 * followed by the procedure results, under a checksum that verifies.  Without
 * this, a server that skipped the wrapping entirely would still look like a
 * success, since the accept status alone says nothing about the wrapping.
 */
static int
check_integ_reply(
    const uint8_t *results,
    uint32_t       len,
    uint32_t       seq,
    int            with_args)
{
    struct wirebuf args;
    uint8_t        expect[GSS_STUB_MIC_LEN];
    uint32_t       db_len, db_pad, ck_len;

    if (len < 8) {
        return 0;
    }

    db_len = get32(results);
    db_pad = (db_len + 3) & ~3u;
    if (db_len < 4 || 4 + db_pad + 4 > len) {
        return 0;
    }

    ck_len = get32(results + 4 + db_pad);
    if (ck_len != GSS_STUB_MIC_LEN || 4 + db_pad + 4 + ck_len > len) {
        return 0;
    }

    gss_stub_mic(results + 4, db_len, expect);
    if (memcmp(expect, results + 4 + db_pad + 4, GSS_STUB_MIC_LEN)) {
        return 0;
    }

    if (get32(results + 4) != seq) {
        return 0;
    }

    /* NULLPROC returns nothing, so its wrapped databody is the seq_num and
     * not a byte more.  A server that padded it out with something would
     * still checksum correctly, so the length is the only thing that says
     * the empty result survived the wrapping intact. */
    if (!with_args) {
        return db_len == 4;
    }

    /* Every handler echoes, so the unwrapped results must be the arguments
     * that went in -- which is what proves the server decoded the inner call
     * rather than handing back the wrapper it was given. */
    build_args(&args, TGT_TSCALARS);
    return db_len - 4 == args.len &&
           memcmp(results + 8, args.data, args.len) == 0;
} /* check_integ_reply */

/*
 * Build an RPCSEC_GSS_DESTROY control message.  RFC 2203 sec 5.4: framed like
 * a data request, but with gss_proc set to DESTROY, NULLPROC in the header and
 * no procedure arguments.
 */
static void
build_gss_destroy_call(
    struct wirebuf *msg,
    uint32_t        xid,
    uint32_t        handle,
    uint32_t        seq,
    int             gss_verf)
{
    uint8_t  mic[GSS_STUB_MIC_LEN];
    uint32_t cred_len;

    msg->len = 0;
    put32(msg, xid);
    put32(msg, 0);                          /* CALL */
    put32(msg, 2);
    put32(msg, CONF_PROG);
    put32(msg, CONF_VERS);
    put32(msg, 0);                          /* NULLPROC */
    cred_len = put_gss_cred(msg, RPCSEC_GSS_VERS_1, RPCSEC_GSS_DESTROY,
                            seq, GSS_SVC_NONE, &handle);

    if (gss_verf) {
        gss_stub_mic(msg->data, gss_signed_len(cred_len), mic);
        put32(msg, RPCSEC_GSS_FLAVOR);
        put32(msg, GSS_STUB_MIC_LEN);
        put_bytes(msg, mic, GSS_STUB_MIC_LEN);
    } else {
        put32(msg, 0);                      /* verf AUTH_NONE */
        put32(msg, 0);
    }
} /* build_gss_destroy_call */

/*
 * Compare one observed outcome against what the model requires and record it.
 * Shared by the byte-level defect path and the RPCSEC_GSS path so both report
 * divergences the same way.
 */
static void
record_outcome(
    const struct conf_defect_case *c,
    int                            actual,
    uint32_t                       lo,
    uint32_t                       hi)
{
    /* For the mismatch outcomes the version range is part of the contract: a
     * client uses it to decide what to retry, so the right reply carrying the
     * wrong range is still a divergence. */
    if (actual == c->expect &&
        (actual == EXP_PROGMISMATCH || actual == EXP_RPCMISMATCH) &&
        c->expect_lo >= 0 &&
        ((int32_t) lo != c->expect_lo || (int32_t) hi != c->expect_hi)) {
        if (!is_known_divergence(c->defect, c->expect, ACT_BADRANGE)) {
            evpl_test_error(
                "defect %s: %s reported version range [%u,%u], expected [%d,%d]",
                defect_name(c->defect), outcome_name(actual), lo, hi,
                c->expect_lo, c->expect_hi);
            g_results.defect_unknown++;
            return;
        }
        g_results.defect_known++;
        return;
    }

    if (actual == c->expect) {
        g_results.defect_matched++;
        return;
    }

    if (is_known_divergence(c->defect, c->expect, actual)) {
        g_results.defect_known++;
        return;
    }

    evpl_test_error("defect %s (target %u): expected %s, got %s",
                    defect_name(c->defect), c->target,
                    outcome_name(c->expect), outcome_name(actual));
    g_results.defect_unknown++;
} /* record_outcome */

/*
 * Is this one of the RPCSEC_GSS cases?  Enumerated rather than expressed as an
 * enum range: the generated enum's order follows the model's defect list, and
 * a later defect appended between two GSS ones would silently break a range
 * test while this one still compiles into the right answer.
 */
static int
defect_is_gss(uint8_t defect)
{
    switch (defect) {
        case DEF_GSSINITESTABLISHES:
        case DEF_GSSINITCONTINUES:
        case DEF_GSSINITMECHFAILS:
        case DEF_GSSDATAVALID:
        case DEF_GSSCREDVERSIONWRONG:
        case DEF_GSSPROCUNKNOWN:
        case DEF_GSSSERVICEPRIVACY:
        case DEF_GSSHANDLEUNKNOWN:
        case DEF_GSSVERIFIERNOTGSS:
        case DEF_GSSMICWRONG:
        case DEF_GSSSEQREPLAYED:
        case DEF_GSSINTEGDATAVALID:
        case DEF_GSSINTEGCHECKSUMWRONG:
        case DEF_GSSINTEGSEQMISMATCH:
        case DEF_GSSDESTROYCONTEXT:
        case DEF_GSSDESTROYUNAUTHENTICATED:
        case DEF_GSSSEQABOVEMAX:
        case DEF_GSSSEQWINDOWJUMP:
        case DEF_GSSSEQTOOOLD:
        case DEF_GSSSEQOUTOFORDER:
        case DEF_GSSCREDTRUNCATED:
        case DEF_GSSCREDHANDLEOVERRUNS:
        case DEF_GSSNOMECHANISM:
        case DEF_GSSCONTINUEINITUNKNOWNHANDLE:
        case DEF_GSSINITTOKENMALFORMED:
        case DEF_GSSCONTINUEINITTOKENMALFORMED:
        case DEF_GSSINITMECHFAILSWITHTOKEN:
        case DEF_GSSINTEGFRAMINGBAD:
        case DEF_GSSINTEGEMPTYARGS:
        case DEF_GSSINTEGSPLITACROSSFRAGMENTS:
        case DEF_GSSINTEGREPLYMICFAILS:
        case DEF_GSSINTEGREPLYMICOVERSIZE:
            return 1;
        default:
            return 0;
    } /* switch */
} /* defect_is_gss */

/*
 * A defect that acts on the envelope or the framing rather than on the
 * procedure arguments -- every RPCSEC_GSS case, and the reassembly cap,
 * which is decided before a single argument byte is read -- is worth running
 * once, against whichever target the model
 * happened to pair it with first.  Pinning it to a single named target instead
 * would make the case silently vanish on any run where the sampler never drew
 * that one pair -- which is not a hypothetical: the generated table routinely
 * omits a handful of (defect, target) combinations.
 *
 * "Once" means once per (defect, param): a parameterised GSS defect carries
 * its variant in the param, so de-duplicating on the defect alone would run
 * the first value the sampler produced and silently drop every other -- which
 * is exactly the opposite of what enumerating the values in the model was
 * for.
 */
struct defect_case_key {
    uint8_t defect;
    int64_t param;
};

static struct defect_case_key g_defect_case_seen[256];
static unsigned int           g_defect_case_nseen;

static int
defect_case_first_time(
    uint8_t defect,
    int64_t param)
{
    unsigned int i;

    for (i = 0; i < g_defect_case_nseen; i++) {
        if (g_defect_case_seen[i].defect == defect &&
            g_defect_case_seen[i].param == param) {
            return 0;
        }
    }

    evpl_test_abort_if(g_defect_case_nseen >= sizeof(g_defect_case_seen) /
                       sizeof(g_defect_case_seen[0]),
                       "too many distinct RPCSEC_GSS cases");

    g_defect_case_seen[g_defect_case_nseen].defect = defect;
    g_defect_case_seen[g_defect_case_nseen].param  = param;
    g_defect_case_nseen++;
    return 1;
} /* defect_case_first_time */

/*
 * Turn the absence of a reply into a verdict.
 *
 * Silence alone does not distinguish a deliberate discard from a server that
 * has stopped making progress, so a case that was met with nothing has to
 * prove the connection still works: a fresh, valid sequence number on the same
 * context must still be answered.  If it is, the silence was a decision --
 * NO_REPLY -- and if it is not, the server is simply stalled.  `outcome` is
 * passed through untouched when a reply did arrive, so this can wrap any
 * exchange whose answer may or may not be silence.
 */
static int
gss_classify_silence(
    struct evpl *evpl,
    int          fd,
    int          outcome,
    uint32_t     handle,
    uint32_t     next_seq)
{
    struct wirebuf msg;

    if (outcome != ACT_STALLED) {
        return outcome;
    }

    build_gss_data_call(&msg, 0x47535360 + next_seq, handle, next_seq,
                        GSS_SVC_NONE, 1, 1);
    if (gss_exchange(evpl, fd, &msg, NULL, NULL) != EXP_SUCCESS) {
        return ACT_STALLED;
    }
    return EXP_NOREPLY;
} /* gss_classify_silence */

/*
 * Run one RPCSEC_GSS case on its own connection.
 *
 * Cases that act on an established context perform the handshake first, so
 * each one is self-contained: the context, its handle and its sequence window
 * all belong to this connection and cannot leak into another case.
 */
static int
run_gss_case(
    struct evpl                   *evpl,
    const struct conf_defect_case *c,
    int                            fd)
{
    struct wirebuf msg;
    uint32_t       handle = 0;
    uint32_t       lo, hi;
    int            outcome;

    /* The stub's behaviour is part of the case, not a fixed backdrop. */
    gss_stub_set_behaviour(
        c->defect == DEF_GSSINITMECHFAILS ? GSS_STUB_ACCEPT_FAIL :
        c->defect == DEF_GSSINITMECHFAILSWITHTOKEN ? GSS_STUB_ACCEPT_FAIL_TOK :
        c->defect == DEF_GSSINITCONTINUES ||
        c->defect == DEF_GSSCONTINUEINITTOKENMALFORMED
            ? GSS_STUB_ACCEPT_CONTINUE :
        GSS_STUB_ACCEPT_COMPLETE,
        GSS_STUB_VERIFY_HONEST,
        /* Only the reply-signing cases break get_mic, and only for the
         * databody: the handshake below has to succeed first, and its
         * verifiers are MICs too. */
        c->defect == DEF_GSSINTEGREPLYMICFAILS ? GSS_STUB_MIC_FAIL_BODY :
        c->defect == DEF_GSSINTEGREPLYMICOVERSIZE ? GSS_STUB_MIC_HUGE_BODY :
        GSS_STUB_MIC_HONEST);

    switch (c->defect) {
        case DEF_GSSINITESTABLISHES:
            return gss_establish(evpl, fd, &handle, 1);

        case DEF_GSSINITCONTINUES:
            /* Two legs: the first must be answered so the second can follow. */
            return gss_establish(evpl, fd, &handle, 2);

        case DEF_GSSINITMECHFAILS:
        case DEF_GSSINITMECHFAILSWITHTOKEN:
            return gss_establish(evpl, fd, &handle, 1);

        case DEF_GSSINITTOKENMALFORMED:
            /* An INIT whose rpc_gss_init_arg cannot be decoded.  No context
             * exists yet, so whatever the server made to hold one has to be
             * unmade before it answers. */
            build_gss_init_call(&msg, 0x4753534c, RPCSEC_GSS_INIT, NULL,
                                c->param == 0 ? INIT_TOKEN_ABSENT
                                              : INIT_TOKEN_OVERRUN);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSCONTINUEINITUNKNOWNHANDLE:
            /* A CONTINUE_INIT for a context the server never issued. */
            handle = 0xdeadbeef;
            build_gss_init_call(&msg, 0x4753534d, RPCSEC_GSS_CONT_INIT,
                                &handle, INIT_TOKEN_GOOD);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSCREDTRUNCATED:
        case DEF_GSSCREDHANDLEOVERRUNS:
            build_gss_bad_cred_call(&msg, 0x4753534e,
                                    c->defect == DEF_GSSCREDHANDLEOVERRUNS);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSNOMECHANISM:
            /* Take the mechanism away for the duration of one call: libevpl
            * carries the RPCSEC_GSS framing but links no mechanism of its
            * own, so "flavor 6 arrives at a server that has none configured"
            * is the shipped default, not a contrived state.  Both entry
            * points have to refuse it -- a context-creation request (param
            * 0) and a data request (param 1) reach the check separately. */
            evpl_rpc2_set_gss_provider(g_thread, NULL, NULL);

            if (c->param == 0) {
                build_gss_init_call(&msg, 0x47535361, RPCSEC_GSS_INIT, NULL,
                                    INIT_TOKEN_GOOD);
            } else {
                build_gss_data_call(&msg, 0x47535362, 1, 1, GSS_SVC_NONE,
                                    1, 1);
            }
            outcome = gss_exchange(evpl, fd, &msg, NULL, NULL);

            evpl_rpc2_set_gss_provider(g_thread, gss_stub_provider(), NULL);
            return outcome;

        case DEF_GSSCREDVERSIONWRONG:
        case DEF_GSSPROCUNKNOWN:
            msg.len = 0;
            put32(&msg, 0x47535332);
            put32(&msg, 0);
            put32(&msg, 2);
            put32(&msg, CONF_PROG);
            put32(&msg, CONF_VERS);
            put32(&msg, PROC_ECHO_SCALARS);
            put_gss_cred(&msg,
                         c->defect == DEF_GSSCREDVERSIONWRONG
                             ? (uint32_t) c->param : RPCSEC_GSS_VERS_1,
                         c->defect == DEF_GSSPROCUNKNOWN
                             ? (uint32_t) c->param : RPCSEC_GSS_DATA,
                         0, GSS_SVC_NONE, &handle);
            put32(&msg, 0);
            put32(&msg, 0);
            build_args_into(&msg, TGT_TSCALARS);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSSERVICEPRIVACY:
            build_gss_data_call(&msg, 0x47535333, handle, 1,
                                GSS_SVC_PRIVACY, 1, 0);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSHANDLEUNKNOWN:
            build_gss_data_call(&msg, 0x47535334, 0xdeadbeef, 1,
                                GSS_SVC_NONE, 1, 1);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        default:
            break;
    } /* switch */

    /* Everything below needs a live context. */
    outcome = gss_establish(evpl, fd, &handle, 1);
    if (outcome != EXP_SUCCESS) {
        return outcome;
    }

    switch (c->defect) {
        case DEF_GSSDATAVALID:
            build_gss_data_call(&msg, 0x47535340, handle, 1, GSS_SVC_NONE, 1, 1);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSCONTINUEINITTOKENMALFORMED:
            /* The handshake above stopped at CONTINUE_NEEDED, so the handle
             * names a real half-built context.  Its second leg then carries a
             * token that cannot be decoded: the context must survive the
             * refusal -- it is the caller's argument that was bad, not the
             * context -- which is the opposite of the INIT case, where there
             * is nothing worth keeping. */
            build_gss_init_call(&msg, 0x4753534f, RPCSEC_GSS_CONT_INIT,
                                &handle, INIT_TOKEN_OVERRUN);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSVERIFIERNOTGSS:
            /* A DATA call whose verifier is AUTH_NONE rather than a MIC. */
            build_gss_data_call(&msg, 0x47535341, handle, 1, GSS_SVC_NONE, 1, 0);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSMICWRONG:
            build_gss_data_call(&msg, 0x47535342, handle, 1, GSS_SVC_NONE, 0, 1);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSINTEGDATAVALID:
        {
            uint8_t  results[512];
            uint32_t results_len = sizeof(results);

            build_gss_integ_call(&msg, 0x47535346, handle, 1, 1, 1, 1);
            outcome = gss_exchange(evpl, fd, &msg, results, &results_len);
            if (outcome != EXP_SUCCESS) {
                return outcome;
            }
            return check_integ_reply(results, results_len, 1, 1)
                   ? EXP_SUCCESS : ACT_MALFORMED;
        }

        case DEF_GSSINTEGEMPTYARGS:
        {
            uint8_t  results[512];
            uint32_t results_len = sizeof(results);

            build_gss_integ_call(&msg, 0x47535350, handle, 1, 1, 1, 0);
            outcome = gss_exchange(evpl, fd, &msg, results, &results_len);
            if (outcome != EXP_SUCCESS) {
                return outcome;
            }
            return check_integ_reply(results, results_len, 1, 0)
                   ? EXP_SUCCESS : ACT_MALFORMED;
        }

        case DEF_GSSINTEGSPLITACROSSFRAGMENTS:
        {
            uint8_t  results[512];
            uint32_t results_len = sizeof(results);

            build_gss_integ_call(&msg, 0x47535351, handle, 1, 1, 1, 1);

            /* Split inside the databody, past the RPC header: the header
             * checksum then sits wholly in the first fragment while the
             * databody and its checksum straddle the boundary, so the server
             * has to gather each of them across two buffers -- and the
             * checksum's gather begins beyond the end of the first. */
            evpl_test_abort_if(msg.len < 60, "integrity call unexpectedly short");
            outcome = gss_exchange_split(evpl, fd, &msg, msg.len - 40,
                                         results, &results_len);
            if (outcome != EXP_SUCCESS) {
                return outcome;
            }
            return check_integ_reply(results, results_len, 1, 1)
                   ? EXP_SUCCESS : ACT_MALFORMED;
        }

        case DEF_GSSINTEGREPLYMICFAILS:
        case DEF_GSSINTEGREPLYMICOVERSIZE:
        {
            uint8_t  results[512];
            uint32_t results_len = sizeof(results);

            /* The call itself is impeccable; only the server's own signature
             * over the results cannot be produced.  A reply that comes back
             * anyway is therefore an unsigned reply on a channel the client
             * asked to have signed, which is what the outcome comparison
             * catches -- and check_integ_reply confirms it really is
             * unwrapped rather than wrapped in some other way. */
            build_gss_integ_call(&msg, 0x47535352, handle, 1, 1, 1, 1);
            outcome = gss_exchange(evpl, fd, &msg, results, &results_len);
            if (outcome != EXP_SUCCESS) {
                return outcome;
            }
            return check_integ_reply(results, results_len, 1, 1)
                   ? ACT_MALFORMED : EXP_SUCCESS;
        }

        case DEF_GSSINTEGCHECKSUMWRONG:
            build_gss_integ_call(&msg, 0x47535347, handle, 1, 1, 0, 1);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSINTEGSEQMISMATCH:
            /* The checksum is computed over the tampered databody, so the
             * databody itself verifies and the seq consistency check is the
             * only thing left that can reject the call. */
            build_gss_integ_call(&msg, 0x47535348, handle, 1, 2, 1, 1);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSINTEGFRAMINGBAD:
            build_gss_integ_bad_call(&msg, 0x47535353, handle, 1,
                                     (int) c->param);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSSEQWINDOWJUMP:
            /* A jump far clear of the window: the window cannot slide to
             * cover it and has to be reset outright.  Both calls must be
             * answered -- the second proves the reset left a usable window
             * behind rather than a wedged one. */
            build_gss_data_call(&msg, 0x47535354, handle, 1, GSS_SVC_NONE, 1, 1);
            outcome = gss_exchange(evpl, fd, &msg, NULL, NULL);
            if (outcome != EXP_SUCCESS) {
                return outcome;
            }
            build_gss_data_call(&msg, 0x47535355, handle, 5000, GSS_SVC_NONE,
                                1, 1);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSSEQOUTOFORDER:
            /* Inside the window, unseen, and not the next number: the case
             * the window exists for. */
            build_gss_data_call(&msg, 0x47535356, handle, 10, GSS_SVC_NONE,
                                1, 1);
            outcome = gss_exchange(evpl, fd, &msg, NULL, NULL);
            if (outcome != EXP_SUCCESS) {
                return outcome;
            }
            build_gss_data_call(&msg, 0x47535357, handle, 5, GSS_SVC_NONE,
                                1, 1);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        case DEF_GSSSEQTOOOLD:
            /* Move the window well past the sequence number we then present,
             * so it has fallen out of the bottom rather than merely being a
             * repeat. */
            build_gss_data_call(&msg, 0x47535358, handle, 200, GSS_SVC_NONE,
                                1, 1);
            outcome = gss_exchange(evpl, fd, &msg, NULL, NULL);
            if (outcome != EXP_SUCCESS) {
                return outcome;
            }
            build_gss_data_call(&msg, 0x47535359, handle, 1, GSS_SVC_NONE,
                                1, 1);
            outcome = gss_exchange(evpl, fd, &msg, NULL, NULL);
            return gss_classify_silence(evpl, fd, outcome, handle, 201);

        case DEF_GSSSEQABOVEMAX:
            /* Above MAXSEQ.  Nothing about the context is wrong, so a server
             * that discards this instead of answering leaves the client with
             * no way to learn it must refresh. */
            build_gss_data_call(&msg, 0x4753535a, handle, 0x80000001,
                                GSS_SVC_NONE, 1, 1);
            outcome = gss_exchange(evpl, fd, &msg, NULL, NULL);
            return gss_classify_silence(evpl, fd, outcome, handle, 5);

        case DEF_GSSDESTROYCONTEXT:
            build_gss_destroy_call(&msg, 0x47535349, handle, 1, 1);
            outcome = gss_exchange(evpl, fd, &msg, NULL, NULL);
            if (outcome != EXP_SUCCESS) {
                return outcome;
            }
            /* An acknowledged DESTROY that left the context usable would pass
             * on the reply alone, so make the context prove it is gone. */
            build_gss_data_call(&msg, 0x4753534a, handle, 2, GSS_SVC_NONE, 1, 1);
            return gss_exchange(evpl, fd, &msg, NULL, NULL) == EXP_AUTHERROR
                   ? EXP_SUCCESS : ACT_MALFORMED;

        case DEF_GSSDESTROYUNAUTHENTICATED:
            build_gss_destroy_call(&msg, 0x4753534b, handle, 1, 0);
            return gss_exchange(evpl, fd, &msg, NULL, NULL);

        default:  /* DEF_GSSSEQREPLAYED */
            /* Use a sequence number, then use it again.  The first call must
             * succeed; the replay must be met with silence. */
            build_gss_data_call(&msg, 0x47535343, handle, 7, GSS_SVC_NONE, 1, 1);
            outcome = gss_exchange(evpl, fd, &msg, NULL, NULL);
            if (outcome != EXP_SUCCESS) {
                return outcome;
            }

            build_gss_data_call(&msg, 0x47535344, handle, 7, GSS_SVC_NONE, 1, 1);
            outcome = gss_exchange(evpl, fd, &msg, NULL, NULL);
            (void) lo;
            (void) hi;
            return gss_classify_silence(evpl, fd, outcome, handle, 8);
    } /* switch */
} /* run_gss_case */

static void
run_defect_case(
    struct evpl                   *evpl,
    const struct conf_defect_case *c)
{
    struct wirebuf args, msg, cred;
    uint32_t       prog = CONF_PROG, vers = CONF_VERS, rpcvers = 2;
    uint32_t       proc = target_proc(c->target);
    uint32_t       cred_flavor = 0, cred_len = 0;
    uint32_t       lo = 0, hi = 0;
    uint32_t       mark_override = 0;
    int            fd, actual, use_mark_override = 0, fragments = 1;
    int            truncate_by = 0, trailing = 0, reasm_flood = 0;

    if (!defect_applies(c->defect, c->target)) {
        g_results.defect_skipped++;
        return;
    }

    /* Framing is refused before any argument encoding is examined, so running
     * this against all four targets would be the same test four times over
     * with a different unread payload.  Same rule as the RPCSEC_GSS cases,
     * and for the same reason -- see defect_case_first_time. */
    if (c->defect == DEF_REASSEMBLYCAPEXCEEDED &&
        !defect_case_first_time(c->defect, c->param)) {
        g_results.defect_skipped++;
        return;
    }

    if (defect_is_gss(c->defect)) {
        if (!defect_case_first_time(c->defect, c->param)) {
            g_results.defect_skipped++;
            return;
        }

        fd = connect_raw();
        if (fd < 0) {
            evpl_test_error("defect case %s: connect failed", defect_name(c->defect));
            g_results.defect_unknown++;
            return;
        }
        g_results.defect_run++;
        actual = run_gss_case(evpl, c, fd);
        close(fd);
        record_outcome(c, actual, 0, 0);
        return;
    }

    build_args(&args, c->target);
    cred.len = 0;

    /* Apply the defect. */
    switch (c->defect) {
        case DEF_NODEFECT:
            break;
        case DEF_RPCVERSWRONG:
            rpcvers = (uint32_t) c->param;
            break;
        case DEF_PROGRAMUNKNOWN:
            prog = 0x5eadbeef;
            break;
        case DEF_VERSIONUNSUPPORTED:
            vers = (uint32_t) c->param;
            break;
        case DEF_PROCEDUREUNKNOWN:
            proc     = (uint32_t) c->param;
            args.len = 0;
            break;
        case DEF_PROCEDURENULL:
            proc     = 0;
            args.len = 0;
            break;
        case DEF_AUTHFLAVORUNSUPPORTED:
            cred_flavor = (uint32_t) c->param;
            break;
        case DEF_CREDBODYOVERLONG:
            /* A credential whose declared body length runs past the message. */
            cred_flavor = 1;   /* AUTH_SYS */
            cred_len    = 0x0fffffff;
            break;
        case DEF_AUTHSYSVALID:
            cred_flavor = 1;   /* AUTH_SYS */
            build_authsys_cred(&cred);
            cred_len = cred.len;
            break;
        case DEF_ARGSTRUNCATED:
            truncate_by = (int) c->param;
            break;
        case DEF_ARGSTRAILINGGARBAGE:
            trailing = (int) c->param;
            break;
        case DEF_STRINGLENOVERFLOW:
            poke32(&args, BYTES_OFF_STRING_LEN, 0xffffffff);
            break;
        case DEF_STRINGLENBEYONDMESSAGE:
            poke32(&args, BYTES_OFF_STRING_LEN, 0x1000);
            break;
        case DEF_STRINGEXCEEDSBOUND:
            build_bytes_over_bound(&args, BOUNDED_MAX + 1, 4);
            break;
        case DEF_OPAQUEEXCEEDSBOUND:
            build_bytes_over_bound(&args, 4, BOUNDED_MAX + 1);
            break;
        case DEF_ARRAYCOUNTEXCEEDSBOUND:
            build_arrays_over_bound(&args, BOUNDED_MAX + 1);
            break;
        case DEF_ARRAYCOUNTHUGE:
            poke32(&args, ARRAYS_OFF_VAR_COUNT, 0x40000000);
            break;
        case DEF_DISCRIMINANTUNMATCHED:
            poke32(&args, STRICT_OFF_DISCRIM, 99);
            break;
        case DEF_BOOLNOTZEROORONE:
            poke32(&args, SCALARS_OFF_BOOL, 2);
            break;
        case DEF_ENUMNOTDECLARED:
            poke32(&args, SCALARS_OFF_ENUM, 99);
            break;
        case DEF_RECORDMARKHUGE:
            use_mark_override = 1;
            mark_override     = 0x7fffffff;
            break;
        case DEF_RECORDMARKZEROLENGTH:
            use_mark_override = 1;
            mark_override     = 0;
            break;
        case DEF_CALLSPLITACROSSFRAGMENTS:
            fragments = (int) c->param;
            break;
        /* Swap in the large payload and ask for more fragments than the
         * receiver's payload iovec ceiling, so it has to flatten the
         * reassembled message rather than pass the iovecs straight through. */
        case DEF_CALLSPLITPATHOLOGICAL:
            build_args_large_bytes(&args);
            fragments = PATHOLOGICAL_FRAGMENTS;
            break;
        /* Legal fragments, illegal total: the record is never terminated and
         * is walked past the receiver's per-message cap. */
        case DEF_REASSEMBLYCAPEXCEEDED:
            reasm_flood = 1;
            break;
        default:
            break;
    } /* switch */

    /* Assemble the RPC call message (without the record mark). */
    msg.len = 0;
    put32(&msg, 0x436f6e66);      /* xid */
    put32(&msg, 0);               /* CALL */
    put32(&msg, rpcvers);
    put32(&msg, prog);
    put32(&msg, vers);
    put32(&msg, proc);
    put32(&msg, cred_flavor);
    put32(&msg, cred_len);
    if (cred.len) {
        evpl_test_abort_if(msg.len + cred.len > sizeof(msg.data),
                           "message buffer overflow");
        memcpy(msg.data + msg.len, cred.data, cred.len);
        msg.len += cred.len;
    }
    put32(&msg, 0);               /* verf flavor AUTH_NONE */
    put32(&msg, 0);               /* verf length           */

    if (truncate_by > 0 && (uint32_t) truncate_by <= args.len) {
        args.len -= truncate_by;
    }
    if (args.len) {
        evpl_test_abort_if(msg.len + args.len > sizeof(msg.data),
                           "message buffer overflow");
        memcpy(msg.data + msg.len, args.data, args.len);
        msg.len += args.len;
    }
    if (trailing > 0) {
        evpl_test_abort_if(msg.len + trailing > (int) sizeof(msg.data),
                           "message buffer overflow");
        memset(msg.data + msg.len, 0xa5, trailing);
        msg.len += trailing;
    }

    fd = connect_raw();
    if (fd < 0) {
        evpl_test_error("defect case %s: connect failed", defect_name(c->defect));
        g_results.defect_unknown++;
        return;
    }

    g_results.defect_run++;

    if (use_mark_override) {
        uint8_t  hdr[4];
        uint32_t m = 0x80000000u | mark_override;

        hdr[0] = (uint8_t) (m >> 24);
        hdr[1] = (uint8_t) (m >> 16);
        hdr[2] = (uint8_t) (m >> 8);
        hdr[3] = (uint8_t) m;
        send_all(evpl, fd, hdr, 4);
        /* For the huge mark, send a token body so the server has something to
         * buffer while it waits for the rest that will never arrive. */
        if (mark_override) {
            send_all(evpl, fd, msg.data, msg.len);
        }
    } else if (reasm_flood) {
        uint32_t total = 0;
        int      i;

        /*
         * The leading fragment is the real, well-formed call, so what the
         * receiver is asked to hold is a genuine partial message rather than
         * noise; everything after it is filler, because the point is that the
         * record must be refused on its accumulated length alone, before any
         * of it is parsed.  No fragment carries the terminal bit: the record
         * is never completed, and a receiver that does not bound reassembly
         * will hold every byte of it for as long as the peer keeps talking.
         */
        if (!send_fragment(evpl, fd, msg.data, msg.len, 0)) {
            total = msg.len;

            for (i = 0;
                 i < REASM_FLOOD_FRAGS && total <= CONF_MAX_MESSAGE_SIZE;
                 i++) {
                if (send_fragment(evpl, fd, g_reasm_filler,
                                  REASM_FLOOD_FRAG_LEN, 0)) {
                    /* The receiver dropped the connection mid-flood, which is
                     * the outcome under test; read_outcome confirms it. */
                    break;
                }
                total += REASM_FLOOD_FRAG_LEN;
            }
        }
    } else if (fragments > 1) {
        uint32_t chunk = msg.len / fragments;
        uint32_t sent  = 0;
        int      i;

        if (chunk < 4) {
            chunk = 4;
        }
        for (i = 0; i < fragments && sent < msg.len; i++) {
            uint32_t this_len = (i == fragments - 1) ? msg.len - sent : chunk;

            if (sent + this_len > msg.len) {
                this_len = msg.len - sent;
            }
            send_fragment(evpl, fd, msg.data + sent, this_len,
                          sent + this_len >= msg.len);
            sent += this_len;
        }
    } else {
        send_fragment(evpl, fd, msg.data, msg.len, 1);
    }

    actual = read_outcome(evpl, fd, &lo, &hi);
    close(fd);

    record_outcome(c, actual, lo, hi);
} /* run_defect_case */


/*
 * The defect phase needs the server serviced while the driver does blocking
 * socket I/O, so here the server gets its own thread and the main thread
 * speaks raw TCP -- the multifrag topology.  The value phase has fully torn
 * its event loop down by this point.
 */
static void
run_defect_phase(struct evpl *evpl)
{
    unsigned int i;

    for (i = 0; i < CONF_NUM_DEFECT_CASES; i++) {
        run_defect_case(evpl, &conf_defect_cases[i]);
    }
} /* run_defect_phase */

/* ------------------------------------------------------------------ *
* main
* ------------------------------------------------------------------ */

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
    struct server_ctx          ctx;
    struct evpl               *evpl;
    struct evpl_rpc2_server   *server;
    struct evpl_rpc2_conn     *conn;
    struct evpl_endpoint      *endpoint;
    struct evpl_rpc2_program  *programs[1];
    struct evpl_thread_config *tcfg;
    uint64_t                   drain_deadline;
    int                        opt, rc, failed;

    conformance_evpl_config();

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

    pattern_init();

    /*
     * Server and client share one event loop and one thread.  The raw-socket
     * phase therefore never blocks on the socket: it pumps evpl_continue
     * between non-blocking reads, since the server that owes it a reply is
     * running on this same thread.  Exactly one evpl is created for the whole
     * run -- a second create/destroy cycle wedges process exit.
     */
    memset(&ctx, 0, sizeof(ctx));

    /*
     * A bounded wait is required, not merely nice: the default (-1) parks
     * evpl_continue in the poller until something happens, and the defect
     * cases that expect no reply at all would never come back to check their
     * deadline.
     *
     * evpl_create() takes ownership of the config and releases it itself.
     */
    tcfg = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(tcfg, 1);
    evpl = evpl_create(tcfg);

    conformance_program_init(&ctx);
    programs[0] = &ctx.prog.rpc2;

    server = evpl_rpc2_server_init(programs, 1);
    /* A name-addressed transport (AF_UNIX, inproc) has no wildcard bind and no
     * port, so the address is resolved once here.  test_address() derives a
     * per-pid socket name under the build tree, which is what makes these runs
     * safe to execute concurrently without a network namespace or a port
     * lock -- the name is what has to be unique, not the port. */
    g_address = test_address(proto, "0.0.0.0", argv[0]);
    endpoint  = evpl_endpoint_create(g_address, port);
    evpl_rpc2_server_start(server, proto, endpoint);

    /* Two distinct private-data values, so that a notification reporting the
     * wrong one is visible rather than indistinguishable -- see
     * conformance_notify, which asserts which notification carries which. */
    g_server_private = &ctx;
    g_thread_private = &g_notify;

    g_thread = evpl_rpc2_thread_init(evpl, programs, 1, conformance_notify,
                                     g_thread_private);

    /* Register the deterministic GSS provider so the RPCSEC_GSS cases have a
     * mechanism to talk to.  Without one, libevpl rejects flavor-6 calls with
     * AUTH_REJECTEDCRED before reaching any of the framing under test. */
    evpl_rpc2_set_gss_provider(g_thread, gss_stub_provider(), NULL);

    evpl_rpc2_server_attach(g_thread, server, g_server_private);

    conn = evpl_rpc2_client_connect(g_thread, proto, endpoint, NULL, 0, NULL);
    evpl_test_abort_if(!conn, "failed to connect RPC2 client");
    g_connections_opened++;

    evpl_test_info("running %u value cases", (unsigned int) CONF_NUM_VALUE_CASES);
    run_value_phase(evpl, &ctx.prog, conn);

    /* Needs a peer that writes its own transport header, so it runs outside
     * the rpc2 client -- see the comment on the function. */
    check_rdma_version_mismatch(evpl, endpoint, proto, conn->rdma);

    /* The raw-socket phase needs a stream transport it can open a socket of
     * its own onto: TCP or AF_UNIX.  RDMA carries no record marks, so the
     * framing defects are not expressible there, and inproc has no descriptor
     * to write to at all. */
    if (proto == EVPL_STREAM_SOCKET_TCP || evpl_protocol_is_local(proto)) {
        evpl_test_info("running %u defect cases",
                       (unsigned int) CONF_NUM_DEFECT_CASES);
        run_defect_phase(evpl);
    } else {
        evpl_test_info(
            "skipping defect phase (needs a stream transport with a socket)");
    }

    /*
     * The defect phase leaves behind connections in every state the server
     * knows how to reach -- half-open, mid-reassembly, closed by the peer.
     * Give the loop a chance to retire them before tearing it down.
     */
    drain_deadline = now_ms() + 200;
    while (now_ms() < drain_deadline) {
        evpl_continue(evpl);
    }

    evpl_rpc2_server_stop(server);
    evpl_rpc2_client_disconnect(g_thread, conn);
    evpl_rpc2_server_detach(g_thread, server);
    evpl_rpc2_thread_destroy(g_thread);

    /* Only now can no further notification arrive: thread_destroy closes what
     * the run left behind and pumps until rpc2 has retired all of it. */
    check_notifications();

    /* The client connection the driver holds must be the one the notification
     * path identified as unaccepted -- if those two disagree, the pointer the
     * callback reported is not the connection the caller was handed, and
     * everything the callback said about it was about something else. */
    notify_check(g_notify.client_conn == conn,
                 "the connection reported as this process's client is %p, "
                 "but evpl_rpc2_client_connect returned %p",
                 (void *) g_notify.client_conn, (void *) conn);

    evpl_rpc2_server_destroy(server);
    evpl_destroy(evpl);

    printf("value cases:  %d run, %d failed (%d requesting chunks, placed %s)\n",
           g_results.value_run, g_results.value_failed, g_results.value_chunked,
           g_results.rdma_capable ? "by RDMA" : "inline -- transport reports no RDMA");
    if (g_results.rdma_error_checks) {
        printf("rdma error:   %d assertions (ERR_CHUNK refusal, connection survives, ERR_VERS range)\n",
               g_results.rdma_error_checks);
    }
    printf("defect cases: %d run, %d matched spec, %d known divergences, "
           "%d unexpected, %d not applicable\n",
           g_results.defect_run, g_results.defect_matched,
           g_results.defect_known, g_results.defect_unknown,
           g_results.defect_skipped);
    printf("notifications: %d accepted, %d connected, %d disconnected, "
           "%d incoherent\n",
           g_notify.accepted, g_notify.connected, g_notify.disconnected,
           g_notify.errors);

    failed = g_results.value_failed || g_results.defect_unknown ||
        g_notify.errors;

    printf("Test %s\n", failed ? "FAILED" : "PASSED");
    return failed ? 1 : 0;
} /* main */
