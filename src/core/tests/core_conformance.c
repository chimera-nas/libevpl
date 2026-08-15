/*
 * SPDX-FileCopyrightText: 2026 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Model-based conformance test for libevpl's core SDK.
 *
 * The RPC2 conformance tests replay a table of independent cases.  This one
 * replays PROGRAMS: quint/core.qnt models the core API as a state machine,
 * and each generated program is a sequence of SDK calls against a freshly
 * created evpl.  This file is the interpreter.
 *
 * The oracle is not a return value -- an asynchronous API has none to check
 * against.  It is the event log.  Each program op registers, arms or retires
 * something; each OpQuiesce runs the loop to an absolute deadline and then
 * holds the callbacks that arrived against the obligations the model says
 * were owed, in three directions:
 *
 *   - every obligation is discharged (a missing callback is a caller waiting
 *     forever, which in production is a hang and not a crash);
 *   - no callback arrives that nothing expected (this is what makes "the
 *     removed timer stopped firing" and "the one-shot did not refire"
 *     observable at all -- they are absences);
 *   - callbacks that the model orders arrive in that order.
 *
 * A quiesce therefore always runs its whole window and never returns early on
 * satisfaction: an early exit would observe no absence, and the second and
 * third checks above would be worthless.
 *
 * The transport half runs over EVPL_STREAM_INPROC.  In-process is what makes
 * a whole connection lifecycle reachable from one thread and one evpl: both
 * ends are in this process, so the model can state what BOTH of them are
 * owed, and there is no port to collide on, no namespace to need and nothing
 * for a crash to leave behind.  Everything here is transport-agnostic above
 * the protocol id, so widening it to the socket transports is a matter of
 * parameterizing that id rather than of rewriting the harness.
 *
 * The model encodes the SPECIFICATION that include/evpl states, so a mismatch
 * is a candidate bug in libevpl rather than a broken test.  Reviewed,
 * consciously deferred divergences go in known_divergences[] with a note;
 * anything else fails.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "core/test_log.h"
#include "evpl/evpl.h"
#include "tests/test_common.h"

#include "core_cases.h"

/*
 * The delay classes, in microseconds.  These MUST match core.qnt's delayMs():
 * the model computes which quiesce window each deadline falls in, so a driver
 * that armed a different delay would be checking a different program from the
 * one that was generated.
 */
#define DELAY_FAST_US    1000
#define DELAY_SLOW_US    50000

/*
 * The clock is advanced a millisecond at a time rather than in one jump per
 * window.  Jumping would collapse every deadline in the window onto a single
 * instant: two timers due 40ms apart would come due together and their order
 * would stop meaning anything, and a periodic timer would fire once for the
 * window instead of throughout it.
 */
#define TICK_NS          1000000ull

/*
 * How many consecutive passes of the loop must produce nothing before it is
 * considered settled.
 *
 * With the clock frozen, the only thing left that can make progress is I/O
 * and the deferrals it schedules, so this is bounded and small -- the peer's
 * queue is filled synchronously by the send and the wakeup is already
 * readable by the next pass.  It is generous because the cost of being
 * generous is a few more non-blocking passes, and the cost of being mean is a
 * missed callback reported as a conformance failure.
 */
#define SETTLE_PASSES    8

/*
 * A backstop on settling.  With the clock frozen the loop has a bounded
 * amount of work to do, so needing more passes than this means something is
 * producing events without end -- and a loop that never settles is a hang,
 * which is the least debuggable way for a test to fail.
 */
#define SETTLE_LIMIT     200000

/*
 * How long to keep driving the loop at the end of a window for obligations
 * that have not arrived yet.
 *
 * evpl_listener_create() runs the accept path on a thread of its own, so a
 * connection's arrival is handed across threads and how many passes of THIS
 * loop it takes is a property of the scheduler, not of libevpl.  Waiting for
 * it costs nothing when it is prompt and does not weaken anything: a callback
 * that must arrive is waited for, while a callback that must NOT arrive is
 * still decided by the clock, which does not move here.
 *
 * The bound is a backstop against a genuine hang.  Each pass is a
 * non-blocking poll, so exhausting it takes well under a second, and what
 * follows is the ordinary "obligation not discharged" failure -- which is
 * exactly what a callback that never comes is.
 */
#define AWAIT_PASSES     200000

/* Object slots the model may name.  It declares two of each; the driver
 * carries a little slack so that widening the model is a one-line change
 * there.  Connection ends share the slot space with the rest, two per
 * connection -- see END_SLOT. */
#define MAX_SLOT         4
#define MAX_CONN         2

#define SIDE_CLIENT      0
#define SIDE_SERVER      1
#define NUM_SIDE         2

#define END_SLOT(conn, side) ((conn) * NUM_SIDE + (side))
#define PEER(side)           (1 - (side))

/* Comes from the generated header; see CORE_NUM_EVENT_KIND. */
#define NUM_EVENT_KIND   CORE_NUM_EVENT_KIND

/*
 * Poll mode, as the driver configures it.
 *
 * poll_iterations is deliberately 1 rather than the default 1000.  The loop
 * runs that many pure-polling passes between each full pass, and only a full
 * pass can observe activity or let the spin window expire -- so with the
 * default, settle() would give up long before the loop ever looked at whether
 * it should still be spinning, and no mode transition would ever be seen.
 * One keeps the poll callback firing regularly while leaving a full pass
 * between each, which is the same state machine at a legible cadence.
 */
#define POLL_ITERATIONS  1

/* The largest number of iovecs a payload is allowed to arrive in or be sent
 * as; ample for the largest size class at any sane buffer size. */
#define MAX_SEND_IOV     64

/*
 * Buffer size for the run, well below the largest payload class on purpose.
 *
 * The default is 2 MiB, which puts every payload this model sends into a
 * single iovec and leaves the gather and scatter paths -- the ones that walk
 * a chain -- almost entirely unexercised.  At 32 KiB the largest class spans
 * four.
 *
 * Not smaller, because evpl_send bounces through evpl_iovec_alloc with room
 * for four iovecs and aborts if the payload needs more -- so a buffer under a
 * quarter of the largest class turns evpl_send into an abort rather than a
 * test.
 */
#define CONF_BUFFER_SIZE (32 * 1024)

/* Must match core.qnt's SPIN_MS.  Set rather than assumed: the model's poll
 * transitions are computed against it. */
#define CONF_SPIN_NS     1000000UL

/*
 * Where AF_UNIX socket files go.
 *
 * ctest points EVPL_TEST_SOCKET_DIR at the build tree so a run leaves nothing
 * behind in /tmp; the fallbacks are for running the binary by hand.  sun_path
 * is only 108 bytes, so a deep build tree can push a generated name past it --
 * hence the length check and the fallback to /tmp rather than a truncated
 * path, which would be a different socket.
 *
 * libevpl owns the file from bind onwards: it removes it at teardown and steps
 * over a stale predecessor, so nothing here has to clean up after itself.
 */
static const char *
socket_dir(void)
{
    const char *dir = getenv("EVPL_TEST_SOCKET_DIR");

    if (!dir || dir[0] != '/') {
        dir = getenv("TMPDIR");
    }

    if (!dir || dir[0] != '/') {
        dir = "/tmp";
    }

    return dir;
} /* socket_dir */

/*
 * Base port for the socket transports.  Each listen takes the next one, and
 * a program never reuses one, so nothing here contends with itself; what it
 * does contend with is the rest of the suite, which is why the test is
 * registered under the same network serialization as the other socket tests.
 */
#define CONF_BASE_PORT 9300

/* Global iovecs are one whole buffer each and are released at teardown, so a
 * program can hold at most this many at once. */
#define MAX_GLOBAL_IOV 16

/* Sized from the model's largest payload class; see size_bytes(). */
#define MAX_SEND_BYTES 131072
#define RECV_SCRATCH   65536
#define MAX_RECVV_IOV  64

/* A program is a dozen ops and its quiesces are bounded, so the log cannot
 * grow without bound -- except through a periodic timer, which fires as often
 * as the loop spins.  The cap is a backstop against a runaway rather than an
 * expected limit, and overflowing it fails the run rather than truncating
 * silently, which would turn a storm of spurious callbacks into a pass. */
#define MAX_LOG        65536

struct log_entry {
    uint8_t  kind;
    uint8_t  slot;
    /* One for a callback; a byte count for CEV_EVRECV, because what a stream
     * owes is bytes and not notifications. */
    uint32_t count;
};

struct prog_state;

struct timer_slot {
    struct evpl_timer  timer;     /* first member: the callback casts back */
    struct prog_state *ps;
    int                slot;
    int                rearm_left;
    uint64_t           delay_us;
    int                armed;
};

struct deferral_slot {
    struct evpl_deferral deferral;
    struct prog_state   *ps;
    int                  slot;
    int                  redefer_left;
};

struct doorbell_slot {
    struct evpl_doorbell doorbell;  /* first member: same trick */
    struct prog_state   *ps;
    int                  slot;
    int                  present;
    int                  remove_in_cb;
};

/* What a notify callback needs to know about the end it was registered for.
 * A bind carries no slot of its own, so this is how a callback finds its way
 * back into the model's object space. */
struct end_ctx {
    struct prog_state *ps;
    int                conn;
    int                side;
};

struct conn_slot {
    struct evpl_bind     *bind[NUM_SIDE];
    /* Where each end of an unconnected pair lives.  A connected transport
     * has one endpoint for the pair, held on the program; an unconnected one
     * has an address per end, because that is what its peer has to name. */
    struct evpl_endpoint *ep[NUM_SIDE];
    struct end_ctx        ctx[NUM_SIDE];
    uint8_t               drain;
    /* Byte-stream offsets, indexed by the end that RECEIVES.  The sender
     * writes a position-keyed pattern from tx_off and the receiver checks it
     * against rx_off, so a payload delivered short, twice, out of order or at
     * the wrong offset fails on content rather than only on length. */
    uint64_t              tx_off[NUM_SIDE];
    uint64_t              rx_off[NUM_SIDE];
};

struct prog_state {
    struct evpl                  *evpl;
    struct timer_slot             timers[MAX_SLOT];
    struct deferral_slot          deferrals[MAX_SLOT];
    struct doorbell_slot          doorbells[MAX_SLOT];

    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    struct evpl_endpoint         *endpoint;
    int                           listen_seq;
    struct conn_slot              conns[MAX_CONN];
    /* The connection awaiting its accept, or -1.  The model generates at most
     * one connect in flight precisely so that this is unambiguous: an accept
     * callback is handed a bind with nothing on it that says which connect it
     * answers. */
    int                           pending_connect;

    struct log_entry              log[MAX_LOG];
    int                           nlog;
    int                           window;   /* first log index of this window */
    struct evpl_poll             *poll;
    /* Global iovecs are owned outright by whoever allocated them: the library
     * never frees one, and a borrow taken by the send path does not keep it
     * alive.  So they are held here for the life of the program and released
     * exactly once at teardown, which is both the documented contract and the
     * only way the payload is guaranteed to still be there when the transport
     * gets to it. */
    struct evpl_iovec             globals[MAX_GLOBAL_IOV];
    int                           nglobals;
    struct evpl_loop_hooks        hooks;
    /* The protocol this program runs over, taken from its steps.  Fixed for
     * the program: listen and connect must agree, and both ends of a
     * connection are the same transport by construction. */
    enum evpl_protocol_id         proto;
    /* A poll callback fires on every pass of the loop while the thread is
     * spinning.  Logging each one would mean the loop never looked settled,
     * so the driver records only the first in a window -- which is what the
     * model claims: that the poll ran, not how often. */
    int                           poll_logged;
    /* As poll_logged: the hooks run on every pass, so only the first of each
     * in a window is recorded. */
    int                           hook_logged[3];
    /* The virtual clock reading this program calls zero.  The clock is
     * process-wide and never rewinds, so each program takes its own base
     * rather than resetting it. */
    uint64_t                      base_ns;

    uint8_t                       sendbuf[MAX_SEND_BYTES];
    uint8_t                       recvbuf[RECV_SCRATCH];
};

/*
 * Failure kinds.  These are the three directions the check runs in, plus the
 * ordering claim; they are what a known divergence is keyed on.
 */
enum core_failure {
    CFAIL_MISSING = 0,      /* fewer callbacks than the obligation requires */
    CFAIL_EXTRA,            /* more than an exact obligation allows         */
    CFAIL_UNEXPECTED,       /* a callback no obligation covers              */
    CFAIL_ORDER,            /* a required ordering was violated             */
};

/*
 * Known divergences from the specification.
 *
 * Keyed on the shape of the obligation rather than on the program that
 * happened to hit it, because the programs are regenerated and a program
 * index is not stable across a seed or quint bump.  The shape is
 * discriminating even so: (EvTimer, exactly 1) is a one-shot, (EvTimer,
 * exactly 2) a re-armer, (EvTimer, at least 1) a periodic, (EvDeferral,
 * exactly 1) a coalesced arming, (EvDeferral, exactly 2) a re-armed one,
 * (EvDoorbell, at least 1) a ring, (EvDoorbell, exactly 1) a doorbell that
 * retires itself from its own callback.
 *
 * Removing an entry turns its divergence back into a hard failure, which is
 * what should happen once the underlying issue is fixed.
 */
struct known_divergence {
    uint8_t     kind;
    uint8_t     mult;
    uint32_t    count;
    uint8_t     failure;
    const char *note;
};

static const struct known_divergence known_divergences[] = {
    /* Empty: every obligation the model states is currently met. */
    { 0, 0, 0, 0, NULL }
};

static int
is_known_divergence(
    uint8_t  kind,
    uint8_t  mult,
    uint32_t count,
    uint8_t  failure)
{
    unsigned int i;

    for (i = 0; i < sizeof(known_divergences) / sizeof(known_divergences[0]);
         i++) {
        if (known_divergences[i].note &&
            known_divergences[i].kind == kind &&
            known_divergences[i].mult == mult &&
            known_divergences[i].count == count &&
            known_divergences[i].failure == failure) {
            return 1;
        }
    }

    return 0;
} /* is_known_divergence */

/* Set from CORE_TRACE; prints each op as it runs, for when a program does
 * something the failure message alone does not explain. */
static int g_trace;

/* Next socket port to hand out; see CONF_BASE_PORT. */
static int g_port_seq;

static struct {
    int      programs;
    int      steps;
    int      obligations;
    int      quiesces;
    int      known;
    int      failed;
    uint64_t bytes;
} g_results;

/* ------------------------------------------------------------------ */

static const char *
op_name(uint8_t op)
{
    switch (op) {
        case COP_OPRESET: return "Reset";
        case COP_OPADDTIMER: return "AddTimer";
        case COP_OPREMOVETIMER: return "RemoveTimer";
        case COP_OPDEFER: return "Defer";
        case COP_OPDEFERTWICE: return "DeferTwice";
        case COP_OPDEFERREENTRANT: return "DeferReentrant";
        case COP_OPADDDOORBELL: return "AddDoorbell";
        case COP_OPRINGDOORBELL: return "RingDoorbell";
        case COP_OPRINGDOORBELLTWICE: return "RingDoorbellTwice";
        case COP_OPREMOVEDOORBELL: return "RemoveDoorbell";
        case COP_OPREMOVEDOORBELLINCALLBACK: return "RemoveDoorbellInCallback";
        case COP_OPREMOVEDEFERRAL: return "RemoveDeferral";
        case COP_OPREMOVEDEFERRALIDLE: return "RemoveDeferralIdle";
        case COP_OPADDPOLL: return "AddPoll";
        case COP_OPREMOVEPOLL: return "RemovePoll";
        case COP_OPACTIVITY: return "Activity";
        case COP_OPPOLLPIN: return "PollPin";
        case COP_OPPOLLUNPIN: return "PollUnpin";
        case COP_OPREQUESTSENDNOTIFY: return "RequestSendNotify";
        case COP_OPSETLOOPHOOKS: return "SetLoopHooks";
        case COP_OPCLEARLOOPHOOKS: return "ClearLoopHooks";
        case COP_OPLISTEN: return "Listen";
        case COP_OPSTOPLISTEN: return "StopListen";
        case COP_OPBINDPAIR: return "BindPair";
        case COP_OPCONNECT: return "Connect";
        case COP_OPSEND: return "Send";
        case COP_OPCLOSE: return "Close";
        case COP_OPFINISH: return "Finish";
        case COP_OPQUIESCE: return "Quiesce";
        default: return "?";
    } /* switch */
} /* op_name */

static const char *
event_name(uint8_t kind)
{
    switch (kind) {
        case CEV_EVTIMER: return "timer";
        case CEV_EVDEFERRAL: return "deferral";
        case CEV_EVDOORBELL: return "doorbell";
        case CEV_EVCONNECTED: return "connected";
        case CEV_EVDISCONNECTED: return "disconnected";
        case CEV_EVRECV: return "recv-bytes";
        case CEV_EVPOLLENTER: return "poll-enter";
        case CEV_EVPOLLEXIT: return "poll-exit";
        case CEV_EVPOLL: return "poll";
        case CEV_EVRECVMSG: return "recv-messages";
        case CEV_EVSENT: return "sent-bytes";
        case CEV_EVHOOK: return "loop-hook";
        default: return "?";
    } /* switch */
} /* event_name */

static const char *
failure_name(uint8_t failure)
{
    switch (failure) {
        case CFAIL_MISSING: return "missing";
        case CFAIL_EXTRA: return "extra";
        case CFAIL_UNEXPECTED: return "unexpected";
        case CFAIL_ORDER: return "out-of-order";
        default: return "?";
    } /* switch */
} /* failure_name */

/* Must match core.qnt's sizeBytes(). */
static int
size_bytes(uint8_t size)
{
    switch (size) {
        case CSZ_SZTINY: return 1;
        case CSZ_SZSMALL: return 100;
        case CSZ_SZMEDIUM: return 8192;
        case CSZ_SZLARGE: return 131072;
        default: return 0;
    } /* switch */
} /* size_bytes */

/*
 * Drive the loop until it settles.
 *
 * The clock is frozen while this runs, so nothing can become due inside it;
 * what it waits for is the genuinely asynchronous part -- a payload becoming
 * visible to its peer, a close being dispatched off its deferral -- which
 * depends on passes of the loop and not on time.  That is what keeps the
 * suite's verdicts independent of how loaded the machine is.
 */
static void
settle(struct prog_state *ps)
{
    int quiet = 0, passes = 0;

    while (quiet < SETTLE_PASSES) {
        int before = ps->nlog;

        evpl_continue(ps->evpl);

        quiet = (ps->nlog == before) ? quiet + 1 : 0;

        evpl_test_abort_if(++passes > SETTLE_LIMIT,
                           "the loop has not settled in %d passes with the "
                           "clock stopped; something is producing events "
                           "without end (last was %s slot %d)",
                           SETTLE_LIMIT,
                           ps->nlog ? event_name(ps->log[ps->nlog - 1].kind) : "nothing",
                           ps->nlog ? ps->log[ps->nlog - 1].slot : -1);
    }
} /* settle */

static void
log_event(
    struct prog_state *ps,
    uint8_t            kind,
    int                slot,
    uint32_t           count)
{
    evpl_test_abort_if(ps->nlog >= MAX_LOG,
                       "event log overflow at %s slot %d: more than %d "
                       "callbacks in one program, which is a callback storm "
                       "rather than a capacity problem",
                       event_name(kind), slot, MAX_LOG);

    ps->log[ps->nlog].kind  = kind;
    ps->log[ps->nlog].slot  = (uint8_t) slot;
    ps->log[ps->nlog].count = count;
    ps->nlog++;
} /* log_event */

/* ------------------------------------------------------------------ */

static void
timer_cb(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    struct timer_slot *ts = (struct timer_slot *) timer;

    log_event(ts->ps, CEV_EVTIMER, ts->slot, 1);

    /*
     * A re-arming one-shot arms itself again from inside its own callback,
     * which is only legal because the loop pops a one-shot BEFORE calling it.
     * Doing it here rather than from the op is the whole point: arming it
     * from the outside would test nothing about that ordering.
     */
    if (ts->rearm_left > 0) {
        ts->rearm_left--;
        evpl_add_oneshot_timer(evpl, timer, timer_cb, ts->delay_us);
    } else if (ts->armed == 1) {
        /* A plain one-shot is gone once it has fired; remember that so the
         * teardown below does not try to remove it again... which is itself a
         * documented no-op, but the model already covers that explicitly. */
        ts->armed = 0;
    }
} /* timer_cb */

static void
deferral_cb(
    struct evpl *evpl,
    void        *private_data)
{
    struct deferral_slot *ds = private_data;

    log_event(ds->ps, CEV_EVDEFERRAL, ds->slot, 1);

    /* Re-arm from inside the callback.  Distinct from arming twice before the
     * loop runs, which coalesces: this one must produce a second callback. */
    if (ds->redefer_left > 0) {
        ds->redefer_left--;
        evpl_defer(evpl, &ds->deferral);
    }
} /* deferral_cb */

static void
doorbell_cb(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    struct doorbell_slot *bs = (struct doorbell_slot *) doorbell;

    log_event(bs->ps, CEV_EVDOORBELL, bs->slot, 1);

    /*
     * evpl_doorbell.h permits retiring a doorbell from inside its own
     * callback and promises the library holds no reference afterwards, so the
     * storage may be freed immediately.  Doing it here is what puts that
     * promise under test -- a dispatch loop that keeps walking the array it
     * just mutated fails here and nowhere else.
     */
    if (bs->remove_in_cb) {
        bs->remove_in_cb = 0;
        bs->present      = 0;
        evpl_remove_doorbell(evpl, doorbell);
    }
} /* doorbell_cb */

/* ------------------------------------------------------------------ */

static void
poll_enter_cb(
    struct evpl *evpl,
    void        *private_data)
{
    log_event(private_data, CEV_EVPOLLENTER, 0, 1);
} /* poll_enter_cb */

static void
poll_exit_cb(
    struct evpl *evpl,
    void        *private_data)
{
    log_event(private_data, CEV_EVPOLLEXIT, 0, 1);
} /* poll_exit_cb */

static void
poll_cb(
    struct evpl *evpl,
    void        *private_data)
{
    struct prog_state *ps = private_data;

    /* Once per window; see poll_logged. */
    if (!ps->poll_logged) {
        ps->poll_logged = 1;
        log_event(ps, CEV_EVPOLL, 0, 1);
    }
} /* poll_cb */

/*
 * The three loop hooks.  Each fires on every pass of the loop, so like the
 * poll callback only the first of each in a window is recorded; what the
 * model claims is that each ran, not how often.
 */
static void
hook_log(
    struct prog_state *ps,
    int                which)
{
    if (!ps->hook_logged[which]) {
        ps->hook_logged[which] = 1;
        log_event(ps, CEV_EVHOOK, which, 1);
    }
} /* hook_log */

static void
hook_iteration_end_cb(
    struct evpl *evpl,
    void        *private_data)
{
    hook_log(private_data, 0);
} /* hook_iteration_end_cb */

static void
hook_pre_wait_cb(
    struct evpl *evpl,
    void        *private_data)
{
    hook_log(private_data, 1);
} /* hook_pre_wait_cb */

static void
hook_post_wait_cb(
    struct evpl *evpl,
    void        *private_data)
{
    hook_log(private_data, 2);
} /* hook_post_wait_cb */

/* Position-keyed, so the check is on WHICH bytes arrived and not merely how
 * many.  A payload delivered at the wrong offset, duplicated, or reordered
 * has the right length and the wrong content. */
static inline uint8_t
pattern_byte(uint64_t off)
{
    return (uint8_t) (off * 31u + 17u);
} /* pattern_byte */

static void
verify_bytes(
    struct prog_state *ps,
    int                conn,
    int                side,
    const uint8_t     *data,
    int                len)
{
    struct conn_slot *cs = &ps->conns[conn];
    int               i;

    for (i = 0; i < len; i++) {
        uint8_t want = pattern_byte(cs->rx_off[side] + i);

        evpl_test_abort_if(data[i] != want,
                           "conn %d side %d: byte at stream offset %llu is "
                           "0x%02x, expected 0x%02x -- the payload arrived "
                           "corrupt, short, duplicated or out of order",
                           conn, side,
                           (unsigned long long) (cs->rx_off[side] + i),
                           data[i], want);
    }

    cs->rx_off[side] += len;
    g_results.bytes  += len;
} /* verify_bytes */

/*
 * Take everything buffered on this end, whichever way the program asked for.
 * The three modes must be interchangeable -- the byte stream is the same
 * however it is drained -- so the model states one obligation and this is
 * where the variation lives.
 */
static void
drain_end(
    struct prog_state *ps,
    struct end_ctx    *ec)
{
    struct conn_slot *cs   = &ps->conns[ec->conn];
    struct evpl_bind *bind = cs->bind[ec->side];
    struct evpl_iovec iov[MAX_RECVV_IOV];
    int               n, niov, length, i;

    if (!bind) {
        return;
    }

    switch (cs->drain) {
        case CDRN_DRAINRECV:
            while ((n = evpl_recv(ps->evpl, bind, ps->recvbuf, RECV_SCRATCH,
                                  0)) > 0) {
                verify_bytes(ps, ec->conn, ec->side, ps->recvbuf, n);
                log_event(ps, CEV_EVRECV, END_SLOT(ec->conn, ec->side),
                          (uint32_t) n);
            }
            break;

        case CDRN_DRAINRECVV:
            /* evpl_recvv CLONES: the iovecs it hands back carry references
             * this end now owns, so failing to release them leaks a buffer
             * per call and evpl_allocator_destroy aborts at teardown. */
            while ((niov = evpl_recvv(ps->evpl, bind, iov, MAX_RECVV_IOV,
                                      RECV_SCRATCH, &length)) > 0) {
                for (i = 0; i < niov; i++) {
                    verify_bytes(ps, ec->conn, ec->side, iov[i].data,
                                 iov[i].length);
                }

                log_event(ps, CEV_EVRECV, END_SLOT(ec->conn, ec->side),
                          (uint32_t) length);

                evpl_iovecs_release(ps->evpl, iov, niov);
            }
            break;

        case CDRN_DRAINPEEK:
            /* evpl_peek copies without consuming, so the bytes are still
             * there afterwards; consuming exactly what was peeked is the
             * contract between the two, and consuming more than is buffered
             * is required to fail. */
            while ((n = evpl_peek(ps->evpl, bind, ps->recvbuf,
                                  RECV_SCRATCH)) > 0) {
                verify_bytes(ps, ec->conn, ec->side, ps->recvbuf, n);

                evpl_test_abort_if(evpl_consume(ps->evpl, bind, n),
                                   "conn %d side %d: consume of %d peeked "
                                   "bytes failed, so peek reported bytes the "
                                   "bind does not hold",
                                   ec->conn, ec->side, n);

                log_event(ps, CEV_EVRECV, END_SLOT(ec->conn, ec->side),
                          (uint32_t) n);
            }
            break;

        case CDRN_DRAINPEEKV:
            /* evpl_peekv does NOT clone, unlike evpl_recvv: the iovecs it
             * hands back are borrowed views of the receive ring, so they must
             * not be released -- doing so would drop a reference this end
             * never took.  Nor does it consume, which is why the length has
             * to be summed back out of the iovecs and handed to
             * evpl_consume. */
            while ((niov = evpl_peekv(ps->evpl, bind, iov, MAX_RECVV_IOV,
                                      RECV_SCRATCH)) > 0) {
                length = 0;

                for (i = 0; i < niov; i++) {
                    verify_bytes(ps, ec->conn, ec->side, iov[i].data,
                                 iov[i].length);
                    length += iov[i].length;
                }

                evpl_test_abort_if(evpl_consume(ps->evpl, bind, length),
                                   "conn %d side %d: consume of %d peeked "
                                   "bytes failed, so peekv reported bytes the "
                                   "bind does not hold",
                                   ec->conn, ec->side, length);

                log_event(ps, CEV_EVRECV, END_SLOT(ec->conn, ec->side),
                          (uint32_t) length);
            }
            break;

        default:
            evpl_test_abort("unknown drain mode %d", cs->drain);
    } /* switch */
} /* drain_end */

static void
conn_notify_cb(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct end_ctx   *ec = private_data;
    struct conn_slot *cs = &ec->ps->conns[ec->conn];

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            cs->bind[ec->side] = bind;

            /* Accessors on a bind that is definitely up.  Sequence-free, so
             * they live here rather than in the model; the point of checking
             * them on a live connection is that there is no other state in
             * which their answers mean anything. */
            {
                char addr[EVPL_ADDRESS_STRLEN];

                evpl_test_abort_if(evpl_bind_get_protocol(bind) !=
                                   ec->ps->proto,
                                   "a bind reports a protocol it was not "
                                   "created with");
                /* The in-process DATAGRAM transport advertises RDMA on
                 * purpose -- it is what lets rpc2 exercise its chunk and
                 * rdma_msg paths with no hardware -- so only the stream one
                 * is required to say no. */
                evpl_test_abort_if(ec->ps->proto == EVPL_STREAM_INPROC &&
                                   evpl_bind_is_rdma(bind),
                                   "an in-process stream bind claims to be RDMA");
                evpl_test_abort_if(evpl_bind_is_closing(bind),
                                   "a bind is closing before it has been used");

                evpl_bind_get_local_address(bind, addr, sizeof(addr));
                evpl_test_abort_if(addr[0] == '\0',
                                   "a connected bind has no local address");

                evpl_bind_get_remote_address(bind, addr, sizeof(addr));
                evpl_test_abort_if(addr[0] == '\0',
                                   "a connected bind has no remote address");
            }
            log_event(ec->ps, CEV_EVCONNECTED, END_SLOT(ec->conn, ec->side), 1);
            break;

        case EVPL_NOTIFY_DISCONNECTED:
            /* The bind is freed once this returns, so drop it here: anything
             * that reached for it afterwards would be a use after free, and
             * the model's own state says this end is gone. */
            cs->bind[ec->side] = NULL;
            log_event(ec->ps, CEV_EVDISCONNECTED, END_SLOT(ec->conn, ec->side),
                      1);
            break;

        case EVPL_NOTIFY_RECV_DATA:
            drain_end(ec->ps, ec);
            break;

        case EVPL_NOTIFY_RECV_MSG:
            /*
             * A datagram arrives whole, in the notification, rather than being
             * drained off the bind -- evpl_recv and friends are stream-only
             * and refuse a datagram bind outright.  The iovecs are the
             * receiver's to release, the same rule as evpl_recvv.
             */
        {
            struct conn_slot *dcs = &ec->ps->conns[ec->conn];
            unsigned int      i;

            for (i = 0; i < notify->recv_msg.niov; i++) {
                verify_bytes(ec->ps, ec->conn, ec->side,
                             notify->recv_msg.iovec[i].data,
                             notify->recv_msg.iovec[i].length);
            }

            (void) dcs;

            log_event(ec->ps, CEV_EVRECV, END_SLOT(ec->conn, ec->side),
                      notify->recv_msg.length);

            /* One delivery.  Counting these separately from the bytes is
             * the only way a coalesced or split datagram is visible. */
            log_event(ec->ps, CEV_EVRECVMSG, END_SLOT(ec->conn, ec->side), 1);

            evpl_iovecs_release(ec->ps->evpl, notify->recv_msg.iovec,
                                notify->recv_msg.niov);
        }
        break;

        case EVPL_NOTIFY_SENT:
            /* Counted in bytes, not notifications: how many the transport
             * batches the sends into is its business. */
            log_event(ec->ps, CEV_EVSENT, END_SLOT(ec->conn, ec->side),
                      (uint32_t) notify->sent.bytes);
            break;

        default:
            break;
    } /* switch */
} /* conn_notify_cb */

static void
accept_cb(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    struct prog_state *ps = private_data;
    int                c  = ps->pending_connect;

    evpl_test_abort_if(c < 0,
                       "a connection was accepted with no connect "
                       "outstanding, so the accepted end cannot be attributed "
                       "to one of the model's connections");

    ps->conns[c].bind[SIDE_SERVER] = bind;

    *notify_callback   = conn_notify_cb;
    *conn_private_data = &ps->conns[c].ctx[SIDE_SERVER];

    ps->pending_connect = -1;
} /* accept_cb */

/* ------------------------------------------------------------------ */

/* Total occurrences of (kind, slot) logged in the current window. */
static uint64_t
window_count(
    struct prog_state *ps,
    uint8_t            kind,
    uint8_t            slot)
{
    uint64_t total = 0;
    int      i;

    for (i = ps->window; i < ps->nlog; i++) {
        if (ps->log[i].kind == kind && ps->log[i].slot == slot) {
            total += ps->log[i].count;
        }
    }

    return total;
} /* window_count */

/* Whether everything this window is owed has arrived.  Says nothing about
 * what should NOT have arrived; that is check_window's business, and the
 * clock's. */
static int
expectations_met(
    struct prog_state      *ps,
    const struct core_step *step)
{
    int i;

    for (i = 0; i < step->expect_count; i++) {
        const struct core_expect *e = &core_expects[step->expect_first + i];

        if (window_count(ps, e->kind, e->slot) < e->count) {
            return 0;
        }
    }

    return 1;
} /* expectations_met */

/*
 * Hold one quiesce window against what the model says was owed.
 *
 * Returns the number of unsuppressed failures.
 */
static int
check_window(
    struct prog_state      *ps,
    const struct core_step *step,
    int                     prog,
    int                     stepno)
{
    uint64_t seen[NUM_EVENT_KIND][MAX_SLOT];
    int      first[NUM_EVENT_KIND][MAX_SLOT];
    int      covered[NUM_EVENT_KIND][MAX_SLOT];
    int      i, k, s, failures = 0;

    memset(seen, 0, sizeof(seen));
    memset(covered, 0, sizeof(covered));

    for (k = 0; k < NUM_EVENT_KIND; k++) {
        for (s = 0; s < MAX_SLOT; s++) {
            first[k][s] = -1;
        }
    }

    for (i = ps->window; i < ps->nlog; i++) {
        k = ps->log[i].kind;
        s = ps->log[i].slot;

        evpl_test_abort_if(k >= NUM_EVENT_KIND || s >= MAX_SLOT,
                           "logged an event outside the model's object space");

        seen[k][s] += ps->log[i].count;

        if (first[k][s] < 0) {
            first[k][s] = i;
        }
    }

    /* Direction one: every obligation discharged. */
    for (i = 0; i < step->expect_count; i++) {
        const struct core_expect *e    = &core_expects[step->expect_first + i];
        uint64_t                  got  = seen[e->kind][e->slot];
        int                       fail = -1;

        g_results.obligations++;
        covered[e->kind][e->slot] = 1;

        if (got < e->count) {
            fail = CFAIL_MISSING;
        } else if (e->mult == CMUL_MEXACTLY && got > e->count) {
            fail = CFAIL_EXTRA;
        }

        if (fail < 0) {
            continue;
        }

        if (is_known_divergence(e->kind, e->mult, e->count, (uint8_t) fail)) {
            g_results.known++;
            continue;
        }

        evpl_test_error(
            "program %d step %d: %s %s for slot %d: required %s %u, got %llu",
            prog, stepno, failure_name((uint8_t) fail), event_name(e->kind),
            e->slot, e->mult == CMUL_MEXACTLY ? "exactly" : "at least",
            e->count, (unsigned long long) got);
        failures++;
    }

    /*
     * Direction two: nothing arrived that was not owed.  This is the check
     * that makes an absence observable, and the reason a quiesce runs its
     * whole window instead of stopping once the obligations above are met.
     */
    for (k = 0; k < NUM_EVENT_KIND; k++) {
        for (s = 0; s < MAX_SLOT; s++) {
            if (!seen[k][s] || covered[k][s]) {
                continue;
            }

            if (is_known_divergence((uint8_t) k, CMUL_MEXACTLY, 0,
                                    CFAIL_UNEXPECTED)) {
                g_results.known++;
                continue;
            }

            evpl_test_error(
                "program %d step %d: unexpected %s for slot %d (%llu) -- "
                "nothing armed it, or something that was retired delivered "
                "anyway",
                prog, stepno, event_name((uint8_t) k), s,
                (unsigned long long) seen[k][s]);
            failures++;
        }
    }

    /* Direction three: the orderings the model claims. */
    for (i = 0; i < step->order_count; i++) {
        const struct core_order *o = &core_orders[step->order_first + i];
        int                      a = first[o->first_kind][o->first_slot];
        int                      b = first[o->then_kind][o->then_slot];

        if (a >= 0 && b >= 0 && a < b) {
            continue;
        }

        if (is_known_divergence(o->first_kind, CMUL_MEXACTLY, 0, CFAIL_ORDER)) {
            g_results.known++;
            continue;
        }

        evpl_test_error(
            "program %d step %d: %s slot %d must be delivered before %s slot "
            "%d (first seen at %d and %d)",
            prog, stepno, event_name(o->first_kind), o->first_slot,
            event_name(o->then_kind), o->then_slot, a, b);
        failures++;
    }

    return failures;
} /* check_window */

static int
do_quiesce(
    struct prog_state      *ps,
    const struct core_step *step,
    int                     prog,
    int                     stepno)
{
    uint64_t target = ps->base_ns + (uint64_t) step->at_ms * TICK_NS;
    int      i;

    ps->window      = ps->nlog;
    ps->poll_logged = 0;

    memset(ps->hook_logged, 0, sizeof(ps->hook_logged));

    /*
     * The whole window, a tick at a time, unconditionally.  Stopping as soon
     * as the obligations were met would make every "must not fire" claim
     * vacuous, and those are half of what this model states -- an absence is
     * only observed by getting to the end of the window without it.
     *
     * Which is cheap here in a way it is not on a real clock: the window
     * costs a few hundred non-blocking passes of the loop rather than its
     * length in milliseconds of sleep.
     */
    while (evpl_virtual_clock_now() < target) {
        evpl_virtual_clock_advance(TICK_NS);
        settle(ps);
    }

    /* Anything still outstanding is waiting on another thread rather than on
     * the clock; see AWAIT_PASSES. */
    for (i = 0; i < AWAIT_PASSES && !expectations_met(ps, step); i++) {
        evpl_continue(ps->evpl);
    }

    g_results.quiesces++;

    return check_window(ps, step, prog, stepno);
} /* do_quiesce */

/* ------------------------------------------------------------------ */

static void
do_listen(
    struct prog_state *ps,
    int                prog)
{
    /* Long enough for a socket path; sun_path is 108. */
    char name[108];

    if (evpl_protocol_is_local(ps->proto)) {
        int len = snprintf(name, sizeof(name), "%s/cc-%d-%d-%d.sock",
                           socket_dir(), (int) getpid(), prog,
                           ps->listen_seq++);

        if (len < 0 || (size_t) len >= sizeof(name)) {
            snprintf(name, sizeof(name), "/tmp/cc-%d-%d-%d.sock",
                     (int) getpid(), prog, ps->listen_seq++);
        }

        ps->endpoint = evpl_endpoint_create_local(name);
    } else if (evpl_protocol_is_inproc(ps->proto)) {
        /* The registry behind an in-process name is private to this process,
         * so the pid is not needed for isolation from other test binaries --
         * but the program and sequence numbers are, because a name is only
         * released when its listener is destroyed and a program may listen
         * more than once. */
        snprintf(name, sizeof(name), "core-conf-%d-%d-%d", (int) getpid(),
                 prog, ps->listen_seq++);

        ps->endpoint = evpl_endpoint_create_inproc(name);
    } else {
        /* A port of its own per listen; see CONF_BASE_PORT. */
        snprintf(name, sizeof(name), "127.0.0.1:%d",
                 CONF_BASE_PORT + g_port_seq);

        ps->endpoint = evpl_endpoint_create("127.0.0.1",
                                            CONF_BASE_PORT + g_port_seq++);
    }

    evpl_test_abort_if(!ps->endpoint, "failed to create endpoint '%s'", name);

    ps->listener = evpl_listener_create();
    ps->binding  = evpl_listener_attach(ps->evpl, ps->listener, accept_cb, ps);

    evpl_test_abort_if(evpl_listen(ps->listener, ps->proto, ps->endpoint),
                       "failed to listen on '%s'", name);
} /* do_listen */

static void
do_stop_listen(struct prog_state *ps)
{
    evpl_listener_detach(ps->evpl, ps->binding);
    evpl_listener_destroy(ps->listener);
    evpl_endpoint_close(ps->endpoint);

    ps->binding  = NULL;
    ps->listener = NULL;
    ps->endpoint = NULL;
} /* do_stop_listen */

static void
do_connect(
    struct prog_state      *ps,
    const struct core_step *step)
{
    struct conn_slot *cs = &ps->conns[step->conn];

    cs->drain = step->drain;

    memset(cs->tx_off, 0, sizeof(cs->tx_off));
    memset(cs->rx_off, 0, sizeof(cs->rx_off));

    ps->pending_connect = step->conn;

    cs->bind[SIDE_CLIENT] = evpl_connect(ps->evpl, ps->proto, NULL,
                                         ps->endpoint, conn_notify_cb, NULL,
                                         &cs->ctx[SIDE_CLIENT]);

    evpl_test_abort_if(!cs->bind[SIDE_CLIENT],
                       "connect on conn %d returned no bind", step->conn);
} /* do_connect */

/*
 * Fill freshly allocated iovecs with the pattern the peer expects.  The
 * allocator may hand back several, so the pattern has to be written across
 * them by position rather than per-buffer.
 */
static void
fill_iovecs(
    uint64_t           off,
    struct evpl_iovec *iov,
    int                niov,
    int                len)
{
    uint64_t written = 0;
    int      i, j;

    for (i = 0; i < niov; i++) {
        uint8_t *p = iov[i].data;

        for (j = 0; j < (int) iov[i].length; j++) {
            p[j] = pattern_byte(off + written + j);
        }

        written += iov[i].length;
    }

    evpl_test_abort_if(written != (uint64_t) len,
                       "iovecs cover %llu bytes, asked for %d",
                       (unsigned long long) written, len);
} /* fill_iovecs */

static int
alloc_and_fill(
    struct prog_state *ps,
    uint64_t           off,
    int                len,
    struct evpl_iovec *iov)
{
    int niov = evpl_iovec_alloc(ps->evpl, len, 0, MAX_SEND_IOV, 0, iov);

    evpl_test_abort_if(niov < 1,
                       "failed to allocate %d bytes of send space in at most "
                       "%d iovecs", len, MAX_SEND_IOV);

    fill_iovecs(off, iov, niov, len);

    return niov;
} /* alloc_and_fill */

/*
 * Both ends of an unconnected pair.
 *
 * There is no listen, no connect and no handshake: each end binds an address
 * of its own and names the other's when it sends.  Nothing is notified about
 * the pair coming up, which is why the model owes nothing for this op where
 * connect owes two CONNECTED.
 */
static void
do_bind_pair(
    struct prog_state      *ps,
    const struct core_step *step)
{
    struct conn_slot *cs = &ps->conns[step->conn];
    int               s;

    memset(cs->tx_off, 0, sizeof(cs->tx_off));
    memset(cs->rx_off, 0, sizeof(cs->rx_off));

    for (s = 0; s < NUM_SIDE; s++) {
        cs->ep[s] = evpl_endpoint_create("127.0.0.1",
                                         CONF_BASE_PORT + g_port_seq++);

        evpl_test_abort_if(!cs->ep[s], "failed to create a bind endpoint");

        cs->bind[s] = evpl_bind(ps->evpl, ps->proto, cs->ep[s],
                                conn_notify_cb, &cs->ctx[s]);

        evpl_test_abort_if(!cs->bind[s],
                           "failed to bind conn %d side %d", step->conn, s);
    }
} /* do_bind_pair */

/*
 * Every send mode must put the same bytes on the wire; what differs is who
 * owns the references afterwards.  Without EVPL_SEND_FLAG_TAKE_REF the send
 * path clones and this end must release its own; with it the references are
 * handed over and releasing them here would be a double free.  Both directions
 * of getting that wrong are caught at teardown by evpl_allocator_destroy.
 */
static void
do_send(
    struct prog_state      *ps,
    const struct core_step *step)
{
    struct conn_slot     *cs   = &ps->conns[step->conn];
    struct evpl_bind     *bind = cs->bind[step->side];
    int                   dest = PEER(step->side);
    int                   len  = size_bytes(step->size);
    struct evpl_endpoint *dest_ep;
    struct evpl_iovec     iov[MAX_SEND_IOV];
    int                   niov, i;

    evpl_test_abort_if(len <= 0 || len > MAX_SEND_BYTES,
                       "size class %d is outside the driver's send buffer",
                       step->size);

    evpl_test_abort_if(!bind,
                       "send on conn %d side %d, which has no bind -- the "
                       "model believes this connection is up",
                       step->conn, step->side);

    switch (step->send) {
        case CSND_SENDBUF:
            for (i = 0; i < len; i++) {
                ps->sendbuf[i] = pattern_byte(cs->tx_off[dest] + i);
            }
            evpl_send(ps->evpl, bind, ps->sendbuf, len);
            break;

        /* Not generated today; see SendMode in core.qnt.  The arms stay so
         * that re-enabling them is a one-line change in the model once the
         * address ownership on that path is settled. */
        case CSND_SENDTOEP:
            dest_ep = cs->ep[dest] ? cs->ep[dest] : ps->endpoint;
            evpl_test_abort_if(!dest_ep,
                               "sendtoep with no endpoint to address");
            for (i = 0; i < len; i++) {
                ps->sendbuf[i] = pattern_byte(cs->tx_off[dest] + i);
            }
            evpl_sendtoep(ps->evpl, bind, dest_ep, ps->sendbuf, len);
            break;

        case CSND_SENDV:
            niov = alloc_and_fill(ps, cs->tx_off[dest], len, iov);
            evpl_sendv(ps->evpl, bind, iov, niov, len, 0);
            /* Cloned by the send path, so this end still holds its own. */
            evpl_iovecs_release(ps->evpl, iov, niov);
            break;

        case CSND_SENDRESERVECOMMIT:
            /* Reserve takes references on space without charging it to the
             * buffer; commit is what tells the allocator how much was used
             * and hands the rest back for the next allocation.  Sending with
             * TAKE_REF then transfers the references reserve took. */
            niov = evpl_iovec_reserve(ps->evpl, len, 0, MAX_SEND_IOV, iov);
            evpl_test_abort_if(niov < 1,
                               "failed to reserve %d bytes in at most %d iovecs",
                               len, MAX_SEND_IOV);
            fill_iovecs(cs->tx_off[dest], iov, niov, len);
            evpl_iovec_commit(ps->evpl, 0, iov, niov);
            evpl_sendv(ps->evpl, bind, iov, niov, len,
                       EVPL_SEND_FLAG_TAKE_REF);
            break;

        case CSND_SENDGLOBAL:
            /* One whole buffer whose lifetime this end owns outright.  Sent
             * without TAKE_REF so the send path takes a borrow -- which for a
             * GLOBAL buffer is not counted and does not keep it alive, so the
             * owning reference is held until teardown rather than released
             * here.  Releasing it now would hand the buffer back to the pool
             * while the transport still has it queued. */
            evpl_test_abort_if(ps->nglobals >= MAX_GLOBAL_IOV,
                               "program holds more than %d global iovecs",
                               MAX_GLOBAL_IOV);

            evpl_iovec_alloc_global(ps->evpl, &iov[0]);

            evpl_test_abort_if((int) evpl_iovec_length(&iov[0]) < len,
                               "a global iovec is %u bytes, too small for a "
                               "%d byte payload",
                               evpl_iovec_length(&iov[0]), len);

            evpl_iovec_set_length(&iov[0], len);
            fill_iovecs(cs->tx_off[dest], iov, 1, len);

            evpl_sendv(ps->evpl, bind, iov, 1, len, 0);

            /* Moved, not copied: an iovec carries ownership, and the debug
             * build tracks which struct holds it.  A plain assignment leaves
             * that tracking pointing at the stack slot this one came from. */
            evpl_iovec_move(&ps->globals[ps->nglobals++], &iov[0]);
            break;

        case CSND_SENDVTAKEREF:
            niov = alloc_and_fill(ps, cs->tx_off[dest], len, iov);
            evpl_sendv(ps->evpl, bind, iov, niov, len,
                       EVPL_SEND_FLAG_TAKE_REF);
            /* Handed over; releasing here would be a double free. */
            break;

        case CSND_SENDTOEPV:
            dest_ep = cs->ep[dest] ? cs->ep[dest] : ps->endpoint;
            evpl_test_abort_if(!dest_ep,
                               "sendtoepv with no endpoint to address");
            niov = alloc_and_fill(ps, cs->tx_off[dest], len, iov);
            evpl_sendtoepv(ps->evpl, bind, dest_ep, iov, niov, len,
                           EVPL_SEND_FLAG_TAKE_REF);
            break;

        default:
            evpl_test_abort("unknown send mode %d", step->send);
    } /* switch */

    cs->tx_off[dest] += len;
} /* do_send */

static int
run_step(
    struct prog_state      *ps,
    const struct core_step *step,
    int                     prog,
    int                     stepno)
{
    struct timer_slot    *ts;
    struct deferral_slot *ds;
    struct doorbell_slot *bs;
    struct conn_slot     *cs;

    g_results.steps++;

    evpl_test_abort_if(step->slot >= MAX_SLOT || step->conn >= MAX_CONN,
                       "program %d step %d: object index outside the driver's "
                       "tables", prog, stepno);

    switch (step->op) {
        case COP_OPADDTIMER:
            ts           = &ps->timers[step->slot];
            ts->delay_us = step->delay == CDLY_DFAST ? DELAY_FAST_US
                                                     : DELAY_SLOW_US;
            ts->rearm_left = step->timer_kind == CTK_TREARM ? 1 : 0;
            ts->armed      = 1;

            if (step->timer_kind == CTK_TPERIODIC) {
                evpl_add_timer(ps->evpl, &ts->timer, timer_cb, ts->delay_us);
                /* Periodic timers stay in the set until removed, so teardown
                 * has to know to take them out. */
                ts->armed = 2;
            } else {
                evpl_add_oneshot_timer(ps->evpl, &ts->timer, timer_cb,
                                       ts->delay_us);
            }
            break;

        case COP_OPREMOVETIMER:
            ts = &ps->timers[step->slot];
            evpl_remove_timer(ps->evpl, &ts->timer);
            ts->rearm_left = 0;
            ts->armed      = 0;
            break;

        case COP_OPDEFER:
            ds = &ps->deferrals[step->slot];
            evpl_defer(ps->evpl, &ds->deferral);
            break;

        case COP_OPDEFERTWICE:
            /* Two armings before the loop gets a chance to run either.  The
             * `armed` flag is supposed to collapse them into one callback. */
            ds = &ps->deferrals[step->slot];
            evpl_defer(ps->evpl, &ds->deferral);
            evpl_defer(ps->evpl, &ds->deferral);
            break;

        case COP_OPDEFERREENTRANT:
            ds               = &ps->deferrals[step->slot];
            ds->redefer_left = 1;
            evpl_defer(ps->evpl, &ds->deferral);
            break;

        case COP_OPADDDOORBELL:
            bs          = &ps->doorbells[step->slot];
            bs->present = 1;
            evpl_add_doorbell(ps->evpl, &bs->doorbell, doorbell_cb);
            evpl_test_abort_if(evpl_doorbell_fd(&bs->doorbell) < 0,
                               "program %d step %d: doorbell %d has no "
                               "descriptor after being added",
                               prog, stepno, step->slot);
            break;

        case COP_OPRINGDOORBELL:
            bs = &ps->doorbells[step->slot];
            evpl_ring_doorbell(&bs->doorbell);
            break;

        case COP_OPRINGDOORBELLTWICE:
            bs = &ps->doorbells[step->slot];
            evpl_ring_doorbell(&bs->doorbell);
            evpl_ring_doorbell(&bs->doorbell);
            break;

        case COP_OPREMOVEDOORBELL:
            bs          = &ps->doorbells[step->slot];
            bs->present = 0;
            evpl_remove_doorbell(ps->evpl, &bs->doorbell);
            break;

        case COP_OPREMOVEDOORBELLINCALLBACK:
            /* Arm the callback to retire it, then ring once.  The removal
             * happens inside the callback, during the next quiesce. */
            bs               = &ps->doorbells[step->slot];
            bs->remove_in_cb = 1;
            evpl_ring_doorbell(&bs->doorbell);
            break;

        case COP_OPREMOVEDEFERRAL:
        case COP_OPREMOVEDEFERRALIDLE:
            /* One call for both: the difference is the state it is made in,
             * which is the model's business, and the library's promise is
             * that the idle case is harmless. */
            ds               = &ps->deferrals[step->slot];
            ds->redefer_left = 0;
            evpl_remove_deferral(ps->evpl, &ds->deferral);
            break;

        case COP_OPREQUESTSENDNOTIFY:
            cs = &ps->conns[step->conn];
            evpl_test_abort_if(!cs->bind[step->side],
                               "send notifications requested on conn %d side "
                               "%d, which has no bind", step->conn, step->side);
            evpl_bind_request_send_notifications(ps->evpl,
                                                 cs->bind[step->side]);
            break;

        case COP_OPSETLOOPHOOKS:
            ps->hooks.iteration_end = hook_iteration_end_cb;
            ps->hooks.pre_wait      = hook_pre_wait_cb;
            ps->hooks.post_wait     = hook_post_wait_cb;
            ps->hooks.private_data  = ps;
            evpl_set_loop_hooks(ps->evpl, &ps->hooks);
            break;

        case COP_OPCLEARLOOPHOOKS:
            evpl_set_loop_hooks(ps->evpl, NULL);
            break;

        case COP_OPADDPOLL:
            ps->poll = evpl_add_poll(ps->evpl, poll_enter_cb, poll_exit_cb,
                                     poll_cb, ps);
            evpl_test_abort_if(!ps->poll, "evpl_add_poll returned nothing");
            break;

        case COP_OPREMOVEPOLL:
            evpl_remove_poll(ps->evpl, ps->poll);
            ps->poll = NULL;
            break;

        case COP_OPACTIVITY:
            evpl_activity(ps->evpl);
            break;

        case COP_OPPOLLPIN:
            evpl_poll_pin(ps->evpl);
            break;

        case COP_OPPOLLUNPIN:
            evpl_poll_unpin(ps->evpl);
            break;

        case COP_OPLISTEN:
            do_listen(ps, prog);
            break;

        case COP_OPSTOPLISTEN:
            do_stop_listen(ps);
            break;

        case COP_OPBINDPAIR:
            do_bind_pair(ps, step);
            break;

        case COP_OPCONNECT:
            do_connect(ps, step);
            break;

        case COP_OPSEND:
            do_send(ps, step);
            break;

        case COP_OPCLOSE:
            cs = &ps->conns[step->conn];
            evpl_test_abort_if(!cs->bind[step->side],
                               "close on conn %d side %d, which has no bind",
                               step->conn, step->side);
            evpl_close(ps->evpl, cs->bind[step->side]);
            break;

        case COP_OPFINISH:
            cs = &ps->conns[step->conn];
            evpl_test_abort_if(!cs->bind[step->side],
                               "finish on conn %d side %d, which has no bind",
                               step->conn, step->side);
            evpl_finish(ps->evpl, cs->bind[step->side]);
            break;

        case COP_OPQUIESCE:
            return do_quiesce(ps, step, prog, stepno);

        default:
            evpl_test_abort("program %d step %d: op %d has no arm in the "
                            "driver", prog, stepno, step->op);
    } /* switch */

    return 0;
} /* run_step */

/*
 * Teardown is the driver's own business, not part of the specification under
 * test: the model does not require a program to leave its objects retired, so
 * anything still armed, connected or listening is taken out here rather than
 * left for evpl_destroy to find.
 */
static void
teardown_program(struct prog_state *ps)
{
    int i, s;

    for (i = 0; i < MAX_CONN; i++) {
        for (s = 0; s < NUM_SIDE; s++) {
            if (ps->conns[i].bind[s]) {
                evpl_close(ps->evpl, ps->conns[i].bind[s]);
            }
        }
    }

    /* Let those closes dispatch.  Their disconnect callbacks land after the
     * last window, where nothing is checking, which is the point: a program's
     * claims end with its last quiesce. */
    settle(ps);

    if (ps->listener) {
        do_stop_listen(ps);
    }

    for (i = 0; i < MAX_CONN; i++) {
        for (s = 0; s < NUM_SIDE; s++) {
            if (ps->conns[i].ep[s]) {
                evpl_endpoint_close(ps->conns[i].ep[s]);
                ps->conns[i].ep[s] = NULL;
            }
        }
    }

    if (ps->poll) {
        evpl_remove_poll(ps->evpl, ps->poll);
    }

    /* The owning reference on each global buffer, given back exactly once.
    * Clones the send path took are non-owning and must not be released. */
    for (i = 0; i < ps->nglobals; i++) {
        evpl_iovec_release(ps->evpl, &ps->globals[i]);
    }

    for (i = 0; i < MAX_SLOT; i++) {
        if (ps->timers[i].armed) {
            evpl_remove_timer(ps->evpl, &ps->timers[i].timer);
        }
        if (ps->doorbells[i].present) {
            evpl_remove_doorbell(ps->evpl, &ps->doorbells[i].doorbell);
        }
    }

    evpl_destroy(ps->evpl);
} /* teardown_program */

static int
run_program(
    const struct core_program *p,
    int                        prog)
{
    struct evpl_thread_config *tcfg;
    struct prog_state         *ps;
    int                        i, s, failures = 0;

    ps = calloc(1, sizeof(*ps));
    evpl_test_abort_if(!ps, "out of memory");

    ps->pending_connect = -1;

    for (i = 0; i < MAX_SLOT; i++) {
        ps->timers[i].ps      = ps;
        ps->timers[i].slot    = i;
        ps->deferrals[i].ps   = ps;
        ps->deferrals[i].slot = i;
        ps->doorbells[i].ps   = ps;
        ps->doorbells[i].slot = i;

        evpl_deferral_init(&ps->deferrals[i].deferral, deferral_cb,
                           &ps->deferrals[i]);
    }

    for (i = 0; i < MAX_CONN; i++) {
        for (s = 0; s < NUM_SIDE; s++) {
            ps->conns[i].ctx[s].ps   = ps;
            ps->conns[i].ctx[s].conn = i;
            ps->conns[i].ctx[s].side = s;
        }
    }

    /*
     * Poll mode on for every program: with no poll registered the loop never
     * enters it, so this costs the programs that do not use one nothing and
     * saves the model a per-program dimension.  See POLL_ITERATIONS for why
     * the default iteration count would make the mode untestable.
     *
     * No wait_ms: on the virtual clock the core wait is already non-blocking,
     * because nothing can become due while the loop is inside it.
     *
     * evpl_create() takes ownership of the config and releases it itself.
     */
    tcfg = evpl_thread_config_init();
    evpl_thread_config_set_poll_mode(tcfg, 1);
    evpl_thread_config_set_poll_iterations(tcfg, POLL_ITERATIONS);
    ps->evpl = evpl_create(tcfg);

    /* Every step of a program carries the same transport, so the first one
     * settles it. */
    switch (core_steps[p->first_step].transport) {
        case CTR_TSTREAMINPROC:
            ps->proto = EVPL_STREAM_INPROC;
            break;
        case CTR_TDATAGRAMINPROC:
            ps->proto = EVPL_DATAGRAM_INPROC;
            break;
        case CTR_TSTREAMTCP:
            ps->proto = EVPL_STREAM_SOCKET_TCP;
            break;
        case CTR_TSTREAMUNIX:
            ps->proto = EVPL_STREAM_SOCKET_UNIX;
            break;
        case CTR_TDATAGRAMUDP:
            ps->proto = EVPL_DATAGRAM_SOCKET_UDP;
            break;
        default:
            evpl_test_abort("program %d names a transport the driver has no "
                            "arm for", prog);
    } /* switch */

    /* Where this program's model clock starts.  The clock is process-wide and
     * monotonic, so each program takes a base rather than resetting it. */
    ps->base_ns = evpl_virtual_clock_now();

    for (i = 0; i < p->nsteps; i++) {
        if (g_trace) {
            const struct core_step *ts = &core_steps[p->first_step + i];

            fprintf(stderr, "prog %d step %d: %s conn=%d side=%d size=%d "
                    "send=%d\n", prog, i, op_name(ts->op), ts->conn, ts->side,
                    ts->size, ts->send);
        }

        failures += run_step(ps, &core_steps[p->first_step + i], prog, i);
    }

    teardown_program(ps);

    free(ps);

    return failures;
} /* run_program */

/*
 * Facts that are neither model state nor sequence-dependent.
 *
 * The protocol predicates and the endpoint accessors are pure functions of
 * their arguments: there is no ordering to get wrong and nothing for a
 * quiesce to observe, so bending them into the model would be bending it
 * around something it is not about.  They are held here as a flat table
 * instead, the same way conformance.c holds its connection-notification
 * checks.
 */
static void
check_static_facts(void)
{
    struct evpl_endpoint *inproc, *inet, *local;
    enum evpl_protocol_id proto;
    char                  scrape[8192];
    struct timespec       t0, t1;
    struct evpl          *evpl;
    int                   n;

    /* Protocol predicates.  Each protocol is exactly one of stream and
     * datagram, and at most one of local and in-process; an unavailable one
     * reports 0 from every predicate, which is how a caller tells "not a
     * stream" from "not built". */
    evpl_test_abort_if(!evpl_protocol_available(EVPL_STREAM_INPROC) ||
                       !evpl_protocol_available(EVPL_DATAGRAM_INPROC),
                       "the in-process protocols are not available");

    evpl_test_abort_if(!evpl_protocol_is_stream(EVPL_STREAM_INPROC) ||
                       evpl_protocol_is_stream(EVPL_DATAGRAM_INPROC),
                       "stream/datagram misreported for the inproc protocols");

    evpl_test_abort_if(!evpl_protocol_is_inproc(EVPL_STREAM_INPROC) ||
                       evpl_protocol_is_inproc(EVPL_STREAM_SOCKET_TCP),
                       "in-process misreported");

    evpl_test_abort_if(evpl_protocol_is_local(EVPL_STREAM_INPROC) ||
                       !evpl_protocol_is_local(EVPL_STREAM_SOCKET_UNIX),
                       "local misreported: an inproc name is not a socket path");

    evpl_test_abort_if(evpl_protocol_lookup(&proto, "STREAM_INPROC") ||
                       proto != EVPL_STREAM_INPROC,
                       "protocol lookup by name failed");

    /* Endpoint kinds are distinguished, and each renders back what it was
     * given. */
    inproc = evpl_endpoint_create_inproc("core-conf-facts");
    inet   = evpl_endpoint_create("127.0.0.1", 8123);
    local  = evpl_endpoint_create_local("/tmp/core-conf-facts.sock");

    evpl_test_abort_if(!inproc || !inet || !local,
                       "an endpoint of one of the three kinds was refused");

    evpl_test_abort_if(!evpl_endpoint_is_inproc(inproc) ||
                       evpl_endpoint_is_local(inproc),
                       "an in-process endpoint reports the wrong kind");

    evpl_test_abort_if(evpl_endpoint_is_inproc(local) ||
                       !evpl_endpoint_is_local(local),
                       "a local endpoint reports the wrong kind");

    evpl_test_abort_if(evpl_endpoint_is_inproc(inet) ||
                       evpl_endpoint_is_local(inet),
                       "an inet endpoint reports the wrong kind");

    evpl_test_abort_if(strcmp(evpl_endpoint_address(inet), "127.0.0.1") ||
                       evpl_endpoint_port(inet) != 8123,
                       "an inet endpoint does not render back what it was given");

    evpl_endpoint_close(inproc);
    evpl_endpoint_close(inet);
    evpl_endpoint_close(local);

    /* The high-frequency clock is monotonic.  It is deliberately NOT the
     * virtual clock -- it is anchored to CLOCK_MONOTONIC at init and reports
     * real time, so this is the one thing here that a stopped clock does not
     * stop. */
    evpl = evpl_create(NULL);

    evpl_get_hf_monotonic_time(evpl, &t0);
    evpl_get_hf_monotonic_time(evpl, &t1);

    evpl_test_abort_if(t1.tv_sec < t0.tv_sec ||
                       (t1.tv_sec == t0.tv_sec && t1.tv_nsec < t0.tv_nsec),
                       "the high-frequency clock went backwards");

    evpl_destroy(evpl);

    evpl_test_abort_if(evpl_get_slab_size() == 0, "the slab size is zero");

    /* Metrics serialize into a caller's buffer, and report -1 rather than
     * truncating when it is too small. */
    n = evpl_metrics_scrape(scrape, sizeof(scrape));

    evpl_test_abort_if(n <= 0, "metrics scrape produced nothing (%d)", n);
    evpl_test_abort_if(!strstr(scrape, "evpl_allocator"),
                       "metrics scrape has no allocator counters in it");
    evpl_test_abort_if(evpl_metrics_scrape(scrape, 4) != -1,
                       "metrics scrape into a 4 byte buffer did not report -1");
} /* check_static_facts */

/*
 * Everything this test claims about time is claimed against libevpl's own
 * clock, so the first thing it does is take that clock over.  Without this
 * the model's windows would be wall-clock windows and every verdict in the
 * suite would carry the machine's load in it.
 */
static void
core_conformance_init(void)
{
    struct evpl_global_config *config = evpl_global_config_init();

    evpl_global_config_set_virtual_clock(config, 1);

    /* A buffer well under the largest payload class, so payloads actually
     * span several iovecs and the gather/scatter paths are walked rather than
     * short-circuited; see CONF_BUFFER_SIZE. */
    evpl_global_config_set_buffer_size(config, CONF_BUFFER_SIZE);

    /* Set rather than left to the default, because the model computes its
     * poll-mode transitions against it. */
    evpl_global_config_set_spin_ns(config, CONF_SPIN_NS);

    /* Stated explicitly for the same reason: the driver's MAX_SEND_IOV and
     * the ring depth bound what a program can have in flight. */
    evpl_global_config_set_max_num_iovec(config, MAX_SEND_IOV * 2);

    /*
     * Under the buffer size, and deliberately so: a datagram receive buffer
     * is one contiguous iovec, so a max_datagram_size larger than a buffer
     * cannot be satisfied from one.  The default is 64 KiB, which the 32 KiB
     * buffer above cannot hold -- and libevpl neither rejects that
     * combination nor copes with it, it just hands back a short buffer and
     * loses datagrams.  Kept well above the largest payload the model sends
     * over a datagram transport.
     */
    evpl_global_config_set_max_datagram_size(config, CONF_BUFFER_SIZE / 2);
    evpl_global_config_set_iovec_ring_size(config, 1024);

    /* As test_evpl_config(), which this replaces: ctest runs the suite once
     * per event-loop mechanism compiled in and selects it through the
     * environment. */
    test_evpl_set_core_mech(config);

    evpl_init(config);
} /* core_conformance_init */

int
main(
    int   argc,
    char *argv[])
{
    unsigned int i;
    int          failures = 0;

    /* Unbuffered: a sanitizer that finds something at exit terminates the
     * process without flushing, and losing the run's summary to that is how a
     * report goes missing exactly when it is most wanted. */
    setvbuf(stdout, NULL, _IONBF, 0);

    g_trace = getenv("CORE_TRACE") != NULL;

    g_trace = getenv("CORE_TRACE") != NULL;

    core_conformance_init();

    check_static_facts();

    evpl_test_info("running %u core programs, %u steps",
                   (unsigned int) CORE_NUM_PROGRAMS,
                   (unsigned int) (sizeof(core_steps) / sizeof(core_steps[0])));

    for (i = 0; i < CORE_NUM_PROGRAMS; i++) {
        failures += run_program(&core_programs[i], (int) i);
        g_results.programs++;
    }

    g_results.failed = failures;

    printf("core programs: %d run, %d steps, %d quiesces, %d obligations "
           "checked, %llu payload bytes verified, %d known divergences, "
           "%d failures\n",
           g_results.programs, g_results.steps, g_results.quiesces,
           g_results.obligations, (unsigned long long) g_results.bytes,
           g_results.known, g_results.failed);

    if (failures) {
        printf("Test FAILED\n");
        return 1;
    }

    printf("Test PASSED\n");
    return 0;
} /* main */
