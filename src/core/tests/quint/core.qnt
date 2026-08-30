// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * core.qnt -- a behaviour model of libevpl's core SDK, as a C program.
 *
 * The RPC2 models (src/rpc2/tests/quint) enumerate independent cases: each
 * trace state is one defective message and the verdict on it, and the trace is
 * only a sampling device.  That works because an RPC exchange is memoryless.
 *
 * Nothing about the core API is memoryless.  A one-shot fires once and then
 * must not fire again; a deferral armed twice runs once; a doorbell retired
 * from inside its own callback must not be called back afterwards.  Every one
 * of those is a statement about a SEQUENCE, so here a trace is not a bag of
 * cases -- it is a PROGRAM, and the C driver is an interpreter for it.
 *
 * Each program is a run of ops against a freshly created evpl, bracketed by
 * OpReset.  What travels with the program is not a predicted return value --
 * an asynchronous API has none to predict -- but the set of callbacks the
 * library then owes, which OpQuiesce is where the driver collects.
 *
 * Three rules carry most of the weight:
 *
 *   1. Every callback the model says is owed must arrive within the quiesce
 *      window.  A window that closes with an obligation outstanding is the
 *      "completion that never came" bug, which is silent in production and
 *      presents as a hang.
 *
 *   2. Every callback that arrives must be owed.  An event with no expectation
 *      covering it fails the program, which is what makes "the removed timer
 *      stopped firing" and "the one-shot did not refire" checkable at all --
 *      they are absences, and an absence is only observed by waiting for it.
 *
 *   3. A quiesce runs its FULL window, never stopping early at satisfaction.
 *      Rule 2 is worthless otherwise: an early exit observes no absence.
 *
 * This model encodes the SPECIFICATION -- what the header comments in
 * include/evpl promise -- not what libevpl currently does.  Where the two
 * disagree the driver records a divergence, reviewed as a candidate bug.
 *
 *   quint test core.qnt
 *   quint run core.qnt --invariant=safety
 */
module evpl_core {

    // ------------------------------------------------------------------
    // Object slots
    //
    // Small and fixed: the driver owns a static array per kind and the model
    // traffics in indices.  Two of each is enough for every property here --
    // the ones that need a second object (timer ordering, one deferral armed
    // while another is not) need exactly two.
    // ------------------------------------------------------------------

    /// Four timers, not two: evpl_timer_insert/evpl_pop_timer keep a binary
    /// heap, and a heap of two never takes its sift-down branches.  Four is
    /// the smallest size that gives the head two children and a grandchild to
    /// move past.
    pure val NUM_TIMER = 4
    pure val NUM_DEFERRAL = 2
    pure val NUM_DOORBELL = 2
    pure val NUM_CONN = 2

    pure val TIMER_SLOTS = 0.to(NUM_TIMER - 1)
    pure val DEFERRAL_SLOTS = 0.to(NUM_DEFERRAL - 1)
    pure val DOORBELL_SLOTS = 0.to(NUM_DOORBELL - 1)
    pure val CONN_SLOTS = 0.to(NUM_CONN - 1)

    /// A connection has two ends and both are observable from one evpl, so
    /// events name an END rather than a connection.  Flattening the pair into
    /// one index keeps the driver's event log a single (kind, slot) table
    /// instead of growing a third dimension for one op family.
    pure val SIDE_CLIENT = 0
    pure val SIDE_SERVER = 1
    pure val SIDES = Set(SIDE_CLIENT, SIDE_SERVER)

    pure def sideSlot(c: int, side: int): int = c * 2 + side
    pure def peer(side: int): int = 1 - side

    pure val END_SLOTS = CONN_SLOTS.map(c => SIDES.map(s => sideSlot(c, s))).flatten()

    /// Block queues, all on one device.  Two rather than one: a queue owns
    /// its own completion path and a backend threads each completion back to
    /// the queue that submitted it, so a second queue is what makes
    /// "delivered to the right one" a claim at all.
    pure val NUM_BLOCK_QUEUE = 2
    pure val BLOCK_QUEUE_SLOTS = 0.to(NUM_BLOCK_QUEUE - 1)

    /// The device is cut into fixed regions and every data op addresses
    /// exactly one whole region.  Content is then a property of a region
    /// rather than of an arbitrary extent, which is what makes "what does
    /// this read return" answerable without modelling a byte map.
    pure val NUM_REGION = 4
    pure val REGION_SLOTS = 0.to(NUM_REGION - 1)

    /// Ops per program, not counting the OpReset that opens it.  Short on
    /// purpose: a failure at step 380 of a 400-step program is not
    /// debuggable, so this buys coverage with many short programs rather than
    /// a few long ones.
    pure val PROGRAM_LEN = 12

    // ------------------------------------------------------------------
    // Model time
    //
    // The model keeps a millisecond clock that advances ONLY inside a
    // quiesce, by exactly that quiesce's budget.
    //
    // That clock is not an approximation of wall-clock time -- it IS
    // libevpl's clock.  The driver puts the library on a virtual clock
    // (evpl_global_config_set_virtual_clock) and advances it a millisecond at
    // a time with evpl_virtual_clock_advance, so a deadline the model places
    // at 50ms is a deadline the event loop places at 50ms, exactly, on any
    // machine under any load.
    //
    // Everything about this model that concerns time therefore reduces to
    // integer arithmetic on both sides.  There is no guard band around a
    // window edge, no tolerance for a descheduled millisecond, and nothing to
    // retry: a test whose verdict depended on how busy the machine was would
    // be a test of the machine.  What remains genuinely asynchronous -- when
    // a queued payload becomes visible to its peer -- is not time-dependent
    // and is settled by driving the loop until it stops producing events.
    //
    // The clock is also what makes "must not have fired yet" a sound claim
    // across more than one quiesce.  Deciding it per-quiesce instead -- "is
    // this budget longer than that delay" -- is wrong the moment a program
    // has two short quiesces in a row, because a timer's deadline is measured
    // from when it was armed and not from when the window opened.
    // ------------------------------------------------------------------

    type DelayCls = | DFast | DSlow
    type Budget = | QShort | QLong

    pure def delayMs(d: DelayCls): int =
        match d {
            | DFast => 1
            | DSlow => 50
        }

    pure def budgetMs(b: Budget): int =
        match b {
            | QShort => 10
            | QLong => 100
        }

    /// Every block request submitted on a queue owes exactly one completion,
    /// and owes it in the window it was submitted in.  Exactly, not at least:
    /// a request whose callback fires twice has run the caller's completion
    /// handling twice, which is the same class of bug as one that never fires
    /// and just as quiet.
    ///
    /// There is no ordering claim.  The API queues requests and says nothing
    /// about the order they finish in, so what is owed is a COUNT.
    pure def blockExpect(q: int, owes: int): Set[Expect] =
        if (owes > 0)
            Set({ kind: EvBlock, slot: q, mult: MExactly, count: owes })
        else Set()

    /// Order is only claimed between deadlines at least this far apart.  Two
    /// timers due within a millisecond of each other are ordered by the heap's
    /// tie-breaking, which is not something the API promises.
    pure val ORDER_GAP_MS = 10

    // ------------------------------------------------------------------
    // Ops
    //
    // Modelled after values.qnt's Case: one flat record whose fields are only
    // meaningful for the ops that read them.  Keeping the arguments out of
    // the variant payloads is what lets the generated C row be a fixed struct
    // rather than a tagged union.
    // ------------------------------------------------------------------

    type OpKind =
        /* Program boundary.  Not an op the driver runs: it creates a fresh
         * evpl and clears its object table. */
        | OpReset

        /* --- timers (evpl_timer.h) ------------------------------------- */
        | OpAddTimer
        | OpRemoveTimer

        /* --- deferrals (evpl_deferral.h) ------------------------------- */
        | OpDefer
        /* Two evpl_defer() calls back to back.  The `armed` flag is supposed
         * to coalesce them into one callback; a deferral that ran twice would
         * run application bookkeeping twice per arming. */
        | OpDeferTwice
        /* The callback re-arms itself once.  Distinguishes "coalesces while
         * armed" from "cannot be re-armed at all". */
        | OpDeferReentrant
        /* Disarm one that is armed: its callback is cancelled and must not
         * run.  Rule 2 is what checks that -- nothing expects it, so a
         * callback that arrives anyway fails the window. */
        | OpRemoveDeferral
        /* And on one that is not armed, which the API documents as a no-op.
         * A separate op because "harmless" is a claim about a different state
         * and the driver reaches a different branch for it. */
        | OpRemoveDeferralIdle

        /* --- doorbells (evpl_doorbell.h) ------------------------------- */
        | OpAddDoorbell
        | OpRingDoorbell
        /* Two rings before the loop runs.  An eventfd counts, but a doorbell
         * is a wakeup and not a queue, so one callback is enough -- hence
         * "at least once" rather than twice. */
        | OpRingDoorbellTwice
        | OpRemoveDoorbell
        /* Retire from inside the doorbell's own callback.  The header
         * explicitly permits this ("including from inside the doorbell's own
         * callback"), and it is where a dispatch loop that keeps indexing an
         * array it just mutated goes wrong. */
        | OpRemoveDoorbellInCallback

        /* --- the transport (evpl_bind.h, evpl_endpoint.h) -------------- */
        /* Create a listener, attach it to this evpl, and listen on an
         * in-process name.  One op rather than three: a listener that is
         * created but never attached or never listened on has no observable
         * behaviour to state. */
        | OpListen
        | OpStopListen
        /* Bind both ends of a UDP pair.  One op rather than two because an
         * unconnected bind has no peer and no handshake: the pair exists as
         * soon as both ends do, and nothing is notified about it.  Modelling
         * each bind separately would add a state with no observable
         * behaviour attached to it. */
        | OpBindPair
        | OpConnect
        | OpSend
        /* evpl_close: drop the connection.  Only ever generated with nothing
         * in flight, because whether a close delivers what was already queued
         * is exactly the question evpl_finish exists to answer differently --
         * modelling close as "may or may not deliver" would state nothing. */
        | OpClose
        /* evpl_finish: close once everything queued has been sent.  What is
         * queued must therefore still arrive, which is the obligation that
         * separates the two. */
        | OpFinish

        /* --- poll mode (evpl_poll.h) ----------------------------------- */
        /* A poll runs on every pass of the loop while the thread is spinning,
         * and the thread stops spinning after spin_ns without activity.  The
         * enter and exit callbacks bracket that, so between them they say
         * exactly when the loop was in poll mode -- which is the only part of
         * this an application can observe. */
        /* Ask for EVPL_NOTIFY_SENT on this end.  Nothing is notified until it
         * is asked for, so this is the op that turns a send into an
         * obligation in the other direction. */
        | OpRequestSendNotify

        /* Per-iteration hooks (evpl_set_loop_hooks).  Install and clear;
         * while installed, each of the three must be called. */
        | OpSetLoopHooks
        | OpClearLoopHooks

        | OpAddPoll
        | OpRemovePoll
        /* Report activity, which restarts the spin window and so brings the
         * loop back into poll mode.  This is how a framework that polls a
         * ring keeps the thread spinning. */
        | OpActivity
        /* Pin the thread into poll mode regardless of the spin window, and
         * release it.  Refcounted, so the model tracks a count rather than a
         * flag. */
        | OpPollPin
        | OpPollUnpin

        /* --- block I/O (evpl_block.h) ---------------------------------- */
        /* Open a per-thread queue on the program's device, and close it.
         * The device itself is not an op: it is opened once per program by
         * the driver, because a program with no device has no block
         * behaviour to state and nothing else varies with it. */
        | OpOpenQueue
        /* Closing is only legal with nothing outstanding -- a request in
         * flight still names the queue it was submitted on -- so the model
         * never generates it otherwise.  That is the contract, not a
         * limitation of the model. */
        | OpCloseQueue
        | OpBlockRead
        | OpBlockWrite
        /* The same write with sync set.  A separate op rather than a flag on
         * OpBlockWrite so that op coverage says whether the durable path was
         * reached; nothing else observable distinguishes them, since whether
         * a write survives a crash is not a question this suite can put. */
        | OpBlockWriteSync
        | OpBlockFlush
        /* Documented as a data guarantee: the range reads back as zeros. */
        | OpBlockWriteZeroes
        /* The same, over the whole device rather than one region.  A separate
         * op because the range is what makes it interesting: a backend
         * without native zeroing emulates it by writing a zero buffer, and a
         * range larger than one buffer is what makes that emulation loop. */
        | OpBlockWriteZeroesAll
        /* Documented as advisory: the backend may drop the range or ignore
         * the hint, and what reads back afterwards is unspecified.  So the
         * model asserts the completion and then stops claiming to know what
         * is there -- asserting either outcome would be inventing a promise
         * the header explicitly declines to make. */
        | OpBlockDiscard

        /* --- the loop -------------------------------------------------- */
        | OpQuiesce

    /// A one-shot fires once; a periodic keeps firing until removed; a
    /// re-armer is a one-shot whose callback arms it a second time, which is
    /// only legal because the loop pops a one-shot BEFORE calling it.
    ///
    /// Periodic and re-arming timers are held to DFast so that a window
    /// always contains a firing of the one and both firings of the other.
    /// Allowing them to be slow would mean predicting WHICH windows of a
    /// repeating series contain a deadline, which buys no new code path in
    /// libevpl and a great deal of arithmetic here.
    type TimerKind = | TOneshot | TPeriodic | TRearm

    /// Payload sizes, as classes.  Tiny and Small stay inside one buffer;
    /// Medium and Large are chosen to span several, so the send and receive
    /// paths have to gather and scatter rather than hand over a single iovec.
    ///
    /// The driver maps them to 1, 100, 8192 and 131072 bytes.
    type SizeCls = | SzTiny | SzSmall | SzMedium | SzLarge

    pure def sizeBytes(s: SizeCls): int =
        match s {
            | SzTiny => 1
            | SzSmall => 100
            | SzMedium => 8192
            | SzLarge => 131072
        }

    /// How the sending end hands its bytes over.  All five must put the same
    /// byte stream on the wire, so the model states one obligation and the
    /// driver varies the call -- the same shape as DrainMode below.
    ///
    /// The two iovec forms differ in who owns the references afterwards, and
    /// that is the point of having both: without EVPL_SEND_FLAG_TAKE_REF the
    /// send path clones and the caller must release its own, with it the send
    /// path takes them over and the caller must not.  Getting it backwards is
    /// a leak one way and a double free the other, and evpl_allocator_destroy
    /// fails the program either way.
    type SendMode =
        | SendBuf        /* evpl_send: the library bounces the bytes      */
        | SendV          /* evpl_sendv, caller keeps its references       */
        | SendVTakeRef   /* evpl_sendv, references handed over            */
        /* Addressed by endpoint rather than by the bind's peer.  Declared
         * but NOT generated: evpl_sendtoep and evpl_sendtoepv resolve the
         * endpoint for a +1 reference and hand it to evpl_sendto/evpl_sendtov,
         * which treat the address as borrowed and keep the pointer in the
         * queued dgram until the flush -- so nobody releases it and every call
         * leaks a reference.  Releasing it in the wrapper is not the fix: on
         * an INET endpoint the cache is re-resolved on a timer and the old
         * address freed, so the queued dgram would be left pointing at freed
         * memory (confirmed -- it turns the UDP tests into use-after-free).
         * The fix is for the send path to take a reference of its own and
         * every transport to release it on completion, which is a change
         * across all of them; until then generating these would only mean
         * choosing which failure to have. */
        | SendToEp
        | SendToEpV
        /* evpl_iovec_reserve + evpl_iovec_commit: take space, fill it, then
         * tell the allocator how much was actually used.  A distinct path
         * from evpl_iovec_alloc, and the only one that hands the unused tail
         * of a buffer back for the next allocation. */
        | SendReserveCommit
        /* evpl_iovec_alloc_global: one whole registered buffer whose lifetime
         * the caller owns outright.  The library's own refcount operations on
         * it are no-ops, so what is being tested is that a borrow taken by the
         * send path neither frees it nor keeps it alive: the driver holds the
         * single owning reference until the program is over. */
        | SendGlobal

    /// How the receiving end takes its bytes off the bind.  All three must be
    /// interchangeable -- the byte stream is the same however it is drained --
    /// so the model treats them as one obligation and the driver varies the
    /// call.  evpl_peek/evpl_consume and evpl_recvv have no other coverage.
    /// evpl_peekv is the odd one out and is here because of it: unlike
    /// evpl_recvv it does NOT clone, so the iovecs it hands back are borrowed
    /// views that must not be released, and it does not consume either.  That
    /// asymmetry is documented nowhere, and a receiver that gets it wrong
    /// double-frees.
    type DrainMode =
        | DrainRecv
        | DrainRecvV
        | DrainPeek        /* evpl_peek + evpl_consume, copying    */
        | DrainPeekV       /* evpl_peekv + evpl_consume, borrowing */

    /// A connection is CConnecting until the quiesce in which both ends see
    /// EVPL_NOTIFY_CONNECTED, and CClosing until the one in which both see
    /// EVPL_NOTIFY_DISCONNECTED.  Neither transition is instantaneous, and a
    /// model that treated them as such would let a program use a bind that
    /// does not exist yet.
    type ConnSt = | CFree | CConnecting | CUp | CClosing

    /// Which in-process transport a program runs over.  Chosen per program
    /// rather than per connection, because it is fixed at listen and connect
    /// and the two ends must agree.
    ///
    /// The difference that matters is the one the model states: a stream
    /// preserves bytes and a datagram preserves MESSAGES.  A stream may
    /// deliver what was sent in any number of pieces, so only the byte total
    /// is owed; a datagram owes exactly one delivery per send, which is the
    /// whole point of it and the only thing that distinguishes the two.
    type TransportKind =
        | TStreamInproc
        | TDatagramInproc
        | TStreamTcp
        | TStreamUnix
        | TDatagramUdp

    /// What the transport owes: bytes, or whole messages.
    pure def isDatagram(k: TransportKind): bool =
        k == TDatagramInproc or k == TDatagramUdp

    /// Whether it has a connection at all.  UDP does not: it is bind-only --
    /// no listen, no connect, no CONNECTED -- so it needs a lifecycle of its
    /// own rather than a variation on the connected one.
    pure def isConnected(k: TransportKind): bool = k != TDatagramUdp

    /// Addressed by a filesystem path rather than a port or a private name.
    /// The driver has to supply one; libevpl owns it from there, including
    /// removing it at teardown and stepping over a stale predecessor.
    pure def isLocal(k: TransportKind): bool = k == TStreamUnix

    /// How many iovecs a block request is scattered across.  One is the
    /// contiguous case; the others make the backend walk a list, and 16 is
    /// past the point where a backend that keeps a small inline array has to
    /// allocate one instead.
    type SegCls = | BSeg1 | BSeg4 | BSeg16

    pure def segCount(s: SegCls): int =
        match s {
            | BSeg1 => 1
            | BSeg4 => 4
            | BSeg16 => 16
        }

    /// What a region holds, as a byte value: CONTENT_UNKNOWN when nothing is
    /// claimed (never written, or discarded), CONTENT_ZERO after
    /// write_zeroes, and otherwise the byte a write filled it with.
    pure val CONTENT_UNKNOWN = -1
    pure val CONTENT_ZERO = 0

    type Step = {
        op: OpKind,
        slot: int,
        timerKind: TimerKind,
        delay: DelayCls,
        budget: Budget,
        conn: int,
        side: int,
        transport: TransportKind,
        size: SizeCls,
        send: SendMode,
        drain: DrainMode,
        /* Block I/O: which queue, which region, how many segments, and the
         * byte the region is filled with (a write) or must read back as (a
         * read).  CONTENT_UNKNOWN on a read means the model has no claim to
         * make about the bytes, only about the completion. */
        queue: int,
        region: int,
        segs: SegCls,
        pattern: int,
        /* Model time at the END of this step.  Only a quiesce advances it;
         * the driver uses it as the absolute deadline to run that quiesce
         * to. */
        atMs: int
    }

    pure val NOP_STEP: Step = {
        op: OpReset, slot: 0, timerKind: TOneshot, delay: DFast,
        budget: QShort, conn: 0, side: SIDE_CLIENT, transport: TStreamInproc,
        size: SzTiny,
        send: SendBuf, drain: DrainRecv,
        queue: 0, region: 0, segs: BSeg1, pattern: CONTENT_UNKNOWN,
        atMs: 0
    }

    // ------------------------------------------------------------------
    // Observations
    //
    // The event log the driver keeps, and the shape of a claim about it.
    // Everything asserted here is reachable through the public headers; the
    // model may not talk about anything that needs a peek inside struct evpl.
    // ------------------------------------------------------------------

    /// EvRecv is the one event whose obligation counts BYTES rather than
    /// callbacks: how many notifications a stream is delivered in is the
    /// transport's business, but how many bytes come out of it is not.
    type EventKind =
        | EvTimer
        | EvDeferral
        | EvDoorbell
        | EvConnected
        | EvDisconnected
        | EvRecv
        /* The loop entered or left poll mode.  EvPoll is the poll callback
         * itself, which fires on every pass while spinning -- the driver logs
         * only its first firing in a window, since an event per pass would
         * mean the loop never looked settled. */
        | EvPollEnter
        | EvPollExit
        | EvPoll
        /* Bytes reported sent on an end that asked to be told.  Counted in
         * bytes for the same reason EvRecv is: how many notifications the
         * transport batches them into is its business. */
        /* One delivery.  Only a datagram owes these -- see TransportKind --
         * and it owes exactly one per send. */
        | EvRecvMsg
        | EvSent
        /* One of the three loop hooks ran; the slot says which.  Logged once
         * per window, like EvPoll, since they fire on every pass. */
        | EvHook
        /* One block request completed, on the queue it was submitted on.
         * Counted exactly: an asynchronous I/O that completes twice is as
         * wrong as one that never completes, and both are silent. */
        | EvBlock

    /// MExactly is a closed claim, MAtLeast an open one.  The distinction is
    /// not laziness: a periodic timer's firing count over a wall-clock window
    /// is genuinely unspecified, and a doorbell's is genuinely allowed to
    /// coalesce, so demanding a number there would be demanding a guarantee
    /// the API does not make.
    type Mult = | MExactly | MAtLeast

    type Expect = { kind: EventKind, slot: int, mult: Mult, count: int }

    /// First occurrence of `first` must precede first occurrence of `then`.
    type Order = {
        firstKind: EventKind, firstSlot: int,
        thenKind: EventKind, thenSlot: int
    }

    // ------------------------------------------------------------------
    // World
    // ------------------------------------------------------------------

    /// TFired is distinct from TUnused because removing a timer that has
    /// already fired is documented as a harmless no-op, and that is worth an
    /// op; removing one that was never added is not a documented operation at
    /// all, so the model never generates it.
    type TimerSt = | TUnused | TArmed | TFired

    type DeferralSt = | DIdle | DArmed

    /// BRetiring is the state a doorbell is in between the op that asks its
    /// callback to remove it and the quiesce in which that callback runs.  It
    /// is neither present nor free: the storage is still registered, so
    /// re-adding it would open a second wakeup over the first and register
    /// the same event twice, which is a bug in the caller rather than a test
    /// of anything.
    type DoorbellSt = | BAbsent | BPresent | BRetiring

    /// A poll is registered (PIdle) or registered and being called on every
    /// pass of the loop (PSpinning).  The loop spins while there has been
    /// activity within spin_ns or while something has pinned it, and falls
    /// back to event mode otherwise; the enter and exit callbacks bracket
    /// exactly that, and are the only part of it an application can see.
    type PollSt = | PAbsent | PIdle | PSpinning

    var current: Step
    var expects: Set[Expect]
    var orders: Set[Order]

    var programStep: int
    var elapsedMs: int

    var timerSt: int -> TimerSt
    var timerKindOf: int -> TimerKind
    /// Model time at which an armed timer's FIRST firing is due.
    var timerDueAt: int -> int

    var deferralSt: int -> DeferralSt
    var deferralOwes: int -> int

    var doorbellSt: int -> DoorbellSt
    var doorbellOwes: int -> int
    /// Rung and awaiting its callback; the count is not tracked because a
    /// doorbell's obligation is "at least one", never a number.
    var doorbellRung: int -> bool

    /// Which prologue this program opens with; see `step`.
    type Shape =
        | ShapeMixed
        | ShapeTransport
        /* As ShapeTransport, but asks for send notifications before sending.
         * A separate shape rather than a coin flip inside one, so that both
         * "nothing is notified until asked" and "everything is once asked"
         * are generated rather than one crowding out the other. */
        | ShapeTransportNotify
        /* UDP: two unconnected binds sending to each other by endpoint.  A
         * shape of its own because none of listen, connect, close or finish
         * applies to it. */
        | ShapeUdp
        | ShapeTimers
        /* Opens a queue and writes a region, then reads it back in a later
         * window.  A shape for the same reason ShapeTransport is one: the
         * read-back property needs a write, a quiesce and a read in that
         * order on the same region, and a uniform walk over thirty-odd
         * enabled actions inside a twelve-op program draws that sequence
         * about as often as it draws a live connection. */
        | ShapeBlock

    var shape: Shape

    /// spin_ns as the driver configures it, in milliseconds.  The loop leaves
    /// poll mode once this much time has passed with no activity, so with
    /// windows an order of magnitude longer a poll that is not pinned always
    /// enters and exits inside the same window.
    pure val SPIN_MS = 1

    var pollSt: PollSt
    /// evpl_poll_pin is refcounted, so this is a count and not a flag.
    var pollPins: int
    /// Model time of the last activity.  evpl_create starts the spin window,
    /// so a program begins as though activity had just been reported.
    var lastActivityMs: int
    var activityPending: bool
    /// Re-adding a poll after removing one does not emit another enter
    /// callback, because evpl_remove_poll leaves the loop's poll_mode flag
    /// set; the model never generates that rather than encoding it.
    var pollEverAdded: bool

    /// Ends that have asked for send notifications, and the bytes each is
    /// owed a notification for.
    var sentNotify: int -> bool
    var pendingSent: int -> int

    /// The three loop hooks, installed or not.  Slots 0, 1 and 2 are
    /// iteration_end, pre_wait and post_wait.
    pure val HOOK_SLOTS = 0.to(2)
    var hooksInstalled: bool

    /// The transport this program runs over, and the deliveries each end is
    /// owed under it.
    var transport: TransportKind
    var pendingMsgs: int -> int

    /// A block queue is open on the program's device or it is not.
    type BlockQSt = | BQAbsent | BQOpen

    var blockQSt: int -> BlockQSt
    /// Completions this queue is owed and has not yet been given.
    var blockOwes: int -> int

    /// Settled region content: what a read issued in a later window must
    /// return.  CONTENT_UNKNOWN where the model has no claim.
    var regionContent: int -> int
    /// What this window's op leaves the region holding, applied at the
    /// quiesce that closes the window.
    var regionPending: int -> int
    /// A region already addressed in this window.  At most one data op per
    /// region per window: two would be concurrently outstanding against each
    /// other, and the API orders concurrent requests in no particular way, so
    /// whatever the second one saw would be unspecified rather than wrong.
    var regionBusy: int -> bool

    var listening: bool
    var connSt: int -> ConnSt
    /// Bytes sent to an end and not yet required to have arrived.  Indexed by
    /// end, not by connection: the two directions are independent.
    var pendingBytes: int -> int

    pure val ALL_TIMERS_UNUSED = TIMER_SLOTS.mapBy(_ => TUnused)
    pure val ALL_TIMER_KINDS = TIMER_SLOTS.mapBy(_ => TOneshot)
    pure val ALL_TIMERS_DUE_ZERO = TIMER_SLOTS.mapBy(_ => 0)
    pure val ALL_DEFERRALS_IDLE = DEFERRAL_SLOTS.mapBy(_ => DIdle)
    pure val ALL_DEFERRALS_ZERO = DEFERRAL_SLOTS.mapBy(_ => 0)
    pure val ALL_DOORBELLS_ABSENT = DOORBELL_SLOTS.mapBy(_ => BAbsent)
    pure val ALL_DOORBELLS_UNRUNG = DOORBELL_SLOTS.mapBy(_ => false)
    pure val ALL_DOORBELLS_ZERO = DOORBELL_SLOTS.mapBy(_ => 0)
    pure val ALL_QUEUES_ABSENT = BLOCK_QUEUE_SLOTS.mapBy(_ => BQAbsent)
    pure val ALL_QUEUES_ZERO = BLOCK_QUEUE_SLOTS.mapBy(_ => 0)
    pure val ALL_REGIONS_UNKNOWN = REGION_SLOTS.mapBy(_ => CONTENT_UNKNOWN)
    pure val ALL_REGIONS_IDLE = REGION_SLOTS.mapBy(_ => false)
    pure val ALL_CONNS_FREE = CONN_SLOTS.mapBy(_ => CFree)
    pure val ALL_ENDS_DRAINED = END_SLOTS.mapBy(_ => 0)
    pure val ALL_ENDS_UNNOTIFIED = END_SLOTS.mapBy(_ => false)

    // ------------------------------------------------------------------
    // The specification: what a quiesce window is owed
    // ------------------------------------------------------------------

    /// evpl_add_oneshot_timer: "fires once, delay_us from now, and is then
    /// removed automatically".  Once, not at-least-once -- and only in the
    /// window its deadline actually falls in.  A window that closes before
    /// the deadline owes nothing, which by rule 2 is the requirement that the
    /// timer did not fire early.
    ///
    /// evpl_add_timer: "fires every interval_us until evpl_remove_timer".  A
    /// count over a wall-clock window is not something the API promises, so
    /// the claim is at-least-once -- still enough to catch a periodic that
    /// stopped re-arming, which is the failure that matters.
    ///
    /// A re-armer owes two: the first firing plus the one its callback arms.
    pure def timerExpect(
        s: int, st: TimerSt, k: TimerKind, due: int, windowEnd: int
    ): Set[Expect] =
        if (st != TArmed) Set()
        else match k {
            | TPeriodic => Set({ kind: EvTimer, slot: s, mult: MAtLeast, count: 1 })
            /* `due <= windowEnd`, not `<`: the driver advances the clock a
             * millisecond at a time and a deadline landing exactly on the
             * last tick of a window is due on that tick.  With an exact clock
             * the boundary is reachable, so it has to be decided rather than
             * left to a tolerance. */
            | TOneshot =>
                if (due <= windowEnd)
                    Set({ kind: EvTimer, slot: s, mult: MExactly, count: 1 })
                else Set()
            | TRearm =>
                if (due <= windowEnd)
                    Set({ kind: EvTimer, slot: s, mult: MExactly, count: 2 })
                else Set()
        }

    /// Deferrals run on the next pass of the loop whatever the budget: the
    /// loop forces its wait to zero while any are armed, so there is no
    /// deadline to reason about.
    pure def deferralExpect(s: int, st: DeferralSt, owes: int): Set[Expect] =
        if (st != DArmed) Set()
        else Set({ kind: EvDeferral, slot: s, mult: MExactly, count: owes })

    /// Both ends of a connection learn of it, and each learns exactly once.
    /// A second CONNECTED on one bind would be an application told twice
    /// about one connection; none at all is an application that never learns
    /// its connect succeeded.
    pure def connExpect(c: int, st: ConnSt): Set[Expect] =
        match st {
            | CConnecting =>
                SIDES.map(s => { kind: EvConnected, slot: sideSlot(c, s),
                                 mult: MExactly, count: 1 })
            /* Taking one end down takes the other with it, and each end is
             * told once.  Applications free their per-connection state here,
             * so a second notification is a double free and a missing one is
             * a leak. */
            | CClosing =>
                SIDES.map(s => { kind: EvDisconnected, slot: sideSlot(c, s),
                                 mult: MExactly, count: 1 })
            | _ => Set()
        }

    /// Every byte handed to evpl_send must come out of the peer's bind, and
    /// exactly once.  The count is bytes rather than notifications: a stream
    /// may deliver them in any number of pieces, and requiring a particular
    /// number would be requiring a guarantee the API does not make.
    pure def recvExpect(e: int, bytes: int): Set[Expect] =
        if (bytes == 0) Set()
        else Set({ kind: EvRecv, slot: e, mult: MExactly, count: bytes })

    /// A datagram owes one delivery per send, no more and no fewer: coalescing
    /// two sends into one delivery, or splitting one across two, are both
    /// failures and both invisible to a byte count.
    pure def recvMsgExpect(k: TransportKind, e: int, msgs: int): Set[Expect] =
        if (not(isDatagram(k)) or msgs == 0) Set()
        else Set({ kind: EvRecvMsg, slot: e, mult: MExactly, count: msgs })

    /// Every byte an end has queued must be reported back to it, once, if it
    /// has asked to be told.  An end that never asked is owed nothing, so
    /// rule 2 turns a notification it did not ask for into a failure.
    ///
    /// Whether it asked is read at the point the queue is FLUSHED, not at the
    /// point of the send -- and since no op runs the loop, everything queued
    /// between two quiesces is flushed together, after all of them.  So the
    /// order of a send and a request inside one window does not matter, which
    /// is why this takes the flag as it stands at the end of the window
    /// rather than as it stood at each send.
    pure def sentExpect(e: int, notified: bool, bytes: int): Set[Expect] =
        if (not(notified) or bytes == 0) Set()
        else Set({ kind: EvSent, slot: e, mult: MExactly, count: bytes })

    pure def doorbellExpect(s: int, rung: bool, owes: int): Set[Expect] =
        if (not(rung)) Set()
        else if (owes == 0)
            /* Rung repeatedly: a wakeup may coalesce, so one callback
             * discharges it. */
            Set({ kind: EvDoorbell, slot: s, mult: MAtLeast, count: 1 })
        else
            /* Retires itself from the callback, so it cannot fire twice. */
            Set({ kind: EvDoorbell, slot: s, mult: MExactly, count: owes })

    /// A timer due earlier must fire before one due later.  Claimed on
    /// deadlines rather than on delay classes, because a slow timer armed
    /// early is genuinely due before a fast one armed late; and only across
    /// ORDER_GAP_MS, so the claim is about the heap ordering deadlines rather
    /// than about the scheduler's luck between two near-simultaneous ones.
    ///
    /// Periodic timers are left out: one armed long ago is due immediately in
    /// every window, so its deadline says nothing about where its first
    /// firing in THIS window lands.
    pure def orderPairs(
        exp: Set[Expect], tk: int -> TimerKind, due: int -> int
    ): Set[Order] = {
        val ordered = exp.filter(e => e.kind == EvTimer and tk.get(e.slot) != TPeriodic)
                          .map(e => e.slot)
        tuples(ordered, ordered)
            .filter(p => due.get(p._1) + ORDER_GAP_MS <= due.get(p._2))
            .map(p => {
                firstKind: EvTimer, firstSlot: p._1,
                thenKind: EvTimer, thenSlot: p._2
            })
    }

    // ------------------------------------------------------------------
    // Ops: preconditions and effects
    //
    // Preconditions are in the actions rather than filtered afterwards, so
    // the simulator only ever emits a legal program.  An illegal one is not a
    // test of anything: adding the same evpl_timer twice puts one struct in
    // the heap twice, which is a bug in the caller and not in libevpl.
    // ------------------------------------------------------------------

    action doReset(sh: Shape, k: TransportKind): bool = all {
        shape' = sh,
        current' = NOP_STEP.with("op", OpReset),
        expects' = Set(),
        orders' = Set(),
        programStep' = 0,
        elapsedMs' = 0,
        timerSt' = ALL_TIMERS_UNUSED,
        timerKindOf' = ALL_TIMER_KINDS,
        timerDueAt' = ALL_TIMERS_DUE_ZERO,
        deferralSt' = ALL_DEFERRALS_IDLE,
        deferralOwes' = ALL_DEFERRALS_ZERO,
        doorbellSt' = ALL_DOORBELLS_ABSENT,
        doorbellOwes' = ALL_DOORBELLS_ZERO,
        doorbellRung' = ALL_DOORBELLS_UNRUNG,
        blockQSt' = ALL_QUEUES_ABSENT,
        blockOwes' = ALL_QUEUES_ZERO,
        /* A fresh device every program: the driver re-creates the backing
         * file at each reset, so nothing is known about any region until this
         * program writes it. */
        regionContent' = ALL_REGIONS_UNKNOWN,
        regionPending' = ALL_REGIONS_UNKNOWN,
        regionBusy' = ALL_REGIONS_IDLE,
        listening' = false,
        connSt' = ALL_CONNS_FREE,
        pendingBytes' = ALL_ENDS_DRAINED,
        pollSt' = PAbsent,
        pollPins' = 0,
        lastActivityMs' = 0,
        activityPending' = false,
        pollEverAdded' = false,
        transport' = k,
        pendingMsgs' = ALL_ENDS_DRAINED,
        sentNotify' = ALL_ENDS_UNNOTIFIED,
        pendingSent' = ALL_ENDS_DRAINED,
        hooksInstalled' = false,
    }

    /// Fields the ops below never touch, gathered so each action states only
    /// what it changes.
    action keepTimers = all {
        timerSt' = timerSt, timerKindOf' = timerKindOf, timerDueAt' = timerDueAt,
    }

    action keepTransport = all {
        listening' = listening, connSt' = connSt, pendingBytes' = pendingBytes,
        sentNotify' = sentNotify, pendingSent' = pendingSent,
        pendingMsgs' = pendingMsgs,
    }

    action keepHooks = all {
        hooksInstalled' = hooksInstalled,
    }

    action keepPolls = all {
        pollSt' = pollSt, pollPins' = pollPins,
        lastActivityMs' = lastActivityMs, activityPending' = activityPending,
        pollEverAdded' = pollEverAdded,
    }

    action keepDeferrals = all {
        deferralSt' = deferralSt, deferralOwes' = deferralOwes,
    }

    action keepDoorbells = all {
        doorbellSt' = doorbellSt, doorbellOwes' = doorbellOwes,
        doorbellRung' = doorbellRung,
    }

    action keepBlock = all {
        blockQSt' = blockQSt, blockOwes' = blockOwes,
        regionContent' = regionContent, regionPending' = regionPending,
        regionBusy' = regionBusy,
    }

    /// Ops other than a quiesce do not run the loop, so no callback can fire
    /// during one and the clock does not move.
    ///
    /// Split from `emit` so the block ops, which are the only ones that touch
    /// the block state themselves, can reuse it without assigning those vars
    /// twice.  Every other op wants `emit`.
    action emitCore(s: Step): bool = all {
        current' = s.with("atMs", elapsedMs).with("transport", transport),
        expects' = Set(),
        orders' = Set(),
        programStep' = programStep + 1,
        elapsedMs' = elapsedMs,
        shape' = shape,
        transport' = transport,
    }

    action emit(s: Step): bool = all {
        emitCore(s),
        keepBlock,
    }

    action addTimer(s: int, k: TimerKind, d: DelayCls): bool = all {
        timerSt.get(s) != TArmed,
        k != TOneshot implies d == DFast,
        emit(NOP_STEP.with("op", OpAddTimer).with("slot", s)
                 .with("timerKind", k).with("delay", d)),
        timerSt' = timerSt.set(s, TArmed),
        timerKindOf' = timerKindOf.set(s, k),
        timerDueAt' = timerDueAt.set(s, elapsedMs + delayMs(d)),
        keepDeferrals,
        keepDoorbells,
        keepTransport,
        keepPolls,
        keepHooks,
    }

    /// Legal on an armed timer (it stops firing) and on one that has already
    /// fired (documented no-op).  Never on one that was never added.
    action removeTimer(s: int): bool = all {
        timerSt.get(s) != TUnused,
        emit(NOP_STEP.with("op", OpRemoveTimer).with("slot", s)),
        timerSt' = timerSt.set(s, TFired),
        timerKindOf' = timerKindOf,
        timerDueAt' = timerDueAt,
        keepDeferrals,
        keepDoorbells,
        keepTransport,
        keepPolls,
        keepHooks,
    }

    action defer(s: int, kind: OpKind, owes: int): bool = all {
        deferralSt.get(s) == DIdle,
        emit(NOP_STEP.with("op", kind).with("slot", s)),
        deferralSt' = deferralSt.set(s, DArmed),
        deferralOwes' = deferralOwes.set(s, owes),
        keepTimers,
        keepDoorbells,
        keepTransport,
        keepPolls,
        keepHooks,
    }

    action addDoorbell(s: int): bool = all {
        doorbellSt.get(s) == BAbsent,
        emit(NOP_STEP.with("op", OpAddDoorbell).with("slot", s)),
        doorbellSt' = doorbellSt.set(s, BPresent),
        doorbellOwes' = doorbellOwes.set(s, 0),
        doorbellRung' = doorbellRung.set(s, false),
        keepTimers,
        keepDeferrals,
        keepTransport,
        keepPolls,
        keepHooks,
    }

    action ringDoorbell(s: int, kind: OpKind): bool = all {
        doorbellSt.get(s) == BPresent,
        /* owes stays 0: however many times it is rung, one callback is a
         * legal answer. */
        doorbellOwes.get(s) == 0,
        emit(NOP_STEP.with("op", kind).with("slot", s)),
        doorbellSt' = doorbellSt,
        doorbellOwes' = doorbellOwes,
        doorbellRung' = doorbellRung.set(s, true),
        keepTimers,
        keepDeferrals,
        keepTransport,
        keepPolls,
        keepHooks,
    }

    action removeDoorbell(s: int): bool = all {
        doorbellSt.get(s) == BPresent,
        /* Retiring one with a callback still owed would make the obligation
         * unresolvable rather than testing anything: the header requires the
         * library to hold no reference once remove returns, so a callback
         * after it is a failure and a callback before it is a race. */
        not(doorbellRung.get(s)),
        emit(NOP_STEP.with("op", OpRemoveDoorbell).with("slot", s)),
        doorbellSt' = doorbellSt.set(s, BAbsent),
        doorbellOwes' = doorbellOwes,
        doorbellRung' = doorbellRung,
        keepTimers,
        keepDeferrals,
        keepTransport,
        keepPolls,
        keepHooks,
    }

    /// Ring once, and have the callback retire the doorbell.  Exactly one
    /// callback: it cannot fire again once it has removed itself, and it must
    /// not fail to fire the first time.
    ///
    /// The slot goes to BRetiring rather than straight to BAbsent: the
    /// removal happens inside the callback, which does not run until the next
    /// quiesce, so until then the storage is still registered and re-adding
    /// it would be a double registration.
    action removeDoorbellInCallback(s: int): bool = all {
        doorbellSt.get(s) == BPresent,
        not(doorbellRung.get(s)),
        emit(NOP_STEP.with("op", OpRemoveDoorbellInCallback).with("slot", s)),
        doorbellSt' = doorbellSt.set(s, BRetiring),
        doorbellOwes' = doorbellOwes.set(s, 1),
        doorbellRung' = doorbellRung.set(s, true),
        keepTimers,
        keepDeferrals,
        keepTransport,
        keepPolls,
        keepHooks,
    }

    /// Cancel an armed deferral.  Nothing is owed afterwards, so rule 2 is
    /// what checks the cancellation: a callback that arrives anyway has no
    /// expectation covering it and fails the window.
    action removeDeferral(s: int): bool = all {
        deferralSt.get(s) == DArmed,
        emit(NOP_STEP.with("op", OpRemoveDeferral).with("slot", s)),
        deferralSt' = deferralSt.set(s, DIdle),
        deferralOwes' = deferralOwes.set(s, 0),
        keepTimers,
        keepDoorbells,
        keepTransport,
        keepPolls,
        keepHooks,
    }

    /// The documented no-op: removing one that is not armed, which a caller
    /// tearing down state does without knowing whether it armed anything.
    action removeDeferralIdle(s: int): bool = all {
        deferralSt.get(s) == DIdle,
        emit(NOP_STEP.with("op", OpRemoveDeferralIdle).with("slot", s)),
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepTransport,
        keepPolls,
        keepHooks,
    }

    /// Loop hooks fire on every pass, so like a poll callback the driver logs
    /// only the first of each in a window; what is claimed is that each of
    /// the three ran, not how often.
    action setLoopHooks = all {
        not(hooksInstalled),
        emit(NOP_STEP.with("op", OpSetLoopHooks)),
        hooksInstalled' = true,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepTransport,
        keepPolls,
    }

    action clearLoopHooks = all {
        hooksInstalled,
        emit(NOP_STEP.with("op", OpClearLoopHooks)),
        hooksInstalled' = false,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepTransport,
        keepPolls,
    }

    // ------------------------------------------------------------------
    // Poll ops
    //
    // Adding a poll does not by itself put the loop into poll mode: the loop
    // spins while there has been activity within spin_ns or while something
    // has pinned it, and falls back otherwise.  So these ops are about the
    // spin window, and the enter/exit callbacks are how it is observed.
    // ------------------------------------------------------------------

    action addPoll = all {
        pollSt == PAbsent,
        /* Once only per program; see pollEverAdded. */
        not(pollEverAdded),
        emit(NOP_STEP.with("op", OpAddPoll)),
        pollSt' = PIdle,
        pollPins' = pollPins,
        lastActivityMs' = lastActivityMs,
        activityPending' = activityPending,
        pollEverAdded' = true,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepTransport,
        keepHooks,
    }

    action removePoll = all {
        pollSt != PAbsent,
        emit(NOP_STEP.with("op", OpRemovePoll)),
        pollSt' = PAbsent,
        pollPins' = pollPins,
        lastActivityMs' = lastActivityMs,
        activityPending' = activityPending,
        pollEverAdded' = pollEverAdded,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepTransport,
        keepHooks,
    }

    /// Legal with no poll registered -- it only bumps a counter -- so the
    /// model does not require one.
    action activity = all {
        emit(NOP_STEP.with("op", OpActivity)),
        pollSt' = pollSt,
        pollPins' = pollPins,
        lastActivityMs' = lastActivityMs,
        activityPending' = true,
        pollEverAdded' = pollEverAdded,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepTransport,
        keepHooks,
    }

    action pollPin = all {
        /* Bounded so the state space stays finite; the point is that it
         * counts rather than how high it counts. */
        pollPins < 2,
        emit(NOP_STEP.with("op", OpPollPin)),
        pollSt' = pollSt,
        pollPins' = pollPins + 1,
        lastActivityMs' = lastActivityMs,
        activityPending' = activityPending,
        pollEverAdded' = pollEverAdded,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepTransport,
        keepHooks,
    }

    action pollUnpin = all {
        pollPins > 0,
        emit(NOP_STEP.with("op", OpPollUnpin)),
        pollSt' = pollSt,
        pollPins' = pollPins - 1,
        lastActivityMs' = lastActivityMs,
        activityPending' = activityPending,
        pollEverAdded' = pollEverAdded,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepTransport,
        keepHooks,
    }

    // ------------------------------------------------------------------
    // Transport ops
    //
    // Everything here is over the in-process transport.  It is addressed by a
    // name private to the process and needs no kernel transport at all, which
    // is what makes a whole connection lifecycle -- both ends of it --
    // reachable from a single evpl and a single thread, with no port to
    // collide on and nothing left behind by a crash.
    // ------------------------------------------------------------------

    action listen = all {
        not(listening),
        isConnected(transport),
        emit(NOP_STEP.with("op", OpListen)),
        listening' = true,
        connSt' = connSt,
        pendingBytes' = pendingBytes,
        sentNotify' = sentNotify,
        pendingSent' = pendingSent,
        pendingMsgs' = pendingMsgs,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepHooks,
        keepPolls,
    }

    /// Only with no connection outstanding.  Whether tearing down a listener
    /// takes the connections it accepted with it is a real question, but it is
    /// one the headers do not answer, and a model may not invent an answer it
    /// would then report libevpl for failing.
    action stopListen = all {
        listening,
        CONN_SLOTS.forall(c => connSt.get(c) == CFree),
        emit(NOP_STEP.with("op", OpStopListen)),
        listening' = false,
        connSt' = connSt,
        pendingBytes' = pendingBytes,
        sentNotify' = sentNotify,
        pendingSent' = pendingSent,
        pendingMsgs' = pendingMsgs,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepHooks,
        keepPolls,
    }

    /// Both ends of an unconnected pair, in one step.  There is no handshake
    /// to wait for and nothing to notify, so the connection is up as soon as
    /// the op returns -- which is why it owes nothing at the next quiesce
    /// while connect owes two CONNECTED.
    action bindPair(c: int): bool = all {
        not(isConnected(transport)),
        connSt.get(c) == CFree,
        emit(NOP_STEP.with("op", OpBindPair).with("conn", c)),
        connSt' = connSt.set(c, CUp),
        listening' = listening,
        pendingBytes' = pendingBytes,
        sentNotify' = sentNotify,
        pendingSent' = pendingSent,
        pendingMsgs' = pendingMsgs,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepPolls,
        keepHooks,
    }

    /// At most one connect may be in flight at a time.  Not a property of
    /// libevpl -- it accepts as many as are offered -- but of the harness: the
    /// accept callback hands the driver a bind with nothing on it that says
    /// which connect it answers, so two in flight at once could be attributed
    /// the wrong way round and the model would be checking the wrong end.
    action connect(c: int, d: DrainMode): bool = all {
        listening,
        isConnected(transport),
        connSt.get(c) == CFree,
        CONN_SLOTS.forall(o => connSt.get(o) != CConnecting),
        emit(NOP_STEP.with("op", OpConnect).with("conn", c).with("drain", d)),
        connSt' = connSt.set(c, CConnecting),
        listening' = listening,
        pendingBytes' = pendingBytes,
        sentNotify' = sentNotify,
        pendingSent' = pendingSent,
        pendingMsgs' = pendingMsgs,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepHooks,
        keepPolls,
    }

    /// Ask to be told what this end sends.  Sends made before it are not
    /// notified; sends after it are.
    action requestSendNotify(c: int, side: int): bool = all {
        isConnected(transport),
        connSt.get(c) == CUp,
        not(sentNotify.get(sideSlot(c, side))),
        emit(NOP_STEP.with("op", OpRequestSendNotify).with("conn", c)
                 .with("side", side)),
        sentNotify' = sentNotify.set(sideSlot(c, side), true),
        pendingSent' = pendingSent,
        pendingMsgs' = pendingMsgs,
        connSt' = connSt,
        listening' = listening,
        pendingBytes' = pendingBytes,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepPolls,
        keepHooks,
    }

    action send(c: int, side: int, sz: SizeCls, mode: SendMode): bool = all {
        connSt.get(c) == CUp,
        /* Both of these are limited to one buffer's worth, and the driver
         * configures a buffer smaller than the largest payload class.
         *
         * For SendGlobal that is by definition -- a global iovec IS one
         * buffer.  For SendReserveCommit it is a limitation of
         * evpl_iovec_reserve, which discards a buffer that cannot hold the
         * whole remaining length and asks for another; when a fresh buffer
         * cannot either, it does that forever.  Asking for more than one
         * buffer's worth is an infinite loop rather than a short return, and
         * nothing in evpl_memory.h says so. */
        (mode == SendGlobal or mode == SendReserveCommit) implies sz != SzLarge,
        /* A datagram is one message and the transport caps one at
         * max_datagram_size; the driver leaves that at its default, which the
         * largest payload class exceeds. */
        isDatagram(transport) implies sz != SzLarge,
        /* An unconnected bind has no peer to send to, so it must name one;
         * a connected one has no endpoint the model tracks, and the
         * endpoint-addressed calls leak on every transport that does not
         * release the address they hand over -- which today is all of them
         * bar UDP.  So the two forms are exactly complementary. */
        isConnected(transport) implies
            (mode != SendToEp and mode != SendToEpV),
        not(isConnected(transport)) implies
            (mode == SendToEp or mode == SendToEpV),
        emit(NOP_STEP.with("op", OpSend).with("conn", c).with("side", side)
                 .with("size", sz).with("send", mode)),
        pendingBytes' = pendingBytes.set(sideSlot(c, peer(side)),
                                         pendingBytes.get(sideSlot(c, peer(side)))
                                             + sizeBytes(sz)),
        sentNotify' = sentNotify,
        /* Queued, whether or not this end has asked yet; see sentExpect. */
        pendingSent' = pendingSent.set(sideSlot(c, side),
                                       pendingSent.get(sideSlot(c, side))
                                           + sizeBytes(sz)),
        pendingMsgs' = pendingMsgs.set(sideSlot(c, peer(side)),
                                       pendingMsgs.get(sideSlot(c, peer(side))) + 1),
        connSt' = connSt,
        listening' = listening,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepHooks,
        keepPolls,
    }

    /// close() is only generated with both directions quiet; see OpClose.
    action close(c: int, side: int): bool = all {
        isConnected(transport),
        connSt.get(c) == CUp,
        SIDES.forall(s => pendingBytes.get(sideSlot(c, s)) == 0),
        SIDES.forall(s => not(sentNotify.get(sideSlot(c, s))) or
                          pendingSent.get(sideSlot(c, s)) == 0),
        emit(NOP_STEP.with("op", OpClose).with("conn", c).with("side", side)),
        connSt' = connSt.set(c, CClosing),
        listening' = listening,
        pendingBytes' = pendingBytes,
        sentNotify' = sentNotify,
        pendingSent' = pendingSent,
        pendingMsgs' = pendingMsgs,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepHooks,
        keepPolls,
    }

    /// finish() leaves whatever THIS side queued owed: the peer must still
    /// receive every byte handed over before it, and only then see the
    /// disconnect.  This is the op that catches a transport dropping its send
    /// ring on the way out.
    ///
    /// The other direction gets no such promise, and the precondition below is
    /// what keeps the model honest about that.  evpl_finish is not a
    /// half-close: it closes the bind outright once the send ring drains, so
    /// bytes a peer had already put in flight TOWARD this side are lost with
    /// it.  Requiring their delivery would be requiring a shutdown(SHUT_WR)
    /// that this API does not offer.
    action finish(c: int, side: int): bool = all {
        isConnected(transport),
        connSt.get(c) == CUp,
        pendingBytes.get(sideSlot(c, side)) == 0,
        /* Whether a send notification survives the close that follows it is a
         * real question and not one the headers answer, so the model declines
         * to have an opinion: an end that has asked to be told must have
         * nothing queued.  An end that has not asked is free to send and
         * finish in one breath, which is what evpl_finish is for. */
        SIDES.forall(s => not(sentNotify.get(sideSlot(c, s))) or
                          pendingSent.get(sideSlot(c, s)) == 0),
        emit(NOP_STEP.with("op", OpFinish).with("conn", c).with("side", side)),
        connSt' = connSt.set(c, CClosing),
        listening' = listening,
        pendingBytes' = pendingBytes,
        sentNotify' = sentNotify,
        pendingSent' = pendingSent,
        pendingMsgs' = pendingMsgs,
        keepTimers,
        keepDeferrals,
        keepDoorbells,
        keepHooks,
        keepPolls,
    }

    // ------------------------------------------------------------------
    // Block I/O (evpl_block.h)
    //
    // The device belongs to the program rather than to any op: the driver
    // creates a fresh one at each reset and tears it down at the end, so what
    // varies here is the queues opened on it and the requests put through
    // them.
    //
    // Two things are claimed.  One is the completion: every request owes
    // exactly one callback, in the window it was submitted in -- an
    // asynchronous API's only universal promise, and the one whose breach
    // presents as a hang rather than as a wrong answer.  The other is the
    // data: a region written in one window must read back as what was written
    // when a later window reads it.  Both are properties of the API and not
    // of any backend, which is why they live here rather than in a backend's
    // own test.
    // ------------------------------------------------------------------

    action keepRegions = all {
        regionContent' = regionContent, regionPending' = regionPending,
        regionBusy' = regionBusy,
    }

    action keepOthers = all {
        keepTimers, keepDeferrals, keepDoorbells, keepTransport, keepPolls,
        keepHooks,
    }

    action openQueue(q: int): bool = all {
        blockQSt.get(q) == BQAbsent,
        emitCore(NOP_STEP.with("op", OpOpenQueue).with("queue", q)),
        blockQSt' = blockQSt.set(q, BQOpen),
        blockOwes' = blockOwes.set(q, 0),
        keepRegions,
        keepOthers,
    }

    /// Only ever with nothing outstanding.  A request in flight still names
    /// the queue it was submitted on, so closing under one is a use-after-free
    /// waiting to happen rather than a case to test -- the contract is that
    /// the caller waits for its callbacks, and the model keeps to it.
    action closeQueue(q: int): bool = all {
        blockQSt.get(q) == BQOpen,
        blockOwes.get(q) == 0,
        emitCore(NOP_STEP.with("op", OpCloseQueue).with("queue", q)),
        blockQSt' = blockQSt.set(q, BQAbsent),
        blockOwes' = blockOwes,
        keepRegions,
        keepOthers,
    }

    /// What every request has in common: an open queue, and one more
    /// completion owed on it.
    action submit(q: int, s: Step): bool = all {
        blockQSt.get(q) == BQOpen,
        emitCore(s.with("queue", q)),
        blockQSt' = blockQSt,
        blockOwes' = blockOwes.set(q, blockOwes.get(q) + 1),
    }

    /// The byte a write fills its region with, keyed to where in the program
    /// it happens so that two writes in one program are distinguishable and a
    /// read that came back with the wrong one is caught as such rather than
    /// merely as "not zeros".
    pure def writePattern(st: int): int = 1 + st

    action blockWrite(q: int, r: int, sc: SegCls, kind: OpKind): bool = all {
        not(regionBusy.get(r)),
        submit(q, NOP_STEP.with("op", kind).with("region", r).with("segs", sc)
                   .with("pattern", writePattern(programStep))),
        regionContent' = regionContent,
        regionPending' = regionPending.set(r, writePattern(programStep)),
        regionBusy' = regionBusy.set(r, true),
        keepOthers,
    }

    /// Carries what the region is known to hold, or CONTENT_UNKNOWN where
    /// nothing is known -- a region never written, or one a discard has since
    /// been allowed to drop.  The driver checks the bytes only in the first
    /// case; in the second the completion is still owed and still checked.
    action blockRead(q: int, r: int, sc: SegCls): bool = all {
        not(regionBusy.get(r)),
        submit(q, NOP_STEP.with("op", OpBlockRead).with("region", r)
                   .with("segs", sc).with("pattern", regionContent.get(r))),
        regionContent' = regionContent,
        regionPending' = regionPending.set(r, regionContent.get(r)),
        regionBusy' = regionBusy.set(r, true),
        keepOthers,
    }

    /// A data guarantee, unlike discard: the header promises the range reads
    /// back as zeros, so the model claims it and a later read checks it.
    action blockWriteZeroes(q: int, r: int): bool = all {
        not(regionBusy.get(r)),
        submit(q, NOP_STEP.with("op", OpBlockWriteZeroes).with("region", r)
                   .with("pattern", CONTENT_ZERO)),
        regionContent' = regionContent,
        regionPending' = regionPending.set(r, CONTENT_ZERO),
        regionBusy' = regionBusy.set(r, true),
        keepOthers,
    }

    /// Zero the whole device.  Every region must be idle for the same reason
    /// one has to be for a single-region op, and every region is left holding
    /// zeros.
    action blockWriteZeroesAll(q: int): bool = all {
        REGION_SLOTS.forall(r => not(regionBusy.get(r))),
        submit(q, NOP_STEP.with("op", OpBlockWriteZeroesAll)
                   .with("pattern", CONTENT_ZERO)),
        regionContent' = regionContent,
        regionPending' = REGION_SLOTS.mapBy(_ => CONTENT_ZERO),
        regionBusy' = REGION_SLOTS.mapBy(_ => true),
        keepOthers,
    }

    /// Advisory.  The completion is owed like any other, but afterwards the
    /// model stops claiming to know what the region holds: the header says
    /// the data read back is unspecified, and asserting either outcome would
    /// be inventing a promise it explicitly declines to make.
    action blockDiscard(q: int, r: int): bool = all {
        not(regionBusy.get(r)),
        submit(q, NOP_STEP.with("op", OpBlockDiscard).with("region", r)),
        regionContent' = regionContent,
        regionPending' = regionPending.set(r, CONTENT_UNKNOWN),
        regionBusy' = regionBusy.set(r, true),
        keepOthers,
    }

    /// Addresses no region, so it makes no claim about content -- only that
    /// it completes.
    action blockFlush(q: int): bool = all {
        submit(q, NOP_STEP.with("op", OpBlockFlush)),
        keepRegions,
        keepOthers,
    }

    /// Run the loop to the end of this window and collect what fell out.  The
    /// obligations are computed here, at the point where they are checked,
    /// and travel in the trace: the C driver consumes the trace, not the
    /// model, so the prediction has to be in it.
    action quiesce(b: Budget): bool = {
        val windowEnd = elapsedMs + budgetMs(b)

        /* Poll mode over this window, mirroring the loop.  The spin window is
         * an order of magnitude shorter than the shortest window, so a poll
         * that is not pinned always both enters and leaves inside one --
         * there is no case where the model has to guess which window a
         * transition lands in.
         *
         * `elapsedMs <= lastActivityMs` is the loop's own test written out:
         * the first tick of the window is at elapsedMs + 1, and it stays in
         * poll mode while that is no more than SPIN_MS past the last
         * activity.  It is true at the start of a program because
         * evpl_create starts the spin window, and false thereafter unless
         * something reported activity. */
        val pollPresent = pollSt != PAbsent
        val pollSpinning = pollSt == PSpinning
        val pollEnters = pollPresent and not(pollSpinning) and
            (pollPins > 0 or activityPending or elapsedMs <= lastActivityMs)
        val pollActive = pollPresent and (pollSpinning or pollEnters)
        val pollExits = pollActive and pollPins == 0

        val pollExpects =
            (if (pollEnters) Set({ kind: EvPollEnter, slot: 0, mult: MExactly, count: 1 }) else Set())
                .union(if (pollActive) Set({ kind: EvPoll, slot: 0, mult: MExactly, count: 1 }) else Set())
                .union(if (pollExits) Set({ kind: EvPollExit, slot: 0, mult: MExactly, count: 1 }) else Set())

        val exp =
            TIMER_SLOTS.map(s => timerExpect(s, timerSt.get(s), timerKindOf.get(s),
                                             timerDueAt.get(s), windowEnd)).flatten()
                .union(DEFERRAL_SLOTS.map(s =>
                    deferralExpect(s, deferralSt.get(s), deferralOwes.get(s))).flatten())
                .union(DOORBELL_SLOTS.map(s =>
                    doorbellExpect(s, doorbellRung.get(s), doorbellOwes.get(s))).flatten())
                .union(CONN_SLOTS.map(c => connExpect(c, connSt.get(c))).flatten())
                .union(END_SLOTS.map(e => recvExpect(e, pendingBytes.get(e))).flatten())
                .union(END_SLOTS.map(e =>
                    recvMsgExpect(transport, e, pendingMsgs.get(e))).flatten())
                .union(END_SLOTS.map(e =>
                    sentExpect(e, sentNotify.get(e), pendingSent.get(e))).flatten())
                .union(BLOCK_QUEUE_SLOTS.map(q =>
                    blockExpect(q, blockOwes.get(q))).flatten())
                .union(pollExpects)
                .union(if (hooksInstalled)
                           HOOK_SLOTS.map(h => { kind: EvHook, slot: h,
                                                 mult: MExactly, count: 1 })
                       else Set())

        /* A doorbell whose callback retires it is absent once that callback
         * has run, which is inside this window. */
        val dbSt = DOORBELL_SLOTS.mapBy(s =>
            if (doorbellSt.get(s) == BRetiring) BAbsent else doorbellSt.get(s))

        all {
            current' = NOP_STEP.with("op", OpQuiesce).with("budget", b)
                           .with("atMs", windowEnd),
            expects' = exp,
            orders' = orderPairs(exp, timerKindOf, timerDueAt),
            programStep' = programStep + 1,
            elapsedMs' = windowEnd,
            shape' = shape,

            /* A one-shot whose deadline was in this window has fired and is
             * gone; a periodic stays armed; one whose deadline is still ahead
             * is untouched and still owes its callback to a later window. */
            timerSt' = TIMER_SLOTS.mapBy(s =>
                if (timerSt.get(s) == TArmed and timerKindOf.get(s) != TPeriodic
                    and timerDueAt.get(s) <= windowEnd) TFired
                else timerSt.get(s)),
            timerKindOf' = timerKindOf,
            timerDueAt' = timerDueAt,

            deferralSt' = ALL_DEFERRALS_IDLE,
            deferralOwes' = ALL_DEFERRALS_ZERO,

            /* Every request submitted in this window has completed by the end
             * of it, so the queues owe nothing going into the next.  A region
             * this window wrote now holds what was written -- that is the
             * point at which the claim becomes checkable, since only a
             * completed write has a defined result. */
            blockQSt' = blockQSt,
            blockOwes' = ALL_QUEUES_ZERO,
            regionContent' = REGION_SLOTS.mapBy(r =>
                if (regionBusy.get(r)) regionPending.get(r)
                else regionContent.get(r)),
            regionPending' = ALL_REGIONS_UNKNOWN,
            regionBusy' = ALL_REGIONS_IDLE,

            doorbellSt' = dbSt,
            doorbellOwes' = ALL_DOORBELLS_ZERO,
            doorbellRung' = ALL_DOORBELLS_UNRUNG,

            /* A connection is established or gone by the end of the window in
             * which its notifications were due; a slot whose connection has
             * gone is free to carry another. */
            listening' = listening,
            connSt' = CONN_SLOTS.mapBy(c =>
                match connSt.get(c) {
                    | CConnecting => CUp
                    | CClosing => CFree
                    | _ => connSt.get(c)
                }),
            pendingBytes' = ALL_ENDS_DRAINED,
            pendingMsgs' = ALL_ENDS_DRAINED,
            transport' = transport,
            sentNotify' = sentNotify,
            pendingSent' = ALL_ENDS_DRAINED,
            hooksInstalled' = hooksInstalled,

            pollSt' = if (not(pollPresent)) PAbsent
                      else if (pollActive and pollPins > 0) PSpinning
                      else PIdle,
            pollPins' = pollPins,
            /* The loop observes a reported activity on the window's first
             * tick, and dates the spin window from there -- but ONLY while a
             * poll is registered.  With none, evpl_continue skips the block
             * that syncs its activity counter, so an activity reported before
             * any poll existed is still pending whenever one is added, however
             * long afterwards, and brings the loop straight into poll mode.
             * Modelled rather than fixed: it is defensible ("something asked
             * to spin, and now there is something to spin on"), and quietly
             * dropping it would be a behaviour change on the frameworks that
             * report activity. */
            lastActivityMs' = if (pollPresent and activityPending) elapsedMs + 1
                              else lastActivityMs,
            activityPending' = if (pollPresent) false else activityPending,
            pollEverAdded' = pollEverAdded,
        }
    }

    // ------------------------------------------------------------------
    // Program generation
    // ------------------------------------------------------------------

    action pickOp = {
        nondet ts = TIMER_SLOTS.oneOf()
        nondet tk = Set(TOneshot, TPeriodic, TRearm).oneOf()
        nondet td = Set(DFast, DSlow).oneOf()
        nondet ds = DEFERRAL_SLOTS.oneOf()
        nondet bs = DOORBELL_SLOTS.oneOf()
        nondet b = Set(QShort, QLong).oneOf()
        nondet cs = CONN_SLOTS.oneOf()
        nondet sd = SIDES.oneOf()
        nondet sz = Set(SzTiny, SzSmall, SzMedium, SzLarge).oneOf()
        nondet dm = Set(DrainRecv, DrainRecvV, DrainPeek, DrainPeekV).oneOf()
        /* SendToEp and SendToEpV are deliberately not generated; see
         * SendMode.  They are declared because the model should say what the
         * API offers, and excluded because exercising them leaks. */
        nondet sm = Set(SendBuf, SendV, SendVTakeRef, SendReserveCommit,
                        SendGlobal).oneOf()
        nondet bq = BLOCK_QUEUE_SLOTS.oneOf()
        nondet br = REGION_SLOTS.oneOf()
        nondet bg = Set(BSeg1, BSeg4, BSeg16).oneOf()
        any {
            addTimer(ts, tk, td),
            removeTimer(ts),
            defer(ds, OpDefer, 1),
            defer(ds, OpDeferTwice, 1),
            defer(ds, OpDeferReentrant, 2),
            addDoorbell(bs),
            ringDoorbell(bs, OpRingDoorbell),
            ringDoorbell(bs, OpRingDoorbellTwice),
            removeDoorbell(bs),
            removeDoorbellInCallback(bs),
            bindPair(cs),
            send(cs, sd, sz, SendToEp),
            send(cs, sd, sz, SendToEpV),
            requestSendNotify(cs, sd),
            setLoopHooks,
            clearLoopHooks,
            removeDeferral(ds),
            removeDeferralIdle(ds),
            addPoll,
            removePoll,
            activity,
            pollPin,
            pollUnpin,
            listen,
            stopListen,
            connect(cs, dm),
            send(cs, sd, sz, sm),
            close(cs, sd),
            finish(cs, sd),
            openQueue(bq),
            closeQueue(bq),
            blockRead(bq, br, bg),
            blockWrite(bq, br, bg, OpBlockWrite),
            blockWrite(bq, br, bg, OpBlockWriteSync),
            blockWriteZeroes(bq, br),
            blockWriteZeroesAll(bq),
            blockDiscard(bq, br),
            blockFlush(bq),
            quiesce(b),
        }
    }

    /// Any legal send on the prologue's connection.
    action sendAny = {
        nondet sz = Set(SzTiny, SzSmall, SzMedium, SzLarge).oneOf()
        nondet sd = SIDES.oneOf()
        nondet sm = Set(SendBuf, SendV, SendVTakeRef, SendReserveCommit,
                        SendGlobal).oneOf()
        send(0, sd, sz, sm)
    }

    /// The UDP form: addressed by endpoint, because there is no connection.
    action sendAnyEp = {
        nondet sz = Set(SzTiny, SzSmall, SzMedium).oneOf()
        nondet sd = SIDES.oneOf()
        nondet sm = Set(SendToEp, SendToEpV).oneOf()
        send(0, sd, sz, sm)
    }

    action requestSendNotifyAny = {
        nondet sd = SIDES.oneOf()
        requestSendNotify(0, sd)
    }

    action connectAny = {
        nondet d = Set(DrainRecv, DrainRecvV, DrainPeek, DrainPeekV).oneOf()
        connect(0, d)
    }

    /// Fill region 0 on the prologue's queue, scattered any way the model
    /// allows -- including across more segments than a backend is likely to
    /// keep inline.
    action blockWriteAny = {
        nondet g = Set(BSeg1, BSeg4, BSeg16).oneOf()
        nondet k = Set(OpBlockWrite, OpBlockWriteSync).oneOf()
        blockWrite(0, 0, g, k)
    }

    /// And read it back.  The gather on the way out and the scatter on the
    /// way in are chosen independently, since a backend has no business
    /// requiring them to match.
    action blockReadAny = {
        nondet g = Set(BSeg1, BSeg4, BSeg16).oneOf()
        blockRead(0, 0, g)
    }

    action resetUdp = doReset(ShapeUdp, TDatagramUdp)

    action resetAny = {
        nondet sh = Set(ShapeMixed, ShapeTransport, ShapeTransportNotify,
                        ShapeTimers, ShapeBlock).oneOf()
        nondet k = Set(TStreamInproc, TDatagramInproc, TStreamTcp,
                       TStreamUnix).oneOf()
        doReset(if (sh == ShapeUdp) ShapeMixed else sh, k)
    }

    /// Arm one timer, any kind and delay the model allows.
    action addTimerAny(s: int): bool = {
        nondet k = Set(TOneshot, TPeriodic, TRearm).oneOf()
        nondet d = Set(DFast, DSlow).oneOf()
        addTimer(s, k, d)
    }

    /// Deterministic on purpose, where `step`'s resets are not: quint samples
    /// a nondeterministic init on every scenario test, which turns each of
    /// the runs below into ten thousand and the model's own test suite from a
    /// tenth of a second into eleven.  Generation loses nothing by it -- only
    /// the very first program of a trace is pinned, and every reset after it
    /// still chooses.
    action init = doReset(ShapeMixed, TStreamInproc)

    /*
     * Program shape.
     *
     * Half the programs open with a three-op prologue that leaves a live
     * connection, because a uniform random walk over the op set almost never
     * builds one: send, close and finish all need a connection that is up,
     * which takes listen, connect and a quiesce to reach, and the odds of
     * drawing that sequence out of seventeen enabled actions inside a
     * twelve-op program are negligible.  The converter's op-coverage check
     * fails generation outright when that happens, which is how this was
     * found -- but the fix belongs here, in what the model generates, rather
     * than in ever-longer traces.
     *
     * A third opens by arming three timers, for the same reason in the other
     * direction: the timer set is a binary heap, and its sift-down only runs
     * once the heap is deeper than a pair.  A uniform walk over twenty-five
     * enabled actions arms three timers at once about as often as it builds a
     * connection, which is to say almost never -- and unlike a missing op,
     * a heap that never sifts does not fail generation, it just quietly stops
     * being tested.  This is what the coverage report is for.
     *
     * The rest exercise the event-loop primitives with neither in the way, and
     * can still reach any of it on their own.
     *
     * Every program ends with a long quiesce, so that none leaves an
     * obligation for the next to inherit and every teardown runs from a
     * settled loop.
     */
    /// The closing quiesce is only as long as it needs to be.  Every program
    /// has one, so making it unconditionally long would put the suite's
    /// wall-clock floor at one long window per program for the sake of the
    /// minority that have a slow timer still outstanding.
    action finalQuiesce =
        if (TIMER_SLOTS.exists(s => timerSt.get(s) == TArmed and
                                    timerDueAt.get(s) >= elapsedMs + budgetMs(QShort)))
            quiesce(QLong)
        else quiesce(QShort)

    val isTransportShape = shape == ShapeTransport or shape == ShapeTransportNotify

    action step =
        if (programStep >= PROGRAM_LEN) any { resetAny, resetUdp }
        else if (programStep == PROGRAM_LEN - 1) finalQuiesce
        else if (isTransportShape and programStep == 0) listen
        else if (isTransportShape and programStep == 1) connectAny
        else if (isTransportShape and programStep == 2) quiesce(QShort)
        else if (shape == ShapeTransportNotify and programStep == 3)
            requestSendNotifyAny
        else if (shape == ShapeTransportNotify and programStep == 4) sendAny
        else if (shape == ShapeTransportNotify and programStep == 5) quiesce(QShort)
        else if (shape == ShapeTransport and programStep == 3) sendAny
        else if (shape == ShapeTransport and programStep == 4) quiesce(QShort)
        else if (shape == ShapeUdp and programStep == 0) bindPair(0)
        else if (shape == ShapeUdp and programStep == 1) sendAnyEp
        else if (shape == ShapeUdp and programStep == 2) quiesce(QShort)
        else if (shape == ShapeTimers and programStep < 3) addTimerAny(programStep)
        else if (shape == ShapeBlock and programStep == 0) openQueue(0)
        else if (shape == ShapeBlock and programStep == 1) blockWriteAny
        else if (shape == ShapeBlock and programStep == 2) quiesce(QShort)
        else if (shape == ShapeBlock and programStep == 3) blockReadAny
        else if (shape == ShapeBlock and programStep == 4) quiesce(QShort)
        else pickOp

    // ------------------------------------------------------------------
    // Invariants
    // ------------------------------------------------------------------

    /// Totality: every op the model can emit needs an arm in the converter
    /// and in the C driver.  Quint's match is exhaustive, so a new OpKind
    /// without a rule fails to typecheck; this catches the reverse mistake.
    val opIsKnown = match current.op {
        | OpReset => true
        | OpAddTimer => true
        | OpRemoveTimer => true
        | OpDefer => true
        | OpDeferTwice => true
        | OpDeferReentrant => true
        | OpAddDoorbell => true
        | OpRingDoorbell => true
        | OpRingDoorbellTwice => true
        | OpRemoveDoorbell => true
        | OpRemoveDoorbellInCallback => true
        | OpRemoveDeferral => true
        | OpRemoveDeferralIdle => true
        | OpAddPoll => true
        | OpRemovePoll => true
        | OpActivity => true
        | OpPollPin => true
        | OpPollUnpin => true
        | OpRequestSendNotify => true
        | OpSetLoopHooks => true
        | OpClearLoopHooks => true
        | OpListen => true
        | OpStopListen => true
        | OpBindPair => true
        | OpConnect => true
        | OpSend => true
        | OpClose => true
        | OpFinish => true
        | OpOpenQueue => true
        | OpCloseQueue => true
        | OpBlockRead => true
        | OpBlockWrite => true
        | OpBlockWriteSync => true
        | OpBlockFlush => true
        | OpBlockWriteZeroes => true
        | OpBlockWriteZeroesAll => true
        | OpBlockDiscard => true
        | OpQuiesce => true
    }

    /// Obligations are only ever attached to the op that checks them; a
    /// non-quiesce step carrying an expectation would be one the driver
    /// silently drops.
    val expectationsOnlyAtQuiesce =
        (expects.size() > 0 or orders.size() > 0) implies current.op == OpQuiesce

    /// A closed claim of zero callbacks is not a claim -- rule 2 already
    /// requires that anything unexpected fails -- and would let a bug through
    /// as a satisfied expectation.
    val expectationsAreSubstantive =
        expects.forall(e => e.count >= 1)

    /// An order pair may only mention events the same quiesce expects;
    /// otherwise the driver would be asked to order something that never
    /// happened.
    val ordersReferenceExpectedEvents =
        orders.forall(o =>
            expects.exists(e => e.kind == o.firstKind and e.slot == o.firstSlot) and
            expects.exists(e => e.kind == o.thenKind and e.slot == o.thenSlot))

    /// The clock only advances inside a quiesce, and every quiesce carries the
    /// absolute deadline the driver runs it to.  A step that moved the clock
    /// without the driver knowing would put model and real time out of step
    /// for the rest of the program.
    val clockIsCarried =
        current.atMs == elapsedMs

    /// A repeating timer is always fast; see TimerKind.
    val repeatingTimersAreFast =
        TIMER_SLOTS.forall(s =>
            (timerSt.get(s) == TArmed and timerKindOf.get(s) != TOneshot)
                implies timerDueAt.get(s) <= elapsedMs + delayMs(DFast))

    /// Bytes are only ever in flight to an end of a connection that exists.
    /// Owing a payload to a bind that was never created, or has already gone,
    /// would be an obligation the driver has nowhere to check.
    val bytesOnlyFlowOnLiveConnections =
        CONN_SLOTS.forall(c =>
            (connSt.get(c) == CFree or connSt.get(c) == CConnecting) implies
                SIDES.forall(s => pendingBytes.get(sideSlot(c, s)) == 0))

    /// Only one connect outstanding; see the connect action.
    val atMostOneConnectInFlight =
        CONN_SLOTS.filter(c => connSt.get(c) == CConnecting).size() <= 1

    /// On a connected transport, a connection can only exist where something
    /// is listening for it.  It may outlive the listener in principle, but the
    /// model never generates that, so an established connection with no
    /// listener would mean stopListen's precondition had leaked.
    ///
    /// An unconnected pair has no listener by construction, which is the whole
    /// difference between the two lifecycles.
    val connectionsImplyAListener =
        not(isConnected(transport)) or
        CONN_SLOTS.forall(c => connSt.get(c) == CFree) or listening

    val safety =
        opIsKnown and expectationsOnlyAtQuiesce and expectationsAreSubstantive and
        ordersReferenceExpectedEvents and clockIsCarried and
        repeatingTimersAreFast and bytesOnlyFlowOnLiveConnections and
        atMostOneConnectInFlight and connectionsImplyAListener

    // ------------------------------------------------------------------
    // Scenario tests: the obligations most likely to be got wrong
    // ------------------------------------------------------------------

    /// The property timer_oneshot.c checks by hand, stated as a model: a
    /// one-shot owes exactly one callback, and the quiesce after it owes
    /// none -- so a refiring one-shot fails on the second quiesce, where
    /// nothing expects it.
    run oneshotFiresOnceTest =
        init
            .then(addTimer(0, TOneshot, DFast))
            .then(quiesce(QShort))
            .expect(expects == Set({ kind: EvTimer, slot: 0, mult: MExactly, count: 1 }))
            .then(quiesce(QShort))
            .expect(expects == Set())

    /// A re-armer owes two, and the loop popping it before the callback is
    /// the only reason the second arming is legal.
    run rearmedOneshotFiresTwiceTest =
        init
            .then(addTimer(1, TRearm, DFast))
            .then(quiesce(QShort))
            .expect(expects == Set({ kind: EvTimer, slot: 1, mult: MExactly, count: 2 }))

    /// A timer must not fire early -- and "early" is measured from when it was
    /// armed, not from when the window opened.  A 50ms deadline is not due
    /// inside any of the first four 10ms windows; it is due on the last tick
    /// of the fifth.  A model that compared the delay against one budget at a
    /// time would wrongly forbid the firing forever.
    run slowTimerFiresInTheWindowItIsDueTest =
        init
            .then(addTimer(0, TOneshot, DSlow))
            .then(quiesce(QShort))
            .expect(expects == Set())
            .then(quiesce(QShort))
            .expect(expects == Set())
            .then(quiesce(QShort))
            .expect(expects == Set())
            .then(quiesce(QShort))
            .expect(expects == Set())
            .then(quiesce(QShort))
            .expect(expects == Set({ kind: EvTimer, slot: 0, mult: MExactly, count: 1 }))
            .then(quiesce(QShort))
            .expect(expects == Set())

    /// The same timer under one long window is due inside it.
    run slowTimerFiresUnderALongWindowTest =
        init
            .then(addTimer(0, TOneshot, DSlow))
            .then(quiesce(QLong))
            .expect(expects == Set({ kind: EvTimer, slot: 0, mult: MExactly, count: 1 }))

    /// Removing an armed timer retires the obligation with it; removing it
    /// again afterwards is the documented no-op.
    run removedTimerStopsFiringTest =
        init
            .then(addTimer(0, TPeriodic, DFast))
            .then(quiesce(QShort))
            .expect(expects == Set({ kind: EvTimer, slot: 0, mult: MAtLeast, count: 1 }))
            .then(removeTimer(0))
            .then(quiesce(QShort))
            .expect(expects == Set())
            .then(removeTimer(0))
            .then(quiesce(QShort))
            .expect(expects == Set())

    /// The heap has to order two deadlines, and the only way to observe that
    /// is a pair far enough apart to be sure.
    run timerOrderFollowsDeadlineTest =
        init
            .then(addTimer(0, TOneshot, DSlow))
            .then(addTimer(1, TOneshot, DFast))
            .then(quiesce(QLong))
            .expect(orders == Set({
                firstKind: EvTimer, firstSlot: 1,
                thenKind: EvTimer, thenSlot: 0
            }))

    /// Arming twice coalesces; re-arming from the callback does not.  Both
    /// are closed claims, because a deferral that runs an extra time runs the
    /// application's bookkeeping an extra time.
    run deferralCoalescesTest =
        init
            .then(defer(0, OpDeferTwice, 1))
            .then(quiesce(QShort))
            .expect(expects == Set({ kind: EvDeferral, slot: 0, mult: MExactly, count: 1 }))
            .then(defer(0, OpDeferReentrant, 2))
            .then(quiesce(QShort))
            .expect(expects == Set({ kind: EvDeferral, slot: 0, mult: MExactly, count: 2 }))

    /// A wakeup may coalesce, so two rings owe at least one callback -- but
    /// a doorbell that retires itself from its callback owes exactly one, and
    /// the quiesce after it owes none at all.
    run doorbellRingIsAWakeupTest =
        init
            .then(addDoorbell(0))
            .then(ringDoorbell(0, OpRingDoorbellTwice))
            .then(quiesce(QShort))
            .expect(expects == Set({ kind: EvDoorbell, slot: 0, mult: MAtLeast, count: 1 }))
            .then(removeDoorbellInCallback(0))
            .then(quiesce(QShort))
            .expect(expects == Set({ kind: EvDoorbell, slot: 0, mult: MExactly, count: 1 }))
            .then(quiesce(QShort))
            .expect(expects == Set())

    /// Both ends learn of the connection, and each learns once.
    run bothEndsSeeTheConnectionTest =
        init
            .then(listen)
            .then(connect(0, DrainRecv))
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvConnected, slot: sideSlot(0, SIDE_CLIENT), mult: MExactly, count: 1 },
                { kind: EvConnected, slot: sideSlot(0, SIDE_SERVER), mult: MExactly, count: 1 }))
            .then(quiesce(QShort))
            .expect(expects == Set())

    /// Every byte sent arrives at the peer, and only at the peer: the sender's
    /// own end owes nothing, so an implementation that looped a payload back
    /// fails on rule 2 rather than needing a check of its own.
    run bytesArriveAtThePeerTest =
        init
            .then(listen)
            .then(connect(0, DrainPeek))
            .then(quiesce(QShort))
            .then(send(0, SIDE_CLIENT, SzMedium, SendBuf))
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvRecv, slot: sideSlot(0, SIDE_SERVER),
                  mult: MExactly, count: 8192 }))

    /// Sends in both directions are independent, and both are owed in full.
    run bothDirectionsAreIndependentTest =
        init
            .then(listen)
            .then(connect(1, DrainRecvV))
            .then(quiesce(QShort))
            .then(send(1, SIDE_CLIENT, SzTiny, SendV))
            .then(send(1, SIDE_SERVER, SzLarge, SendVTakeRef))
            .then(quiesce(QLong))
            .expect(expects == Set(
                { kind: EvRecv, slot: sideSlot(1, SIDE_SERVER), mult: MExactly, count: 1 },
                { kind: EvRecv, slot: sideSlot(1, SIDE_CLIENT), mult: MExactly, count: 131072 }))

    /// The distinction between the two ways of ending a connection: what was
    /// queued before a finish must still arrive, and the disconnect must
    /// arrive too.  A transport that dropped its send ring on the way out
    /// satisfies the second half and fails the first.
    run finishDeliversWhatWasQueuedTest =
        init
            .then(listen)
            .then(connect(0, DrainRecv))
            .then(quiesce(QShort))
            .then(send(0, SIDE_CLIENT, SzSmall, SendGlobal))
            .then(finish(0, SIDE_CLIENT))
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvRecv, slot: sideSlot(0, SIDE_SERVER), mult: MExactly, count: 100 },
                { kind: EvDisconnected, slot: sideSlot(0, SIDE_CLIENT), mult: MExactly, count: 1 },
                { kind: EvDisconnected, slot: sideSlot(0, SIDE_SERVER), mult: MExactly, count: 1 }))
            /* And the slot is free again afterwards, with nothing owed. */
            .then(quiesce(QShort))
            .expect(expects == Set())

    /// Closing one end takes the other down with it, and each end is told
    /// exactly once -- a second notification would be a double free in an
    /// application that frees its connection state there.
    run closeTakesDownBothEndsTest =
        init
            .then(listen)
            .then(connect(0, DrainRecv))
            .then(quiesce(QShort))
            .then(close(0, SIDE_SERVER))
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvDisconnected, slot: sideSlot(0, SIDE_CLIENT), mult: MExactly, count: 1 },
                { kind: EvDisconnected, slot: sideSlot(0, SIDE_SERVER), mult: MExactly, count: 1 }))
            .then(quiesce(QShort))
            .expect(expects == Set())

    /// A connection slot is reusable once its connection has gone, and the
    /// second connection is a connection in its own right.
    run slotsAreReusableTest =
        init
            .then(listen)
            .then(connect(0, DrainRecv))
            .then(quiesce(QShort))
            .then(close(0, SIDE_CLIENT))
            .then(quiesce(QShort))
            .then(connect(0, DrainRecvV))
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvConnected, slot: sideSlot(0, SIDE_CLIENT), mult: MExactly, count: 1 },
                { kind: EvConnected, slot: sideSlot(0, SIDE_SERVER), mult: MExactly, count: 1 }))

    /// Cancelling an armed deferral owes nothing -- and the point is that
    /// nothing is owed: rule 2 turns the callback arriving anyway into a
    /// failure, which is the only way to observe a cancellation.
    run removedDeferralDoesNotRunTest =
        init
            .then(defer(0, OpDefer, 1))
            .then(removeDeferral(0))
            .then(quiesce(QShort))
            .expect(expects == Set())
            /* And the documented no-op leaves it that way. */
            .then(removeDeferralIdle(0))
            .then(quiesce(QShort))
            .expect(expects == Set())
            /* Still usable afterwards: cancelling is not disabling. */
            .then(defer(0, OpDefer, 1))
            .then(quiesce(QShort))
            .expect(expects == Set({ kind: EvDeferral, slot: 0, mult: MExactly, count: 1 }))

    /// The loop spins while there has been recent activity and falls back
    /// afterwards, and the enter/exit pair brackets exactly that.  A program
    /// begins inside the spin window because evpl_create starts it, so the
    /// first window both enters and leaves; the next owes nothing at all
    /// until something reports activity.
    run pollEntersAndLeavesTest =
        init
            .then(addPoll)
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvPollEnter, slot: 0, mult: MExactly, count: 1 },
                { kind: EvPoll, slot: 0, mult: MExactly, count: 1 },
                { kind: EvPollExit, slot: 0, mult: MExactly, count: 1 }))
            .then(quiesce(QShort))
            .expect(expects == Set())
            .then(activity)
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvPollEnter, slot: 0, mult: MExactly, count: 1 },
                { kind: EvPoll, slot: 0, mult: MExactly, count: 1 },
                { kind: EvPollExit, slot: 0, mult: MExactly, count: 1 }))

    /// A pin holds the loop in poll mode across windows however quiet it is,
    /// and releasing it lets the spin window expire.  This is the property
    /// the pin exists for: a completion that can only be reaped by polling is
    /// lost if the loop falls back while it is outstanding.
    run pinnedPollKeepsSpinningTest =
        init
            .then(addPoll)
            .then(pollPin)
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvPollEnter, slot: 0, mult: MExactly, count: 1 },
                { kind: EvPoll, slot: 0, mult: MExactly, count: 1 }))
            .then(quiesce(QLong))
            .expect(expects == Set(
                { kind: EvPoll, slot: 0, mult: MExactly, count: 1 }))
            .then(pollUnpin)
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvPoll, slot: 0, mult: MExactly, count: 1 },
                { kind: EvPollExit, slot: 0, mult: MExactly, count: 1 }))

    /// Nothing is notified about a send until an end asks; once it has, every
    /// byte it hands over is reported back to it, and only to it.
    run sendNotificationsAreOptInTest =
        init
            .then(listen)
            .then(connect(0, DrainRecv))
            .then(quiesce(QShort))
            /* Before asking: the peer is owed the bytes, this end is owed
             * nothing. */
            .then(send(0, SIDE_CLIENT, SzSmall, SendBuf))
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvRecv, slot: sideSlot(0, SIDE_SERVER), mult: MExactly, count: 100 }))
            /* After asking, both. */
            .then(requestSendNotify(0, SIDE_CLIENT))
            .then(send(0, SIDE_CLIENT, SzSmall, SendReserveCommit))
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvRecv, slot: sideSlot(0, SIDE_SERVER), mult: MExactly, count: 100 },
                { kind: EvSent, slot: sideSlot(0, SIDE_CLIENT), mult: MExactly, count: 100 }))

    /// While hooks are installed all three run on every window, and once
    /// cleared none of them does -- which rule 2 is what checks.
    run loopHooksRunWhileInstalledTest =
        init
            .then(setLoopHooks)
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvHook, slot: 0, mult: MExactly, count: 1 },
                { kind: EvHook, slot: 1, mult: MExactly, count: 1 },
                { kind: EvHook, slot: 2, mult: MExactly, count: 1 }))
            .then(clearLoopHooks)
            .then(quiesce(QShort))
            .expect(expects == Set())

    /// The property that separates the two transports.  Three sends of
    /// different sizes owe three deliveries totalling their sum on a
    /// datagram; on a stream only the sum is owed, because a stream is free
    /// to deliver it in any number of pieces.
    ///
    /// A byte count alone cannot tell the two apart, which is why EvRecvMsg
    /// exists: coalescing two datagrams into one delivery, or splitting one
    /// across two, both keep the total and both are failures.
    run datagramPreservesMessageBoundariesTest =
        init
            .then(doReset(ShapeMixed, TDatagramInproc))
            .then(listen)
            .then(connect(0, DrainRecv))
            .then(quiesce(QShort))
            .then(send(0, SIDE_CLIENT, SzTiny, SendBuf))
            .then(send(0, SIDE_CLIENT, SzSmall, SendV))
            .then(send(0, SIDE_CLIENT, SzMedium, SendBuf))
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvRecv, slot: sideSlot(0, SIDE_SERVER),
                  mult: MExactly, count: 1 + 100 + 8192 },
                { kind: EvRecvMsg, slot: sideSlot(0, SIDE_SERVER),
                  mult: MExactly, count: 3 }))

    /// The same three sends over a stream owe the bytes and nothing about how
    /// they are divided up.
    run streamOwesBytesAndNotMessagesTest =
        init
            .then(listen)
            .then(connect(0, DrainRecv))
            .then(quiesce(QShort))
            .then(send(0, SIDE_CLIENT, SzTiny, SendBuf))
            .then(send(0, SIDE_CLIENT, SzSmall, SendV))
            .then(send(0, SIDE_CLIENT, SzMedium, SendBuf))
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvRecv, slot: sideSlot(0, SIDE_SERVER),
                  mult: MExactly, count: 1 + 100 + 8192 }))

    /// UDP has no connection: both ends are bound and address each other by
    /// endpoint.  Nothing is notified about the pair coming up, which is what
    /// distinguishes this from connect -- and the message-boundary obligation
    /// is the same as any other datagram's.
    run udpPairNeedsNoConnectionTest =
        init
            .then(resetUdp)
            .then(bindPair(0))
            .then(quiesce(QShort))
            .expect(expects == Set())
            .then(send(0, SIDE_CLIENT, SzSmall, SendToEp))
            .then(send(0, SIDE_SERVER, SzTiny, SendToEpV))
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvRecv, slot: sideSlot(0, SIDE_SERVER), mult: MExactly, count: 100 },
                { kind: EvRecvMsg, slot: sideSlot(0, SIDE_SERVER), mult: MExactly, count: 1 },
                { kind: EvRecv, slot: sideSlot(0, SIDE_CLIENT), mult: MExactly, count: 1 },
                { kind: EvRecvMsg, slot: sideSlot(0, SIDE_CLIENT), mult: MExactly, count: 1 }))

    /// Every request owes exactly one completion, and owes it in the window
    /// it was submitted in.  Three requests in one window owe three; the
    /// window after owes none, which is what makes a completion that fires
    /// twice a failure rather than a shrug.
    run blockRequestOwesOneCompletionTest =
        init
            .then(openQueue(0))
            .then(blockWrite(0, 0, BSeg1, OpBlockWrite))
            .then(blockWrite(0, 1, BSeg4, OpBlockWriteSync))
            .then(blockFlush(0))
            .then(quiesce(QShort))
            .expect(expects == Set({ kind: EvBlock, slot: 0, mult: MExactly, count: 3 }))
            .then(quiesce(QShort))
            .expect(expects == Set())

    /// A region reads back what was written to it, whatever the two calls
    /// scattered their buffers across.  The claim only exists once the write
    /// has completed -- before the quiesce there is nothing to read back.
    run blockReadReturnsWhatWasWrittenTest =
        init
            .then(openQueue(0))
            .then(blockWrite(0, 0, BSeg16, OpBlockWrite))
            .then(quiesce(QShort))
            .then(blockRead(0, 0, BSeg1))
            .expect(current.pattern == writePattern(1))
            .then(quiesce(QShort))
            .expect(expects == Set({ kind: EvBlock, slot: 0, mult: MExactly, count: 1 }))

    /// write_zeroes is a data guarantee: the range reads back as zeros.
    /// discard is not one -- it is advisory, and what is there afterwards is
    /// unspecified -- so the model goes back to claiming nothing about the
    /// region while still requiring the completion.
    run blockZeroesAndDiscardDifferTest =
        init
            .then(openQueue(0))
            .then(blockWriteZeroes(0, 2))
            .then(quiesce(QShort))
            .then(blockRead(0, 2, BSeg4))
            .expect(current.pattern == CONTENT_ZERO)
            .then(quiesce(QShort))
            .then(blockWriteZeroesAll(0))
            .then(quiesce(QShort))
            .then(blockRead(0, 3, BSeg1))
            .expect(current.pattern == CONTENT_ZERO)
            .then(quiesce(QShort))
            .then(blockDiscard(0, 2))
            .then(quiesce(QShort))
            .then(blockRead(0, 2, BSeg4))
            .expect(current.pattern == CONTENT_UNKNOWN)

    /// Two queues on one device are independent: each is owed exactly what
    /// was submitted on it, which is the claim a backend breaks by handing a
    /// completion to whichever queue it finds first.
    run blockQueuesAreIndependentTest =
        init
            .then(openQueue(0))
            .then(openQueue(1))
            .then(blockWrite(0, 0, BSeg1, OpBlockWrite))
            .then(blockWrite(1, 1, BSeg1, OpBlockWrite))
            .then(blockFlush(1))
            .then(quiesce(QShort))
            .expect(expects == Set(
                { kind: EvBlock, slot: 0, mult: MExactly, count: 1 },
                { kind: EvBlock, slot: 1, mult: MExactly, count: 2 }))
            .then(closeQueue(0))
            .then(quiesce(QShort))
            .expect(expects == Set())
}
