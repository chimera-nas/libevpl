// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * client.qnt -- the reply-defect taxonomy for the RPC2 *client*.
 *
 * defects.qnt drives libevpl's server with malformed CALLs.  This model is its
 * mirror image: each state is one deliberately defective REPLY delivered to a
 * real libevpl client by a hostile server, plus what the client is required to
 * do with it.
 *
 * IMPORTANT: this model encodes the SPECIFICATION, not libevpl's current
 * behaviour.  Where the two disagree the driver records a divergence, which is
 * reviewed as a candidate bug.  Encoding current behaviour instead would
 * freeze today's defects into the spec and guarantee they are never found.
 *
 * The two requirements that carry most of the weight here, because both are
 * easy to violate and neither is visible from a well-behaved peer:
 *
 *   1. No call may be abandoned in silence.  A client that issued a call owes
 *      its caller exactly one completion, whatever the peer does -- including
 *      hanging up.  Anything else is a caller blocked forever.
 *
 *   2. A reply the peer refused is not a result.  MSG_DENIED and any
 *      accept_stat other than SUCCESS mean there is no result to deliver, so
 *      whatever bytes follow must never reach the caller as a success.
 *
 * The defect kinds are SYMBOLIC; the driver owns the byte-level mis-encoding.
 * Quint's job is to enumerate the taxonomy and state the required outcome.
 *
 *   quint test client.qnt
 *   quint run client.qnt --invariant=safety
 */
module rpc2_client {

    /// Mirrors hello_world.x and the RPC2 reply envelope (RFC 5531 section 9).
    pure val PROG = 42
    pure val VERS = 1
    pure val PROC_GREET = 1
    pure val RPC_VERS = 2

    type Defect =
        /* --- baseline: proves the hostile server can build a VALID reply -- */
        | ReplyWellFormed
        /* A reply verifier need not be AUTH_NONE; any legal opaque_auth must
         * decode.  Positive coverage for the header decoder. */
        | ReplyVerfAuthSys
        /* Legal record marking (RFC 5531 section 11) on the inbound path. */
        | ReplySplitAcrossFragments(int)

        /* --- replies that are not ours ---------------------------------- */
        | ReplyUnknownXid
        | ReplyDuplicated             /* the same reply delivered twice      */
        | ReplyIsACall                /* mtype == CALL on a client connection */

        /* --- envelope the client cannot parse ---------------------------- */
        | ReplyHeaderTruncated(int)   /* record shorter than an RPC header    */
        | ReplyMtypeUndefined(int)    /* mtype neither CALL nor REPLY         */
        | ReplyVerfBodyOverlong       /* verf length disagrees with its body  */
        | PeerClosesWithoutReply      /* connection dropped mid-call          */

        /* --- results the peer refused to produce ------------------------- */
        | ReplyRejectedAuth           /* MSG_DENIED / AUTH_ERROR              */
        | ReplyRejectedRpcMismatch    /* MSG_DENIED / RPC_MISMATCH            */
        | ReplyAcceptStat(int)        /* MSG_ACCEPTED, accept_stat != SUCCESS */
        /* The same refusals, but with a perfectly well-formed result encoded
         * after them.  A client that ignores the status and decodes whatever
         * follows reports success for a call the peer declined -- so these
         * separate "does not look at the status" from "happens to fail to
         * decode the empty body that a refusal leaves behind". */
        | ReplyDeniedWithBody
        | ReplyAcceptStatWithBody(int)
        | ReplyStatUndefined(int)     /* reply_stat neither ACCEPTED nor DENIED */

        /* --- undecodable results (RFC 4506) ------------------------------ */
        | ReplyEmptyBody
        | ReplyTruncatedBody(int)
        | ReplyTrailingGarbage(int)
        | ReplyGarbageBody
        | ReplyStringLenOverflow
        | ReplyStringLenBeyondMessage

    /// What the client must do with the reply.
    type Outcome =
        /* The callback fires with status 0 and the value the peer encoded. */
        | CbSuccess
        /* The callback fires with EVPL_RPC2_REPLY_DECODE_ERROR: the results
         * were present but not decodable as the procedure's return type. */
        | CbDecodeError
        /* The callback fires with some non-zero status.  Which one is left
         * open: libevpl's reply callback carries a single int, so requiring a
         * distinct code for each refusal would be requiring an API change
         * rather than stating a protocol obligation.  What is NOT open is that
         * the call completes, and completes as a failure. */
        | CbFailed
        /* This reply is not an answer to the outstanding call and must be
         * discarded without completing it. */
        | CbDropped

    /// Whether the connection must survive the defect.  ConnAny is for the
    /// defects that destroy the framing or the transport itself, where
    /// dropping the connection is a legitimate response; the callback
    /// obligation above still holds in that case.
    type Survival =
        | ConnUp
        | ConnAny

    /// How the hostile server puts the bytes on the wire.  A defect that is
    /// only detected because the whole record arrived in one read is not
    /// really detected, so every payload defect is also delivered split.
    type Delivery =
        | OneWrite
        | TwoWrites
        | Dribble        /* one byte per write, pumping the loop between */

    type Case = { defect: Defect, delivery: Delivery }

    var current: Case

    /// The response the specification requires for `current`.  State
    /// variables rather than derived expressions so that they are carried in
    /// the generated ITF trace: the trace, not the model, is what the C driver
    /// consumes, so the prediction has to travel with the case.
    var expected: Outcome
    var survives: Survival

    // ------------------------------------------------------------------
    // The specification: defect -> required client behaviour
    // ------------------------------------------------------------------

    pure def required(d: Defect): Outcome = match d {
        | ReplyWellFormed => CbSuccess
        | ReplyVerfAuthSys => CbSuccess

        /* RFC 5531 section 11: a record split across fragments is one
         * message.  Reassembling it is not optional. */
        | ReplySplitAcrossFragments(_) => CbSuccess

        /* The first copy completes the call; the taxonomy entry is about the
         * copy that follows it, which by then matches no outstanding xid.  The
         * driver additionally requires that the callback fired exactly once --
         * a second delivery must not double-complete. */
        | ReplyDuplicated => CbSuccess

        /* A reply matching no outstanding call is late, duplicate, or for a
         * call already reaped.  ONC RPC has no way to acknowledge a reply, so
         * the only correct action is to drop it -- and, because every record
         * is framed independently, to keep the connection. */
        | ReplyUnknownXid => CbDropped

        /* A CALL arriving on a connection where no program is exported is not
         * an answer to anything.  It must not be matched against a pending
         * xid, and it must not take the connection down. */
        | ReplyIsACall => CbDropped

        /* Nothing about a garbled record identifies which call it answers, so
         * the connection may go.  What may not go is the caller's completion:
         * the client knows exactly which calls it had outstanding on that
         * connection and owes each of them an answer. */
        | ReplyHeaderTruncated(_) => CbFailed
        | ReplyMtypeUndefined(_) => CbFailed
        | ReplyVerfBodyOverlong => CbFailed
        | PeerClosesWithoutReply => CbFailed

        /* A refusal is a completed call with no result.  Reporting it as a
         * failure is required; reporting the bytes that follow it as a result
         * is the bug these cases exist to catch. */
        | ReplyRejectedAuth => CbFailed
        | ReplyRejectedRpcMismatch => CbFailed
        | ReplyAcceptStat(_) => CbFailed
        | ReplyDeniedWithBody => CbFailed
        | ReplyAcceptStatWithBody(_) => CbFailed
        | ReplyStatUndefined(_) => CbFailed

        /* Results that are present but not decodable as the procedure's
         * return type.  RFC 4506: too short, too long, or internally
         * inconsistent are all invalid, and the caller must be told the call
         * failed rather than handed a partially decoded value. */
        | ReplyEmptyBody => CbDecodeError
        | ReplyTruncatedBody(_) => CbDecodeError
        | ReplyTrailingGarbage(_) => CbDecodeError
        | ReplyGarbageBody => CbDecodeError
        | ReplyStringLenOverflow => CbDecodeError
        | ReplyStringLenBeyondMessage => CbDecodeError
    }

    /// A defect that leaves the record framing intact gives the client no
    /// reason to hang up: one bad reply does not desync a record-marked
    /// stream, and closing would fail every other call in flight.
    pure def survival(d: Defect): Survival = match d {
        | ReplyHeaderTruncated(_) => ConnAny
        | ReplyMtypeUndefined(_) => ConnAny
        | ReplyVerfBodyOverlong => ConnAny
        | PeerClosesWithoutReply => ConnAny
        | _ => ConnUp
    }

    // ------------------------------------------------------------------
    // Case generation
    // ------------------------------------------------------------------

    pure val DELIVERIES = Set(OneWrite, TwoWrites, Dribble)

    /// Defect instances.  Where a defect carries a number, a few
    /// representative values are enumerated rather than the whole domain: the
    /// driver's encoding is identical for all of them, so extra values buy no
    /// new code paths.
    pure val DEFECTS = Set(
        ReplyWellFormed,
        ReplyVerfAuthSys,
        ReplySplitAcrossFragments(2), ReplySplitAcrossFragments(3),
        ReplySplitAcrossFragments(16),
        ReplyUnknownXid,
        ReplyDuplicated,
        ReplyIsACall,
        ReplyHeaderTruncated(0), ReplyHeaderTruncated(4), ReplyHeaderTruncated(9),
        ReplyMtypeUndefined(2), ReplyMtypeUndefined(4294967295),
        ReplyVerfBodyOverlong,
        PeerClosesWithoutReply,
        ReplyRejectedAuth,
        ReplyRejectedRpcMismatch,
        /* 1 PROG_UNAVAIL, 2 PROG_MISMATCH, 3 PROC_UNAVAIL, 4 GARBAGE_ARGS,
         * 5 SYSTEM_ERR -- PROG_MISMATCH is the one that carries a body of its
         * own, so it is kept in both the with- and without-results forms. */
        ReplyAcceptStat(1), ReplyAcceptStat(2), ReplyAcceptStat(4),
        ReplyAcceptStat(5),
        ReplyDeniedWithBody,
        ReplyAcceptStatWithBody(2), ReplyAcceptStatWithBody(4),
        ReplyStatUndefined(2), ReplyStatUndefined(4294967295),
        ReplyEmptyBody,
        ReplyTruncatedBody(1), ReplyTruncatedBody(4), ReplyTruncatedBody(8),
        ReplyTrailingGarbage(4), ReplyTrailingGarbage(64),
        ReplyGarbageBody,
        ReplyStringLenOverflow,
        ReplyStringLenBeyondMessage
    )

    /// Apply one specific case, recording the required behaviour alongside it.
    action use(d: Defect, v: Delivery): bool = all {
        current' = { defect: d, delivery: v },
        expected' = required(d),
        survives' = survival(d)
    }

    action pick = {
        nondet d = DEFECTS.oneOf()
        nondet v = DELIVERIES.oneOf()
        use(d, v)
    }

    action init = use(ReplyWellFormed, OneWrite)
    action step = pick

    // ------------------------------------------------------------------
    // Invariants
    // ------------------------------------------------------------------

    /// Totality check on `required`.  Quint's match is exhaustive, so a new
    /// Defect variant without a rule fails to typecheck rather than silently
    /// defaulting -- this catches the reverse mistake, an Outcome the C driver
    /// would have no arm for.
    val outcomeIsSpecified = match expected {
        | CbSuccess => true
        | CbDecodeError => true
        | CbFailed => true
        | CbDropped => true
    }

    /// Requirement 1.  Only a reply that is not an answer to the outstanding
    /// call may leave it uncompleted; everything else -- including the peer
    /// hanging up -- must complete it.  This is the property that catches
    /// "frees the pending request without invoking its callback".
    val noCallIsLostInSilence =
        match current.defect {
            | ReplyUnknownXid => expected == CbDropped
            | ReplyIsACall => expected == CbDropped
            | _ => expected != CbDropped
        }

    /// Requirement 2.  A refusal may never be reported as a success, whatever
    /// bytes the peer appended to it.
    val refusalIsNeverSuccess =
        match current.defect {
            | ReplyRejectedAuth => expected == CbFailed
            | ReplyRejectedRpcMismatch => expected == CbFailed
            | ReplyAcceptStat(_) => expected == CbFailed
            | ReplyDeniedWithBody => expected == CbFailed
            | ReplyAcceptStatWithBody(_) => expected == CbFailed
            | ReplyStatUndefined(_) => expected == CbFailed
            | _ => true
        }

    /// A reply the client is required to ignore is not a reason to hang up:
    /// dropping the connection would fail every other call in flight.
    val droppedRepliesKeepTheConnection =
        (expected != CbDropped) or (survives == ConnUp)

    val safety =
        outcomeIsSpecified and noCallIsLostInSilence and
        refusalIsNeverSuccess and droppedRepliesKeepTheConnection

    // ------------------------------------------------------------------
    // Scenario tests: the outcomes most likely to be got wrong
    // ------------------------------------------------------------------

    /// A stray reply is dropped, not fatal -- and dropping it must leave the
    /// connection able to carry the next call.
    run strayReplyIsDroppedTest =
        init
            .then(use(ReplyUnknownXid, OneWrite))
            .expect(expected == CbDropped and survives == ConnUp)
            .then(use(ReplyIsACall, OneWrite))
            .expect(expected == CbDropped and survives == ConnUp)

    /// The distinction that separates "cannot decode the results" from "the
    /// peer declined to produce results": both fail, and a refusal carrying a
    /// decodable body still fails.
    run refusalIsNotAResultTest =
        init
            .then(use(ReplyRejectedAuth, OneWrite))
            .expect(expected == CbFailed)
            .then(use(ReplyDeniedWithBody, OneWrite))
            .expect(expected == CbFailed)
            .then(use(ReplyAcceptStatWithBody(4), OneWrite))
            .expect(expected == CbFailed)
            .then(use(ReplyStatUndefined(2), OneWrite))
            .expect(expected == CbFailed)

    /// Losing the transport is still a completion.
    run transportLossCompletesTheCallTest =
        init
            .then(use(PeerClosesWithoutReply, OneWrite))
            .expect(expected == CbFailed and survives == ConnAny)
            .then(use(ReplyMtypeUndefined(2), OneWrite))
            .expect(expected == CbFailed)

    /// Undecodable results are reported as such, not as a zero-filled value.
    run undecodableResultsAreReportedTest =
        init
            .then(use(ReplyTruncatedBody(4), Dribble))
            .expect(expected == CbDecodeError)
            .then(use(ReplyTrailingGarbage(4), OneWrite))
            .expect(expected == CbDecodeError)
            .then(use(ReplyStringLenOverflow, TwoWrites))
            .expect(expected == CbDecodeError)

    /// Legal framing must still work when it arrives the hard way.
    run legalFramingSucceedsTest =
        init
            .then(use(ReplySplitAcrossFragments(16), OneWrite))
            .expect(expected == CbSuccess)
            .then(use(ReplyWellFormed, Dribble))
            .expect(expected == CbSuccess)
            .then(use(ReplyVerfAuthSys, TwoWrites))
            .expect(expected == CbSuccess)
}
