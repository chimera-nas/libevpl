// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * defects.qnt -- the negative half of the conformance matrix.
 *
 * Each state is one deliberately defective RPC call plus the response RFC
 * 5531 (ONC RPC) and RFC 4506 (XDR) require the server to produce.
 *
 * IMPORTANT: this model encodes the SPECIFICATION, not libevpl's current
 * behaviour.  Where the two disagree the replay driver records a divergence
 * rather than failing outright, and the divergence list is reviewed as a set
 * of candidate bugs.  Encoding current behaviour instead would freeze
 * today's defects into the spec and guarantee they are never found.
 *
 * The defect kinds are SYMBOLIC; the driver owns the byte-level mis-encoding.
 * Quint's job is to enumerate the taxonomy and state the required outcome,
 * which is exactly the part that is easy to get wrong by hand and easy to
 * forget to update.
 *
 *   quint test defects.qnt
 *   quint run defects.qnt --invariant=outcomeIsSpecified
 */
module rpc2_defects {

    /// Mirrors of conformance.x / the RPC2 envelope.
    pure val PROG = 44
    pure val VERS_LOW = 1
    pure val VERS_HIGH = 1
    pure val MAX_PROC = 9
    pure val RPC_VERS = 2
    pure val BOUNDED_MAX = 8

    /// The procedures whose arguments the raw-socket driver can hand-build.
    /// Payload defects target one of these; envelope defects ignore it.
    type Target =
        | TScalars      /* proc 1: fixed-size, no counted fields  */
        | TBytes        /* proc 2: string, opaque<>, opaque<8>    */
        | TArrays       /* proc 4: counted arrays, one bounded    */
        | TStrict       /* proc 6: union with no default arm      */

    type Defect =
        /* --- baseline: proves the driver can build a VALID call ------- */
        | NoDefect
        /* --- RPC envelope (RFC 5531 section 9) ------------------------ */
        | RpcVersWrong(int)
        | ProgramUnknown
        | VersionUnsupported(int)
        | ProcedureUnknown(int)
        | ProcedureNull
        | AuthFlavorUnsupported(int)
        | CredBodyOverlong
        | AuthSysValid                /* a well-formed AUTH_SYS credential */
        /* --- XDR payload (RFC 4506) ----------------------------------- */
        | ArgsTruncated(int)
        | ArgsTrailingGarbage(int)
        | StringLenOverflow
        | StringLenBeyondMessage
        | StringExceedsBound
        | OpaqueExceedsBound
        | ArrayCountExceedsBound
        | ArrayCountHuge
        | DiscriminantUnmatched
        | BoolNotZeroOrOne
        | EnumNotDeclared
        /* --- TCP record marking (RFC 5531 section 11) ----------------- */
        | RecordMarkHuge
        | RecordMarkZeroLength
        | CallSplitAcrossFragments(int)
        /* One call split into more fragments than the receiver's payload
         * iovec ceiling, which forces it to flatten the message into a
         * bounded contiguous copy.  Still legal framing -- RFC 5531 section
         * 11 sets no limit on fragment count -- so it must succeed like any
         * other split.  Deliberately a variant of its own rather than another
         * CallSplitAcrossFragments value: it needs a payload large enough to
         * divide that many ways, and it is meant to run as one scenario
         * rather than across the whole target matrix. */
        | CallSplitPathological
        /* One call split into fragments that are each individually legal --
         * every record mark is small, and none on its own is refusable --
         * but whose running total exceeds what the receiver is willing to
         * hold for one message.  RFC 5531 section 11 bounds a *fragment* at
         * 2**31-1 bytes and says nothing at all about a record's total
         * length, so a receiver that only checks fragments will buffer
         * without limit on an unauthenticated peer's say-so.  Distinct from
         * RecordMarkHuge, which is one oversized mark refused on sight. */
        | ReassemblyCapExceeded
        /* --- RPCSEC_GSS (RFC 2203) ------------------------------------ */
        | GssInitEstablishes          /* handshake completes in one leg    */
        | GssInitContinues            /* handshake needs a second leg      */
        | GssInitMechFails            /* provider rejects the token        */
        | GssDataValid                /* established context, good MIC     */
        | GssCredVersionWrong(int)
        | GssProcUnknown(int)
        /* An rpc_gss_service outside the three RFC 2203 defines.  krb5p used
         * to live here as "a defined service we do not provide"; now that all
         * three are implemented, only an undefined value is refusable, and
         * this keeps that gate covered. */
        | GssServiceUnknown(int)
        | GssHandleUnknown            /* DATA against a handle we never got */
        | GssVerifierNotGss           /* DATA whose verf is not flavor 6   */
        | GssMicWrong                 /* DATA carrying a bad header MIC    */
        | GssSeqReplayed              /* a sequence number already used    */
        | GssIntegDataValid           /* krb5i: well-formed integ_data     */
        | GssIntegChecksumWrong       /* krb5i: databody checksum is bad   */
        | GssIntegSeqMismatch         /* krb5i: databody seq != cred seq   */
        | GssPrivDataValid            /* krb5p: well-formed priv_data      */
        | GssPrivSealCorrupt          /* krb5p: token will not unseal      */
        | GssPrivSeqMismatch          /* krb5p: sealed seq != cred seq     */
        | GssDestroyContext           /* DESTROY of a context we hold      */
        | GssDestroyUnauthenticated   /* DESTROY with no valid header MIC  */
        /* --- RPCSEC_GSS replay window (RFC 2203 section 5.3.3.1) ------- */
        | GssSeqAboveMax              /* seq_num above MAXSEQ (0x80000000) */
        | GssSeqWindowJump            /* seq_num jumps clear of the window */
        | GssSeqTooOld                /* seq_num below the window          */
        | GssSeqOutOfOrder            /* in-window, unseen, not the next   */
        /* --- RPCSEC_GSS credential framing (RFC 2203 section 5) -------- */
        | GssCredTruncated            /* credential body ends mid-field    */
        | GssCredHandleOverruns       /* handle<> runs past the credential */
        /* --- RPCSEC_GSS context creation (RFC 2203 section 5.2) -------- */
        | GssNoMechanism(int)         /* flavor 6 at a server with no GSS  */
        | GssContinueInitUnknownHandle /* CONTINUE_INIT naming no context  */
        | GssInitTokenMalformed(int)  /* rpc_gss_init_arg is undecodable   */
        | GssContinueInitTokenMalformed
        | GssInitMechFailsWithToken   /* accept() fails but emits a token  */
        /* --- RPCSEC_GSS integrity framing (RFC 2203 section 5.3.2.2) --- */
        | GssIntegFramingBad(int)     /* rpc_gss_integ_data is undecodable */
        | GssIntegEmptyArgs           /* krb5i call with no arguments      */
        | GssIntegSplitAcrossFragments
        | GssIntegReplyMicFails       /* cannot sign the results           */
        | GssIntegReplyMicOversize    /* signature too big to emit         */

    /// What the server must do.  Closed means "no reply is possible, the
    /// connection must be dropped" -- used where the defect destroys the
    /// xid, so there is nothing to address a reply to.  A server that
    /// instead hangs or buffers without bound fails this expectation; the
    /// driver reports that distinctly as Stalled.
    type Outcome =
        | Success
        | ProgUnavail
        | ProgMismatch({ lo: int, hi: int })
        | ProcUnavail
        | GarbageArgs
        | RpcMismatch({ lo: int, hi: int })
        | AuthError
        | Closed
        /* Accepted, understood, and deliberately answered with silence: RFC
         * 2203 requires a replayed RPCSEC_GSS sequence number to be discarded
         * without a reply, while the connection stays up.  Distinct from
         * Closed (no connection) and from a stalled server (no decision). */
        | NoReply

    type Case = { defect: Defect, target: Target }

    var current: Case

    /// The response the specification requires for `current`.  This is a
    /// state variable rather than a derived expression so that it is carried
    /// in the generated ITF trace: the trace, not the model, is what the C
    /// driver consumes, so the prediction has to travel with the case.
    var expected: Outcome

    // ------------------------------------------------------------------
    // The specification: defect -> required response
    // ------------------------------------------------------------------

    /**
     * RFC 5531 section 9 fixes both the outcomes and the order of the checks
     * that produce them: the RPC version is validated before the program,
     * the program before the version, and the version before the procedure.
     * Argument decoding happens last, so a call that is defective in two
     * ways reports the earlier defect.  The driver only ever injects one
     * defect at a time, so that ordering is not exercised here -- but it is
     * why each case below can name a single outcome.
     */
    pure def required(d: Defect): Outcome = match d {
        | NoDefect => Success

        /* An unrecognised RPC protocol version is denied outright, with the
         * range of versions the server speaks.  RFC 5531 section 9. */
        | RpcVersWrong(_) => RpcMismatch({ lo: RPC_VERS, hi: RPC_VERS })

        /* A program the server does not export is PROG_UNAVAIL -- NOT
         * PROG_MISMATCH, which is reserved for a program that exists at
         * other versions.  Clients use the distinction to decide whether to
         * downgrade or give up. */
        | ProgramUnknown => ProgUnavail

        /* An exported program at an unsupported version reports the range
         * actually supported, so the client can retry within it. */
        | VersionUnsupported(_) => ProgMismatch({ lo: VERS_LOW, hi: VERS_HIGH })

        | ProcedureUnknown(_) => ProcUnavail

        /* RFC 5531 section 11.1: every program must implement procedure 0,
         * taking no arguments and returning no results. */
        | ProcedureNull => Success

        /* An authentication flavor the server does not support is denied.
         * RFC 5531 leaves the specific auth_stat open (AUTH_BADCRED and
         * AUTH_TOOWEAK are both defensible), so the model requires only
         * AUTH_ERROR and the driver does not compare the sub-status. */
        | AuthFlavorUnsupported(_) => AuthError
        | CredBodyOverlong => AuthError

        /* Not a defect: AUTH_SYS is one of the two flavors RFC 5531 defines,
         * and a call carrying a well-formed one is an ordinary call.  Present
         * so that the flavor's accepted path is asserted, not just the
         * rejection of a malformed credential above. */
        | AuthSysValid => Success

        /* Anything that makes the argument stream undecodable -- too short,
         * too long, or internally inconsistent -- is GARBAGE_ARGS.  The
         * connection stays up: the xid is known, so a reply is possible and
         * required. */
        | ArgsTruncated(_) => GarbageArgs
        | ArgsTrailingGarbage(_) => GarbageArgs
        | StringLenOverflow => GarbageArgs
        | StringLenBeyondMessage => GarbageArgs

        /* RFC 4506: a counted field declared with a bound may not exceed it,
         * and the decoder is required to treat an over-bound count as
         * invalid rather than trusting it. */
        | StringExceedsBound => GarbageArgs
        | OpaqueExceedsBound => GarbageArgs
        | ArrayCountExceedsBound => GarbageArgs
        | ArrayCountHuge => GarbageArgs

        /* RFC 4506: a discriminated union whose discriminant matches no arm
         * and which declares no default is invalid. */
        | DiscriminantUnmatched => GarbageArgs

        /* RFC 4506: bool is an enum over {0,1}; an enum may only carry a
         * declared value.  Anything else is invalid. */
        | BoolNotZeroOrOne => GarbageArgs
        | EnumNotDeclared => GarbageArgs

        /* Record marking defects destroy the message framing itself, so no
         * xid is recoverable and no reply can be addressed.  The server must
         * drop the connection.  Critically it must NOT wait indefinitely for
         * bytes that a hostile length claims are coming. */
        | RecordMarkHuge => Closed
        | RecordMarkZeroLength => Closed

        /* Same conclusion by a different route.  The framing here is never
         * malformed -- it is simply unbounded -- so the receiver has to stop
         * of its own accord.  Once it does, the partial record is discarded
         * and the message it belonged to never existed, so there is no xid
         * to address a reply to and the connection must go.  The failure
         * this catches is the one that costs memory rather than correctness:
         * accumulating fragments until the process dies. */
        | ReassemblyCapExceeded => Closed

        /* RPCSEC_GSS.  The handshake rides on the program's NULL procedure
         * and establishes a context; a DATA call against an established
         * context with a good verifier is an ordinary successful call. */
        | GssInitEstablishes => Success
        | GssInitContinues => Success
        | GssDataValid => Success

        /* A mechanism-level failure during context establishment leaves no
         * context to talk to. */
        | GssInitMechFails => AuthError

        /* RFC 2203 section 5: the credential names a version and a procedure;
         * anything outside the defined set is a bad credential. */
        | GssCredVersionWrong(_) => AuthError
        | GssProcUnknown(_) => AuthError

        /* RFC 2203 section 5.3.1 defines exactly three services.  A value
         * outside them is a credential asking for something that does not
         * exist, which RFC 5531 answers by refusing it as too weak rather
         * than by picking a service the caller did not name. */
        | GssServiceUnknown(_) => AuthError

        /* No usable security context: either it never existed, or the caller
         * cannot prove it holds it. */
        | GssHandleUnknown => AuthError
        | GssVerifierNotGss => AuthError
        | GssMicWrong => AuthError

        /* RFC 2203 section 5.3.3.1: a request whose sequence number falls
         * outside the window, or repeats one already seen, is discarded in
         * silence -- answering it would itself be an oracle for an attacker
         * replaying traffic. */
        | GssSeqReplayed => NoReply

        /* RFC 2203 section 5.3.2.2: under the integrity service the call
         * arguments travel as rpc_gss_integ_data, whose databody is
         * seq_num || args and whose checksum is a MIC over that databody.  A
         * well-formed one is an ordinary call, and the results come back
         * wrapped the same way (section 5.3.3.2). */
        | GssIntegDataValid => Success

        /* RFC 2203 section 5.3.3.4.2: "When GSS_VerifyMIC() is called to
         * verify the call arguments (service is rpc_gss_svc_integrity), a
         * failure results in an RPC response with a reply status of
         * MSG_ACCEPTED, and an acceptance status of GARBAGE_ARGS."  Note the
         * deliberate contrast with the *header* verifier failing, which is
         * MSG_DENIED / AUTH_ERROR: an argument the server cannot authenticate
         * is an undecodable argument, not an unauthenticated caller. */
        | GssIntegChecksumWrong => GarbageArgs

        /* RFC 2203 section 5.3.2.2 requires the seq_num embedded in the
         * databody to equal the one in the credential.  A databody that
         * violates that is not a well-formed rpc_gss_data_t, so it fails
         * argument decoding -- the same GARBAGE_ARGS outcome section 5.3.3.4.2
         * gives every argument-level integrity failure. */
        | GssIntegSeqMismatch => GarbageArgs

        /* RFC 2203 section 5.3.2.3: under the privacy service the arguments
         * travel as rpc_gss_priv_data, a single opaque holding the sealed
         * token of seq_num || args.  A well-formed one is an ordinary call
         * and the results come back sealed the same way (section 5.3.3.3). */
        | GssPrivDataValid => Success

        /* A token that will not unseal is the privacy analogue of a failed
         * argument MIC, and section 5.3.3.4.2 gives it the same answer: the
         * caller authenticated (the header verifier is cleartext-signed and
         * checked first), but its arguments did not survive.  MSG_ACCEPTED
         * with GARBAGE_ARGS, not MSG_DENIED. */
        | GssPrivSealCorrupt => GarbageArgs

        /* Section 5.3.2.3 requires the seq_num sealed inside the token to
         * equal the credential's.  Sealing it is the point: the header seq is
         * cleartext and editable, the sealed one is not, so a disagreement
         * between them is exactly the tampering the service exists to catch
         * -- and it fails argument decoding like any other. */
        | GssPrivSeqMismatch => GarbageArgs

        /* RFC 2203 section 5.4: the client retires a context with a control
         * message carrying gss_proc RPCSEC_GSS_DESTROY over NULLPROC and no
         * arguments; "the server sends a response as it would to a data
         * request". */
        | GssDestroyContext => Success

        /* RFC 2203 section 5.4: "The sequence number in the request must be
         * valid, and the header checksum in the verifier must be valid, for
         * the server to accept the message."  DESTROY is authenticated like
         * any other request -- otherwise anyone who can guess a handle can
         * retire someone else's context.  An unverifiable one is denied, per
         * section 5.3.3.4.2. */
        | GssDestroyUnauthenticated => AuthError

        /* RFC 2203 section 5.3.3.3: "When the client's sequence number
         * exceeds the maximum the server will allow, the server will reject
         * the request with the reason RPCSEC_GSS_CTXPROBLEM."  A rejection,
         * not a silent drop: the client is told to refresh the context and
         * retry, which it cannot infer from silence.  This is the one place
         * in the sequence-number rules where the answer is an error rather
         * than nothing, and it is the easy one to collapse into the general
         * "bad seq_num, discard" case. */
        | GssSeqAboveMax => AuthError

        /* RFC 2203 section 5.3.3.1: "If a sequence number higher than the
         * last number seen is received ... the window is moved forward to the
         * new sequence number", and "a consequence of the silent discard is
         * that clients may increment the seq_num by more than one".  A jump
         * clear of the window is therefore ordinary traffic, not an attack:
         * it just resets the window rather than sliding it. */
        | GssSeqWindowJump => Success

        /* RFC 2203 section 5.3.3.1: "If the sequence number received falls
         * below this range, it is silently discarded" -- the same silence a
         * replay gets, and for the same reason (section 5.3.3.1: the server
         * cannot tell a reordering from an attack, and answering would tell
         * an attacker which it was). */
        | GssSeqTooOld => NoReply

        /* RFC 2203 section 5.3.3.1: "If the sequence number is within this
         * range, and the server has not seen it, the request is accepted."
         * The window exists precisely so that requests may arrive out of
         * order -- section 5.2.3.1 advertises seq_window as the number of
         * requests that "may be out of order" -- so an unseen in-window
         * number is an ordinary request, not a stale one. */
        | GssSeqOutOfOrder => Success

        /* RFC 2203 section 5.3.3.3: "If there is a problem with the
         * credential, such a bad length, illegal control procedure, or an
         * illegal service, the appropriate auth_stat status is AUTH_BADCRED."
         * A credential that stops mid-field, or whose handle<> claims more
         * bytes than the credential contains, is exactly a bad length. */
        | GssCredTruncated => AuthError
        | GssCredHandleOverruns => AuthError

        /* A CONTINUE_INIT whose handle names no context the server holds is a
         * problem with the credential (RFC 2203 section 5.3.3.3), so the call
         * is denied.  Note that section 5.2.3.2 forbids the two RPCSEC_GSS
         * auth_stat values on a context-creation response, which is why the
         * model requires only AUTH_ERROR and the driver does not compare the
         * sub-status. */
        /* RFC 2203 section 5.2.3.2: "MSG_DENIED could be returned because the
         * server's RPC implementation does not recognize the RPCSEC_GSS
         * security flavor.  RFC 1831 does not specify the appropriate reply
         * status in this instance, but common implementation practice appears
         * to be to return a rejection status of AUTH_ERROR with an auth_stat
         * of AUTH_REJECTEDCRED."  A server with no mechanism configured must
         * therefore say so, both to a context-creation request and to a data
         * request -- the two entry points, and the reason this defect is
         * parameterised.  Answering either one as though the flavor were
         * understood would leave the client waiting for a context it will
         * never get. */
        | GssNoMechanism(_) => AuthError

        | GssContinueInitUnknownHandle => AuthError

        /* The GSS token travels in the call ARGUMENTS (rpc_gss_init_arg,
         * RFC 2203 section 5.2.2), not in the credential, so a token that
         * cannot be decoded is an argument-decoding failure: GARBAGE_ARGS per
         * RFC 5531 section 9.  Section 5.2.3.2 explicitly contemplates this
         * ("An MSG_ACCEPTED reply (to a creation request) with an acceptance
         * status of other than SUCCESS ... is formulated as usual") and just
         * as explicitly rules out the alternative libevpl reaches for:
         * "neither of these two [RPCSEC_GSS_CREDPROBLEM and
         * RPCSEC_GSS_CTXPROBLEM] can be returned in responses to context
         * creation requests."  Same split the model already draws for the
         * integrity service: a bad credential is an unauthenticated caller,
         * a bad argument is an undecodable argument. */
        | GssInitTokenMalformed(_) => GarbageArgs
        | GssContinueInitTokenMalformed => GarbageArgs

        /* A mechanism-level failure, modelled the same way as
         * GssInitMechFails above whether or not the mechanism also produced a
         * token: the token is the mechanism's business, and a context that
         * failed to establish leaves nothing to talk to either way. */
        | GssInitMechFailsWithToken => AuthError

        /* RFC 2203 section 5.3.2.2 fixes the shape of the integrity call
         * arguments; anything that does not decode as an rpc_gss_integ_data
         * is undecodable arguments, which section 5.3.3.4.2 and RFC 5531
         * section 9 both answer with GARBAGE_ARGS. */
        | GssIntegFramingBad(_) => GarbageArgs

        /* A procedure that takes no arguments is still a procedure: under
         * integrity its databody is just the seq_num (RFC 2203 section
         * 5.3.2.2), and the reply comes back wrapped the same way. */
        | GssIntegEmptyArgs => Success

        /* Record marking (RFC 5531 section 10) is independent of the security
         * flavor, so an integrity call delivered in pieces must be treated
         * exactly like one delivered whole. */
        | GssIntegSplitAcrossFragments => Success

        /* RFC 2203 section 5.3.3.4.1: "When GSS_GetMIC() is called to sign
         * the call results (service is rpc_gss_svc_integrity), a failure
         * results in no RPC response being sent."  Silence is the specified
         * behaviour: a reply the server could not sign is worse than no
         * reply, because a client that accepted it would have taken
         * unauthenticated results on an authenticated channel. */
        | GssIntegReplyMicFails => NoReply
        | GssIntegReplyMicOversize => NoReply

        /* Not a defect: a correctly framed call split across several
         * fragments is legal and must succeed.  Included here so the
         * framing path gets positive coverage from the same harness. */
        | CallSplitAcrossFragments(_) => Success

        /* Also not a defect: an extreme fragment count is still legal
         * framing, and the flattening it forces must be transparent. */
        | CallSplitPathological => Success
    }

    // ------------------------------------------------------------------
    // Case generation
    // ------------------------------------------------------------------

    pure val TARGETS = Set(TScalars, TBytes, TArrays, TStrict)

    /// Defect instances.  Where a defect carries a number, a few
    /// representative values are enumerated rather than the whole domain:
    /// the driver's encoding is identical for all of them, so extra values
    /// buy no new code paths.
    pure val DEFECTS = Set(
        NoDefect,
        RpcVersWrong(0), RpcVersWrong(1), RpcVersWrong(3), RpcVersWrong(4294967295),
        ProgramUnknown,
        VersionUnsupported(0), VersionUnsupported(2), VersionUnsupported(4294967295),
        ProcedureUnknown(10), ProcedureUnknown(4294967295),
        ProcedureNull,
        AuthFlavorUnsupported(2), AuthFlavorUnsupported(42),
        CredBodyOverlong,
        AuthSysValid,
        GssInitEstablishes, GssInitContinues, GssInitMechFails,
        GssDataValid,
        GssCredVersionWrong(0), GssCredVersionWrong(2),
        GssProcUnknown(4), GssProcUnknown(99),
        GssServiceUnknown(0), GssServiceUnknown(4),
        GssHandleUnknown, GssVerifierNotGss,
        GssMicWrong, GssSeqReplayed,
        GssIntegDataValid, GssIntegChecksumWrong, GssIntegSeqMismatch,
        GssPrivDataValid, GssPrivSealCorrupt, GssPrivSeqMismatch,
        GssDestroyContext, GssDestroyUnauthenticated,
        GssSeqAboveMax, GssSeqWindowJump, GssSeqTooOld, GssSeqOutOfOrder,
        GssCredTruncated, GssCredHandleOverruns,
        GssNoMechanism(0), GssNoMechanism(1),
        GssContinueInitUnknownHandle,
        GssInitTokenMalformed(0), GssInitTokenMalformed(1),
        GssContinueInitTokenMalformed,
        GssInitMechFailsWithToken,
        GssIntegFramingBad(0), GssIntegFramingBad(1), GssIntegFramingBad(2),
        GssIntegFramingBad(3), GssIntegFramingBad(4),
        GssIntegEmptyArgs, GssIntegSplitAcrossFragments,
        GssIntegReplyMicFails, GssIntegReplyMicOversize,
        ArgsTruncated(1), ArgsTruncated(4), ArgsTruncated(8),
        ArgsTrailingGarbage(4), ArgsTrailingGarbage(64),
        StringLenOverflow,
        StringLenBeyondMessage,
        StringExceedsBound,
        OpaqueExceedsBound,
        ArrayCountExceedsBound,
        ArrayCountHuge,
        DiscriminantUnmatched,
        BoolNotZeroOrOne,
        EnumNotDeclared,
        RecordMarkHuge,
        RecordMarkZeroLength,
        CallSplitAcrossFragments(2), CallSplitAcrossFragments(3),
        CallSplitAcrossFragments(16),
        CallSplitPathological,
        ReassemblyCapExceeded
    )

    /// Apply one specific case, recording the required outcome alongside it.
    action use(d: Defect, t: Target): bool = all {
        current' = { defect: d, target: t },
        expected' = required(d)
    }

    action pick = {
        nondet d = DEFECTS.oneOf()
        nondet t = TARGETS.oneOf()
        use(d, t)
    }

    action init = use(NoDefect, TScalars)
    action step = pick

    // ------------------------------------------------------------------
    // Invariants
    // ------------------------------------------------------------------

    /// Every defect in the taxonomy has a required outcome.  This is a
    /// totality check on `required`: Quint's match is exhaustive, so a new
    /// variant added to Defect without a corresponding rule fails to
    /// typecheck rather than silently defaulting.
    val outcomeIsSpecified = match expected {
        | Success => true
        | ProgUnavail => true
        | ProgMismatch(r) => r.lo <= r.hi
        | ProcUnavail => true
        | GarbageArgs => true
        | RpcMismatch(r) => r.lo <= r.hi
        | AuthError => true
        | Closed => true
        | NoReply => true
    }

    /// A defect that destroys the framing cannot be answered, and every
    /// defect that preserves it must be: an RPC server may not silently
    /// drop a call it was able to parse the header of.  This is the
    /// property that catches "closes the connection instead of replying".
    val answerableDefectsAreAnswered =
        match current.defect {
            | RecordMarkHuge => expected == Closed
            | RecordMarkZeroLength => expected == Closed
            /* Silence here is a decision, not a missing answer: RFC 2203
             * names each of these as a case the server answers by sending
             * nothing at all. */
            | ReassemblyCapExceeded => expected == Closed
            /* Silence here is a decision, not a missing answer. */
            | GssSeqReplayed => expected == NoReply
            | GssSeqTooOld => expected == NoReply
            | GssIntegReplyMicFails => expected == NoReply
            | GssIntegReplyMicOversize => expected == NoReply
            | _ => expected != Closed
        }

    val safety = outcomeIsSpecified and answerableDefectsAreAnswered

    // ------------------------------------------------------------------
    // Scenario tests: the outcomes most likely to be got wrong
    // ------------------------------------------------------------------

    /// The distinction clients rely on to negotiate versions.
    run programVsVersionTest =
        init
            .then(use(ProgramUnknown, TScalars))
            .expect(expected == ProgUnavail)
            .then(use(VersionUnsupported(2), TScalars))
            .expect(expected == ProgMismatch({ lo: 1, hi: 1 }))

    run nullProcedureIsAlwaysAvailableTest =
        init
            .then(use(ProcedureNull, TScalars))
            .expect(expected == Success)

    /// Decodable-but-invalid payloads must be answered, not dropped.
    run payloadDefectsAreAnsweredTest =
        init
            .then(use(StringLenOverflow, TBytes))
            .expect(expected == GarbageArgs)
            .then(use(StringExceedsBound, TBytes))
            .expect(expected == GarbageArgs)
            .then(use(ArrayCountExceedsBound, TArrays))
            .expect(expected == GarbageArgs)
            .then(use(DiscriminantUnmatched, TStrict))
            .expect(expected == GarbageArgs)

    /// The two GSS outcomes most easily got wrong: a service the credential
    /// names but that does not exist is refused rather than silently
    /// downgraded to one that does, and a replay is answered with silence
    /// rather than an error that would confirm the replay landed.
    run gssOutcomesTest =
        init
            .then(use(GssServiceUnknown(4), TScalars))
            .expect(expected == AuthError)
            .then(use(GssSeqReplayed, TScalars))
            .expect(expected == NoReply)
            .then(use(GssDataValid, TScalars))
            .expect(expected == Success)

    /// Privacy repeats the integrity split, and adds the one thing integrity
    /// cannot test: the seq is *sealed*, so a header that disagrees with it is
    /// evidence of tampering rather than of a mis-built client.
    run gssPrivacyOutcomesTest =
        init
            .then(use(GssPrivDataValid, TScalars))
            .expect(expected == Success)
            .then(use(GssPrivSealCorrupt, TScalars))
            .expect(expected == GarbageArgs)
            .then(use(GssPrivSeqMismatch, TScalars))
            .expect(expected == GarbageArgs)

    /// The integrity service splits one failure into two different replies,
    /// and getting them the same way round is the easy mistake: a bad *header*
    /// verifier means the caller is not authenticated (MSG_DENIED), while a bad
    /// *argument* checksum means the arguments did not survive (GARBAGE_ARGS).
    run gssIntegrityOutcomesTest =
        init
            .then(use(GssIntegDataValid, TScalars))
            .expect(expected == Success)
            .then(use(GssIntegChecksumWrong, TScalars))
            .expect(expected == GarbageArgs)
            .then(use(GssMicWrong, TScalars))
            .expect(expected == AuthError)

    /// The replay window has three outcomes, not two, and which one applies
    /// turns only on where the sequence number falls.  Getting this wrong in
    /// the safe-looking direction -- discarding anything unexpected -- loses
    /// the one case RFC 2203 requires an answer for, and getting it wrong in
    /// the other direction turns the window into a replay oracle.
    run gssSequenceWindowTest =
        init
            /* Ahead of the window: accepted, the window follows. */
            .then(use(GssSeqWindowJump, TScalars))
            .expect(expected == Success)
            /* Inside the window and not yet seen: accepted, out of order. */
            .then(use(GssSeqOutOfOrder, TScalars))
            .expect(expected == Success)
            /* Inside the window and already seen: silence. */
            .then(use(GssSeqReplayed, TScalars))
            .expect(expected == NoReply)
            /* Below the window: silence. */
            .then(use(GssSeqTooOld, TScalars))
            .expect(expected == NoReply)
            /* Above MAXSEQ: an error, and the only one of the five. */
            .then(use(GssSeqAboveMax, TScalars))
            .expect(expected == AuthError)

    /// A reply the server cannot sign is not a reply.  The tempting
    /// alternative -- ship the results unsigned -- is the one outcome the
    /// integrity service exists to prevent.
    run gssIntegrityReplySigningTest =
        init
            .then(use(GssIntegReplyMicFails, TScalars))
            .expect(expected == NoReply)
            .then(use(GssIntegReplyMicOversize, TScalars))
            .expect(expected == NoReply)

    /// Where the malformation sits decides the answer: a credential the server
    /// cannot parse means it cannot identify the caller, while a token it
    /// cannot parse is just an undecodable argument.
    run gssContextCreationFramingTest =
        init
            .then(use(GssCredTruncated, TScalars))
            .expect(expected == AuthError)
            .then(use(GssInitTokenMalformed(1), TScalars))
            .expect(expected == GarbageArgs)

    /// Destroying a context is an authenticated operation, so an unverifiable
    /// DESTROY must be refused rather than honoured.
    run gssDestroyIsAuthenticatedTest =
        init
            .then(use(GssDestroyContext, TScalars))
            .expect(expected == Success)
            .then(use(GssDestroyUnauthenticated, TScalars))
            .expect(expected == AuthError)

    run framingDefectsCloseTest =
        init
            .then(use(RecordMarkHuge, TScalars))
            .expect(expected == Closed)
            .then(use(CallSplitAcrossFragments(16), TScalars))
            .expect(expected == Success)

    /// Fragmenting is legal without limit; accumulating is not.  The pair
    /// that is easy to conflate: a legal split must succeed however many
    /// pieces it arrives in, while a split whose pieces are individually
    /// just as legal must still be cut off once their total passes what the
    /// receiver will hold.  Getting this wrong in the permissive direction
    /// is a memory-exhaustion hole reachable by any unauthenticated peer.
    run reassemblyIsBoundedTest =
        init
            .then(use(CallSplitPathological, TBytes))
            .expect(expected == Success)
            .then(use(ReassemblyCapExceeded, TBytes))
            .expect(expected == Closed)
}
