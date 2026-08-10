// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: BSD-3-Clause

/**
 * values.qnt -- the positive half of the XDR conformance matrix.
 *
 * Each state picks one procedure of CONFORMANCE_PROGRAM (conformance.x) and
 * one boundary-value class for each of that procedure's fields.  The expected
 * result is always Echo: a well-formed call must come back byte-identical,
 * because every handler in the test server echoes its argument.
 *
 * The classes are SYMBOLIC on purpose -- "U32Max", not 4294967295.  The C
 * driver owns the mapping from class to bytes/values, so this model stays
 * readable and stays out of the business of encoding XDR.
 *
 * The bounds declared here (BoundedMax, FixedOpaqueLen, FixedArrayLen) must
 * match the consts in conformance.x.  defects.qnt derives its
 * bound-exceeding cases from the same numbers, which is the main reason the
 * positive and negative matrices live in one model rather than two ad-hoc
 * lists.
 *
 *   quint test values.qnt
 *   quint run values.qnt --invariant=wellFormed
 *   ./regen_cases.sh      (in the parent directory)
 */
module xdr_values {

    // Mirrors of the conformance.x consts.
    pure val BoundedMax = 8
    pure val FixedOpaqueLen = 16
    pure val FixedArrayLen = 4

    /// Procedures of CONFORMANCE_V1, by name.
    type Proc =
        | EchoScalars
        | EchoBytes
        | EchoZbytes
        | EchoArrays
        | EchoUnion
        | EchoOptional
        | EchoList
        | EchoNested

    /// Boundary classes for the numeric scalars.  Signed types carry their
    /// min so the sign bit and two's-complement encoding are exercised;
    /// floats carry a NaN, which the driver compares bitwise (a value
    /// comparison would spuriously fail).
    type IntCls = | I32Min | I32Neg1 | I32Zero | I32One | I32Max
    type UintCls = | U32Zero | U32One | U32Max
    type LongCls = | I64Min | I64Neg1 | I64Zero | I64Max
    type UlongCls = | U64Zero | U64One | U64Max
    type FloatCls = | FZero | FNegZero | FOne | FNegOne | FLarge | FNan
    type BoolCls = | BFalse | BTrue
    type ColorCls = | ColRed | ColGreen | ColBlue

    /// Length classes for counted things.  Empty and one are the classic
    /// off-by-one traps; Unaligned forces XDR's 4-byte padding; AtBound is
    /// the largest value a bounded field may legally carry.
    type LenCls =
        | LEmpty
        | LOne
        | LUnaligned
        | LAligned
        | LAtBound
        | LLarge

    type OptCls = | OptAbsent | OptPresent
    type ArmCls = | ArmNone | ArmInt | ArmStr | ArmPt

    /// How the call negotiates RPC-over-RDMA data placement.  These map onto
    /// the (ddp, max_rdma_write_chunk, write_chunk_iov, max_rdma_reply_chunk)
    /// arguments every generated send_call_* takes and which the driver
    /// previously always passed as zero -- leaving the whole chunk-negotiation
    /// path in rpc2.c unexercised.
    ///
    /// They are inert on a stream transport (rpc2.c gates all of it on
    /// conn->rdma), so the same case table is meaningful on both transports:
    /// over TCP these degrade to the inline path, over RDMA-on-TCP they select
    /// genuinely different code.
    /// The last two are both RFC 8166 Write chunks -- storage the requester
    /// offers for a DDP-eligible result -- and differ only in who owns the
    /// buffer.  They are separate classes because that ownership split is
    /// exactly what rpc2.c branches on, and getting it wrong is a leak on one
    /// side and a double free on the other.
    type ChunkCls =
        | ChunkNone        /* inline: no direct placement at all         */
        | ChunkDdp         /* direct placement on, sizes left to libevpl */
        | ChunkReply       /* reply travels in a reply chunk             */
        | ChunkReadInto    /* write chunk, caller-owned destination      */
        | ChunkWriteAlloc  /* write chunk, destination allocated by libevpl */
        | ChunkWriteExact  /* write chunk sized exactly to the result    */

    /// One generated test case.  Only the fields relevant to `proc` are
    /// meaningful; the driver ignores the rest.
    type Case = {
        proc: Proc,
        i: IntCls,
        u: UintCls,
        l: LongCls,
        ul: UlongCls,
        f: FloatCls,
        b: BoolCls,
        col: ColorCls,
        strLen: LenCls,
        opaqueLen: LenCls,
        boundedLen: LenCls,
        arrLen: LenCls,
        optPresent: OptCls,
        arm: ArmCls,
        depth: LenCls,
        chunk: ChunkCls
    }

    pure val DEFAULT_CASE: Case = {
        proc: EchoScalars,
        i: I32Zero, u: U32Zero, l: I64Zero, ul: U64Zero,
        f: FZero, b: BFalse, col: ColRed,
        strLen: LEmpty, opaqueLen: LEmpty, boundedLen: LEmpty,
        arrLen: LEmpty, optPresent: OptAbsent, arm: ArmNone, depth: LEmpty,
        chunk: ChunkNone
    }

    var current: Case

    // ------------------------------------------------------------------
    // Case generation
    // ------------------------------------------------------------------

    pure val INT_CLASSES = Set(I32Min, I32Neg1, I32Zero, I32One, I32Max)
    pure val UINT_CLASSES = Set(U32Zero, U32One, U32Max)
    pure val LONG_CLASSES = Set(I64Min, I64Neg1, I64Zero, I64Max)
    pure val ULONG_CLASSES = Set(U64Zero, U64One, U64Max)
    pure val FLOAT_CLASSES = Set(FZero, FNegZero, FOne, FNegOne, FLarge, FNan)
    pure val BOOL_CLASSES = Set(BFalse, BTrue)
    pure val COLOR_CLASSES = Set(ColRed, ColGreen, ColBlue)
    pure val ARM_CLASSES = Set(ArmNone, ArmInt, ArmStr, ArmPt)
    pure val OPT_CLASSES = Set(OptAbsent, OptPresent)

    /// Arming a destination buffer only means something when the reply
    /// actually carries a zero-copy payload to place into it, which among
    /// these procedures is ECHO_ZBYTES alone.  The others take the shapes that
    /// apply to any reply.
    pure val CHUNK_CLASSES = Set(ChunkNone, ChunkDdp, ChunkReply)

    /// The write-chunk classes offer storage for the reply's DDP-eligible
    /// result, so they only mean anything for a procedure whose reply has one
    /// -- ECHO_ZBYTES alone here, which writeChunkOnlyWhereItApplies below
    /// enforces.
    ///
    /// ChunkReadInto was held out of generation for a while because it failed
    /// the echo oracle; the cause was the missing take_read_chunk call in the
    /// test's own handler rather than anything in the transport, and with that
    /// fixed it belongs in the matrix.
    /// ChunkWriteExact is the at-bound length class for chunk sizing: the
    /// chunk offered is exactly as large as the result placed in it, which is
    /// the one case where a segment is consumed to its last byte rather than
    /// capped short.  The others all offer more room than the result needs.
    pure val WRITE_CHUNK_CLASSES = Set(ChunkReadInto, ChunkWriteAlloc,
                                       ChunkWriteExact)

    pure val CHUNK_CLASSES_ZEROCOPY = CHUNK_CLASSES.union(WRITE_CHUNK_CLASSES)

    /// Unbounded counted fields may take any length class; LAtBound is only
    /// meaningful for a field that actually declares a bound, but it is a
    /// legal (and interesting) length for an unbounded one too.
    pure val LEN_CLASSES = Set(LEmpty, LOne, LUnaligned, LAligned, LAtBound, LLarge)

    /// Bounded fields (opaque<8>, uint32_t<8>) may not exceed the bound, so
    /// LLarge is excluded here -- exceeding it is a defect, and lives in
    /// defects.qnt rather than being silently generated as a "positive" case.
    pure val BOUNDED_LEN_CLASSES = Set(LEmpty, LOne, LUnaligned, LAligned, LAtBound)

    action pick = {
        nondet p = Set(EchoScalars, EchoBytes, EchoZbytes, EchoArrays,
                       EchoUnion, EchoOptional, EchoList, EchoNested).oneOf()
        nondet vi = INT_CLASSES.oneOf()
        nondet vu = UINT_CLASSES.oneOf()
        nondet vl = LONG_CLASSES.oneOf()
        nondet vul = ULONG_CLASSES.oneOf()
        nondet vf = FLOAT_CLASSES.oneOf()
        nondet vb = BOOL_CLASSES.oneOf()
        nondet vcol = COLOR_CLASSES.oneOf()
        nondet vstr = LEN_CLASSES.oneOf()
        nondet vopq = LEN_CLASSES.oneOf()
        nondet vbnd = BOUNDED_LEN_CLASSES.oneOf()
        nondet varr = LEN_CLASSES.oneOf()
        nondet vopt = OPT_CLASSES.oneOf()
        nondet varm = ARM_CLASSES.oneOf()
        nondet vdepth = LEN_CLASSES.oneOf()
        nondet vchunk = (if (p == EchoZbytes) CHUNK_CLASSES_ZEROCOPY
                         else CHUNK_CLASSES).oneOf()
        current' = {
            proc: p, i: vi, u: vu, l: vl, ul: vul, f: vf, b: vb, col: vcol,
            strLen: vstr, opaqueLen: vopq, boundedLen: vbnd, arrLen: varr,
            optPresent: vopt, arm: varm, depth: vdepth, chunk: vchunk
        }
    }

    action init = all { current' = DEFAULT_CASE }
    action step = pick

    // ------------------------------------------------------------------
    // Invariant: every generated case is legal input
    // ------------------------------------------------------------------

    /// A bounded field must never be asked to carry more than its bound --
    /// otherwise this model would be emitting cases that RFC 4506 requires
    /// the server to REJECT, while labelling them as expected-to-echo.
    val boundedWithinBound =
        BOUNDED_LEN_CLASSES.contains(current.boundedLen)

    /// A case may only offer a write chunk for a procedure whose reply carries
    /// a zero-copy payload; anywhere else the chunk would go unused and the
    /// case would silently be testing the inline path instead.
    val writeChunkOnlyWhereItApplies =
        WRITE_CHUNK_CLASSES.contains(current.chunk) implies current.proc == EchoZbytes

    val wellFormed = boundedWithinBound and writeChunkOnlyWhereItApplies

    // ------------------------------------------------------------------
    // Scenario tests
    // ------------------------------------------------------------------

    run scalarExtremesTest =
        init
            .then(all {
                current' = DEFAULT_CASE.with("proc", EchoScalars)
                    .with("i", I32Min).with("u", U32Max)
                    .with("l", I64Min).with("ul", U64Max).with("f", FNan)
            })
            .expect(wellFormed)

    run boundedNeverExceedsTest =
        init
            .then(pick)
            .expect(boundedWithinBound)
            .then(pick)
            .expect(boundedWithinBound)
}
