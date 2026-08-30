#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

"""Convert Quint ITF traces of core.qnt into the C program table.

The RPC2 converters turn a trace into a set of independent cases.  This one
turns it into a set of PROGRAMS: core.qnt's states are the steps of a
sequence, delimited by OpReset, and the C driver in core_conformance.c is an
interpreter for them.  The obligations a quiesce carries travel in side tables
that each step indexes, so a step stays a fixed-size struct.

Every tag the model can emit must appear in the tables below.  An unknown tag
is a hard error rather than a silently skipped step: if the model gains an op,
the driver needs an arm for it, and failing loudly here is what forces that.

The op-coverage check at the end is the other half of that.  A trace is a
sample, so a seed bump or a quint release that samples differently could drop
an operation entirely and leave a smaller suite that still looks green; an op
the model declares but no program exercises fails generation instead.
"""

import json
import sys

OPS = [
    "OpReset",
    "OpAddTimer",
    "OpRemoveTimer",
    "OpDefer",
    "OpDeferTwice",
    "OpDeferReentrant",
    "OpAddDoorbell",
    "OpRingDoorbell",
    "OpRingDoorbellTwice",
    "OpRemoveDoorbell",
    "OpRemoveDoorbellInCallback",
    "OpRemoveDeferral",
    "OpRemoveDeferralIdle",
    "OpRequestSendNotify",
    "OpSetLoopHooks",
    "OpClearLoopHooks",
    "OpAddPoll",
    "OpRemovePoll",
    "OpActivity",
    "OpPollPin",
    "OpPollUnpin",
    "OpListen",
    "OpStopListen",
    "OpBindPair",
    "OpConnect",
    "OpSend",
    "OpClose",
    "OpFinish",
    "OpOpenQueue",
    "OpCloseQueue",
    "OpBlockRead",
    "OpBlockWrite",
    "OpBlockWriteSync",
    "OpBlockFlush",
    "OpBlockWriteZeroes",
    "OpBlockWriteZeroesAll",
    "OpBlockDiscard",
    "OpQuiesce",
]

TIMER_KINDS = ["TOneshot", "TPeriodic", "TRearm"]
DELAYS = ["DFast", "DSlow"]
BUDGETS = ["QShort", "QLong"]
SIZES = ["SzTiny", "SzSmall", "SzMedium", "SzLarge"]
DRAINS = ["DrainRecv", "DrainRecvV", "DrainPeek", "DrainPeekV"]
TRANSPORTS = ["TStreamInproc", "TDatagramInproc", "TStreamTcp", "TStreamUnix",
              "TDatagramUdp"]
SENDS = ["SendBuf", "SendV", "SendVTakeRef", "SendToEp", "SendToEpV",
         "SendReserveCommit", "SendGlobal"]
SEGS = ["BSeg1", "BSeg4", "BSeg16"]
EVENTS = ["EvTimer", "EvDeferral", "EvDoorbell",
          "EvConnected", "EvDisconnected", "EvRecv",
          "EvPollEnter", "EvPollExit", "EvPoll", "EvRecvMsg", "EvSent",
          "EvHook", "EvBlock"]
MULTS = ["MExactly", "MAtLeast"]

# OpReset is the program delimiter, not something the driver runs, so it is
# excluded from the coverage requirement below along with nothing else: every
# other op must be reached by some program.
# SendToEp/SendToEpV are declared by the model but deliberately not generated
# (see SendMode in core.qnt), so send-mode coverage is not required the way op
# coverage is.
COVERAGE_EXEMPT = {"OpReset"}


class TagError(Exception):
    pass


def tag_of(v):
    if not isinstance(v, dict) or "tag" not in v:
        raise TagError("expected a tagged variant, got %r" % (v,))
    return v["tag"]


def index_of(table, tag, what):
    try:
        return table.index(tag)
    except ValueError:
        raise TagError("unknown %s tag %r; add it to itf_to_core_cases.py "
                       "and to the C driver" % (what, tag))


def itf_int(v):
    if isinstance(v, dict) and "#bigint" in v:
        return int(v["#bigint"])
    if isinstance(v, int):
        return v
    raise TagError("expected an integer, got %r" % (v,))


def itf_set(v):
    if not isinstance(v, dict) or "#set" not in v:
        raise TagError("expected a set, got %r" % (v,))
    return v["#set"]


def read_expects(state):
    """Expectations, canonically ordered.

    Quint emits a set, whose serialized order is not something to depend on.
    Sorting makes two structurally identical programs compare equal, which is
    what the de-duplication below relies on.
    """
    out = []
    for e in itf_set(state["expects"]):
        out.append((index_of(EVENTS, tag_of(e["kind"]), "event"),
                    itf_int(e["slot"]),
                    index_of(MULTS, tag_of(e["mult"]), "multiplicity"),
                    itf_int(e["count"])))
    return sorted(out)


def read_orders(state):
    out = []
    for o in itf_set(state["orders"]):
        out.append((index_of(EVENTS, tag_of(o["firstKind"]), "event"),
                    itf_int(o["firstSlot"]),
                    index_of(EVENTS, tag_of(o["thenKind"]), "event"),
                    itf_int(o["thenSlot"])))
    return sorted(out)


def read_step(state):
    cur = state["current"]
    op = tag_of(cur["op"])

    return (op,
            index_of(OPS, op, "op"),
            itf_int(cur["slot"]),
            index_of(TIMER_KINDS, tag_of(cur["timerKind"]), "timer kind"),
            index_of(DELAYS, tag_of(cur["delay"]), "delay class"),
            index_of(BUDGETS, tag_of(cur["budget"]), "budget"),
            itf_int(cur["conn"]),
            itf_int(cur["side"]),
            index_of(TRANSPORTS, tag_of(cur["transport"]), "transport"),
            index_of(SIZES, tag_of(cur["size"]), "size class"),
            index_of(SENDS, tag_of(cur["send"]), "send mode"),
            index_of(DRAINS, tag_of(cur["drain"]), "drain mode"),
            itf_int(cur["queue"]),
            itf_int(cur["region"]),
            index_of(SEGS, tag_of(cur["segs"]), "segment class"),
            itf_int(cur["pattern"]),
            itf_int(cur["atMs"]),
            tuple(read_expects(state)),
            tuple(read_orders(state)))


def collect(paths):
    """Split the traces into programs, de-duplicated structurally.

    A program is everything between one OpReset and the next.  Trailing steps
    after the last reset are kept: the model forces a long quiesce as the last
    op of every program, so a truncated tail is still a program that ends
    discharged.
    """
    seen, programs = set(), []

    for path in paths:
        with open(path) as f:
            trace = json.load(f)

        current = []
        for state in trace["states"]:
            step = read_step(state)
            if step[0] == "OpReset":
                if current:
                    key = tuple(current)
                    if key not in seen:
                        seen.add(key)
                        programs.append(current)
                current = []
            else:
                current.append(step)

        if current:
            key = tuple(current)
            if key not in seen:
                seen.add(key)
                programs.append(current)

    return programs


def emit_enum(out, name, prefix, tags):
    out.append("enum %s {" % name)
    for i, t in enumerate(tags):
        out.append("    %s_%s = %d," % (prefix, t.upper(), i))
    out.append("};")
    out.append("")


def main():
    if len(sys.argv) < 3:
        print("usage: %s <out.h> <traces...>" % sys.argv[0], file=sys.stderr)
        return 2

    out_path = sys.argv[1]
    programs = collect(sys.argv[2:])

    if not programs:
        print("error: no programs in the traces", file=sys.stderr)
        return 1

    # Side tables, shared across steps: the expectation lists repeat heavily
    # (most quiesces owe the same one or two callbacks), so interning them
    # keeps the generated header a fraction of the size it would otherwise be.
    expect_rows, expect_index = [], {}
    order_rows, order_index = [], {}

    def intern(rows, index, items):
        if not items:
            return 0, 0
        if items in index:
            return index[items], len(items)
        first = len(rows)
        rows.extend(items)
        index[items] = first
        return first, len(items)

    steps, prog_rows = [], []
    reached = set()

    for prog in programs:
        first_step = len(steps)
        for (op_tag, op, slot, tk, delay, budget, conn, side, transport, size,
             send, drain, queue, region, segs, pattern, at_ms,
             exps, ords) in prog:
            reached.add(op_tag)
            ef, ec = intern(expect_rows, expect_index, exps)
            of, oc = intern(order_rows, order_index, ords)
            steps.append((op, slot, tk, delay, budget, conn, side, transport,
                          size, send, drain, queue, region, segs, pattern,
                          at_ms, ef, ec, of, oc))
        prog_rows.append((first_step, len(steps) - first_step))

    missing = sorted(set(OPS) - COVERAGE_EXEMPT - reached)
    if missing:
        print("error: no generated program exercises: %s\n"
              "       widen the seeds or lengthen the traces in "
              "generate_core_cases.sh" % ", ".join(missing), file=sys.stderr)
        return 1

    o = []
    # The header written into the GENERATED file.  Fenced off because reuse
    # otherwise reads these string literals as this script's own license tags.
    # REUSE-IgnoreStart
    o.append("/* SPDX-FileCopyrightText: 2026 Ben Jarvis")
    o.append(" *")
    o.append(" * SPDX-License-Identifier: LGPL-2.1-only")
    # REUSE-IgnoreEnd
    o.append(" *")
    o.append(" * GENERATED FILE -- DO NOT EDIT.")
    o.append(" *")
    o.append(" * Produced by quint/generate_core_cases.sh from the Quint model")
    o.append(" * in quint/core.qnt.  Each program is a run of SDK operations")
    o.append(" * against a fresh evpl; core_conformance.c interprets them and")
    o.append(" * checks the callbacks that arrive against the ones each")
    o.append(" * quiesce is owed.")
    o.append(" */")
    o.append("")
    o.append("#pragma once")
    o.append("")
    o.append("#include <stdint.h>")
    o.append("")

    emit_enum(o, "core_op", "COP", OPS)
    emit_enum(o, "core_timer_kind", "CTK", TIMER_KINDS)
    emit_enum(o, "core_delay", "CDLY", DELAYS)
    emit_enum(o, "core_budget", "CBUD", BUDGETS)
    emit_enum(o, "core_transport", "CTR", TRANSPORTS)
    emit_enum(o, "core_size", "CSZ", SIZES)
    emit_enum(o, "core_send", "CSND", SENDS)
    emit_enum(o, "core_drain", "CDRN", DRAINS)
    emit_enum(o, "core_segs", "CSEG", SEGS)
    emit_enum(o, "core_event", "CEV", EVENTS)

    # The driver indexes per-event-kind arrays by this, so it is emitted
    # rather than restated there: a count that has to be kept in step by hand
    # is one that eventually is not, and the failure mode is writing past the
    # end of the check tables.
    o.append("#define CORE_NUM_EVENT_KIND %d" % len(EVENTS))
    o.append("")
    emit_enum(o, "core_mult", "CMUL", MULTS)

    o.append("/* One obligation: `count` occurrences of (kind, slot), exactly")
    o.append(" * or at least.  For CEV_EVRECV an occurrence is a BYTE and not")
    o.append(" * a callback, so `count` is wide enough for a payload. */")
    o.append("struct core_expect {")
    o.append("    uint8_t  kind;")
    o.append("    uint8_t  slot;")
    o.append("    uint8_t  mult;")
    o.append("    uint32_t count;")
    o.append("};")
    o.append("")

    o.append("/* First occurrence of (first_kind, first_slot) must precede the")
    o.append(" * first occurrence of (then_kind, then_slot). */")
    o.append("struct core_order {")
    o.append("    uint8_t first_kind;")
    o.append("    uint8_t first_slot;")
    o.append("    uint8_t then_kind;")
    o.append("    uint8_t then_slot;")
    o.append("};")
    o.append("")

    o.append("struct core_step {")
    o.append("    uint8_t  op;")
    o.append("    uint8_t  slot;")
    o.append("    uint8_t  timer_kind;  /* OpAddTimer only */")
    o.append("    uint8_t  delay;       /* OpAddTimer only */")
    o.append("    uint8_t  budget;      /* OpQuiesce only, for reporting  */")
    o.append("    uint8_t  conn;        /* transport ops only */")
    o.append("    uint8_t  side;        /* transport ops only */")
    o.append("    /* Which in-process transport this program runs over; the")
    o.append("     * same on every step of a program. */")
    o.append("    uint8_t  transport;")
    o.append("    uint8_t  size;        /* OpSend only    */")
    o.append("    uint8_t  send;        /* OpSend only    */")
    o.append("    uint8_t  drain;       /* OpConnect only */")
    o.append("    uint8_t  queue;       /* block ops only */")
    o.append("    uint8_t  region;      /* block data ops only */")
    o.append("    uint8_t  segs;        /* block read/write only */")
    o.append("    /* The byte a block write fills its region with, or the one")
    o.append("     * a read must find there.  Negative means the model makes")
    o.append("     * no claim about the bytes -- only about the completion. */")
    o.append("    int16_t  pattern;")
    o.append("    /* Model time in milliseconds at the end of this step,")
    o.append("     * measured from the start of the program.  A quiesce runs")
    o.append("     * to this as an ABSOLUTE deadline, so real and model time")
    o.append("     * cannot drift apart cumulatively over a program. */")
    o.append("    uint32_t at_ms;")
    o.append("    uint16_t expect_first;")
    o.append("    uint16_t expect_count;")
    o.append("    uint16_t order_first;")
    o.append("    uint16_t order_count;")
    o.append("};")
    o.append("")

    o.append("struct core_program {")
    o.append("    uint16_t first_step;")
    o.append("    uint16_t nsteps;")
    o.append("};")
    o.append("")

    o.append("static const struct core_expect core_expects[] = {")
    if not expect_rows:
        o.append("    { 0, 0, 0, 0 },")
    for kind, slot, mult, count in expect_rows:
        o.append("    { %d, %d, %d, %d }," % (kind, slot, mult, count))
    o.append("};")
    o.append("")

    o.append("static const struct core_order core_orders[] = {")
    if not order_rows:
        o.append("    { 0, 0, 0, 0 },")
    for fk, fs, tk, ts in order_rows:
        o.append("    { %d, %d, %d, %d }," % (fk, fs, tk, ts))
    o.append("};")
    o.append("")

    o.append("static const struct core_step core_steps[] = {")
    for (op, slot, tk, delay, budget, conn, side, transport, size, send, drain,
         queue, region, segs, pattern, at_ms, ef, ec, of, oc) in steps:
        o.append("    { %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, "
                 "%d, %d, %d, %d, %d, %d, %d, %d, %d },"
                 % (op, slot, tk, delay, budget, conn, side, transport, size,
                    send, drain, queue, region, segs, pattern, at_ms,
                    ef, ec, of, oc))
    o.append("};")
    o.append("")

    o.append("static const struct core_program core_programs[] = {")
    for first, n in prog_rows:
        o.append("    { %d, %d }," % (first, n))
    o.append("};")
    o.append("")
    o.append("#define CORE_NUM_PROGRAMS "
             "(sizeof(core_programs) / sizeof(core_programs[0]))")
    o.append("")

    with open(out_path, "w") as f:
        f.write("\n".join(o))

    print("%s: %d programs, %d steps, %d obligations" %
          (out_path, len(prog_rows), len(steps), len(expect_rows)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TagError as e:
        print("error: %s" % e, file=sys.stderr)
        sys.exit(1)
