#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

"""Convert Quint ITF traces of client.qnt into a C case table.

client.qnt enumerates reply defects symbolically.  This script turns the
resulting traces into a C header that conformance_client.c compiles in, so the
test binary carries its cases as static data -- no JSON parser, no Python, and
no quint at run time.  CMake runs generate_client_cases.sh, which runs this;
the header lives in the build tree so it can never drift from the model.

Every tag the model can emit must appear in the tables below.  An unknown tag
is a hard error rather than a silently skipped case: if the model gains a
variant, the C driver needs a corresponding arm, and failing loudly here is
what forces that.
"""

import json
import sys

# Tag orderings.  These define the numeric values of the generated C enums, so
# reordering a list renumbers the enum -- harmless (the header is regenerated
# atomically with the table) but avoid it for reviewable diffs.
DEFECTS = [
    "ReplyWellFormed",
    "ReplyVerfAuthSys",
    "ReplySplitAcrossFragments",
    "ReplyUnknownXid",
    "ReplyDuplicated",
    "ReplyIsACall",
    "ReplyHeaderTruncated",
    "ReplyMtypeUndefined",
    "ReplyVerfBodyOverlong",
    "PeerClosesWithoutReply",
    "ReplyRejectedAuth",
    "ReplyRejectedRpcMismatch",
    "ReplyAcceptStat",
    "ReplyDeniedWithBody",
    "ReplyAcceptStatWithBody",
    "ReplyStatUndefined",
    "ReplyEmptyBody",
    "ReplyTruncatedBody",
    "ReplyTrailingGarbage",
    "ReplyGarbageBody",
    "ReplyStringLenOverflow",
    "ReplyStringLenBeyondMessage",
]

DELIVERIES = ["OneWrite", "TwoWrites", "Dribble"]

OUTCOMES = ["CbSuccess", "CbDecodeError", "CbFailed", "CbDropped"]

SURVIVALS = ["ConnUp", "ConnAny"]

# Defects whose wire delivery is fixed by the defect itself, so varying the
# delivery mode does not produce a distinct test -- it produces the same bytes
# in the same order.  Collapsing them to OneWrite keeps the case count honest
# instead of filling the table with triplicates.  Mirrors VALUE_RELEVANT in
# itf_to_cases.py.
DELIVERY_IRRELEVANT = {
    # Nothing is written at all; the defect is the close.
    "PeerClosesWithoutReply",
    # The defect *is* a delivery pattern: it writes its own fragments.
    "ReplySplitAcrossFragments",
}


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
        raise TagError("unknown %s tag %r; add it to itf_to_client_cases.py "
                       "and to the C driver" % (what, tag))


def itf_int(v):
    if isinstance(v, dict) and "#bigint" in v:
        return int(v["#bigint"])
    if isinstance(v, int):
        return v
    raise TagError("expected an integer, got %r" % (v,))


def payload_int(variant):
    """Integer payload of a variant, or -1 when it carries none."""
    val = variant.get("value")
    if isinstance(val, dict) and "#tup" in val:
        return -1
    return itf_int(val)


def collect(paths):
    seen, cases = set(), []
    for path in paths:
        with open(path) as f:
            trace = json.load(f)
        for state in trace["states"]:
            cur = state["current"]
            dv = cur["defect"]
            dtag = tag_of(dv)

            defect = index_of(DEFECTS, dtag, "defect")
            param = payload_int(dv)

            dtag_delivery = ("OneWrite" if dtag in DELIVERY_IRRELEVANT
                             else tag_of(cur["delivery"]))
            delivery = index_of(DELIVERIES, dtag_delivery, "delivery")

            expect = index_of(OUTCOMES, tag_of(state["expected"]), "outcome")
            survive = index_of(SURVIVALS, tag_of(state["survives"]),
                               "survival")

            key = (defect, param, delivery, expect, survive)
            if key not in seen:
                seen.add(key)
                cases.append(key)
    return cases


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
    cases = collect(sys.argv[2:])

    o = []
    o.append("/* SPDX-FileCopyrightText: 2026 Ben Jarvis")
    o.append(" *")
    o.append(" * SPDX-License-Identifier: LGPL-2.1-only")
    o.append(" *")
    o.append(" * GENERATED FILE -- DO NOT EDIT.")
    o.append(" *")
    o.append(" * Produced by quint/generate_client_cases.sh from the Quint")
    o.append(" * model in quint/client.qnt.  Each row is one defective reply;")
    o.append(" * the driver in conformance_client.c maps the symbolic defect to")
    o.append(" * wire bytes and checks the client against the prediction.")
    o.append(" */")
    o.append("")
    o.append("#pragma once")
    o.append("")
    o.append("#include <stdint.h>")
    o.append("")

    emit_enum(o, "client_defect", "CDEF", DEFECTS)
    emit_enum(o, "client_delivery", "CDLV", DELIVERIES)
    emit_enum(o, "client_outcome", "CEXP", OUTCOMES)
    emit_enum(o, "client_survival", "CSRV", SURVIVALS)

    o.append("struct client_case {")
    o.append("    uint8_t defect;")
    o.append("    uint8_t delivery;")
    o.append("    uint8_t expect;   /* required callback outcome */")
    o.append("    uint8_t survive;  /* whether the conn must stay usable */")
    o.append("    int64_t param;    /* defect payload, -1 when it has none */")
    o.append("};")
    o.append("")

    o.append("static const struct client_case client_cases[] = {")
    for defect, param, delivery, expect, survive in cases:
        o.append("    { %d, %d, %d, %d, %d }," %
                 (defect, delivery, expect, survive, param))
    o.append("};")
    o.append("")
    o.append("#define CLIENT_NUM_CASES "
             "(sizeof(client_cases) / sizeof(client_cases[0]))")
    o.append("")

    with open(out_path, "w") as f:
        f.write("\n".join(o))

    print("%s: %d client reply cases" % (out_path, len(cases)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TagError as e:
        print("error: %s" % e, file=sys.stderr)
        sys.exit(1)
