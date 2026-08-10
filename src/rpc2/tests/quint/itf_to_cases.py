#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

"""Convert Quint ITF traces into a C case table for conformance.c.

The Quint models (values.qnt, defects.qnt) enumerate test cases symbolically.
This script turns the resulting traces into a checked-in C header so the test
binary carries its cases as static data -- no JSON parser, no Python, and no
quint at build or run time.  Regenerate with regen_cases.sh after changing a
model.

Every tag the models can emit must appear in the tables below.  An unknown tag
is a hard error rather than a silently skipped case: if a model gains a
variant, the C driver needs a corresponding arm, and failing loudly here is
what forces that.
"""

import json
import sys

# Tag orderings. These define the numeric values of the generated C enums, so
# reordering a list renumbers the enum -- harmless (the header is regenerated
# atomically with the tables) but avoid it for reviewable diffs.
VALUE_FIELDS = {
    "proc": ["EchoScalars", "EchoBytes", "EchoZbytes", "EchoArrays",
             "EchoUnion", "EchoOptional", "EchoList", "EchoNested"],
    "i": ["I32Min", "I32Neg1", "I32Zero", "I32One", "I32Max"],
    "u": ["U32Zero", "U32One", "U32Max"],
    "l": ["I64Min", "I64Neg1", "I64Zero", "I64Max"],
    "ul": ["U64Zero", "U64One", "U64Max"],
    "f": ["FZero", "FNegZero", "FOne", "FNegOne", "FLarge", "FNan"],
    "b": ["BFalse", "BTrue"],
    "col": ["ColRed", "ColGreen", "ColBlue"],
    "strLen": ["LEmpty", "LOne", "LUnaligned", "LAligned", "LAtBound", "LLarge"],
    "opaqueLen": ["LEmpty", "LOne", "LUnaligned", "LAligned", "LAtBound", "LLarge"],
    "boundedLen": ["LEmpty", "LOne", "LUnaligned", "LAligned", "LAtBound", "LLarge"],
    "arrLen": ["LEmpty", "LOne", "LUnaligned", "LAligned", "LAtBound", "LLarge"],
    "optPresent": ["OptAbsent", "OptPresent"],
    "arm": ["ArmNone", "ArmInt", "ArmStr", "ArmPt"],
    "depth": ["LEmpty", "LOne", "LUnaligned", "LAligned", "LAtBound", "LLarge"],
    "chunk": ["ChunkNone", "ChunkDdp", "ChunkReply", "ChunkReadInto",
              "ChunkWriteAlloc", "ChunkWriteExact"],
}

# Field order in struct conf_value_case; also the C member names.
VALUE_ORDER = ["proc", "i", "u", "l", "ul", "f", "b", "col", "strLen",
               "opaqueLen", "boundedLen", "arrLen", "optPresent", "arm", "depth",
               "chunk"]

VALUE_MEMBER = {
    "proc": "proc", "i": "i", "u": "u", "l": "l", "ul": "ul", "f": "f",
    "b": "b", "col": "col", "strLen": "str_len", "opaqueLen": "opaque_len",
    "boundedLen": "bounded_len", "arrLen": "arr_len",
    "optPresent": "opt_present", "arm": "arm", "depth": "depth",
    "chunk": "chunk",
}

# Which fields each procedure actually reads.  The model picks a class for
# every field on every step, but a case for ECHO_SCALARS that differs only in
# its (unused) list depth is not a distinct test -- it is the same RPC on the
# wire.  De-duplicating on the relevant subset keeps the case count honest and
# stops the table filling up with identical calls.  Irrelevant fields are
# zeroed in the emitted row.
VALUE_RELEVANT = {
    "EchoScalars":  ["i", "u", "l", "ul", "f", "b", "col", "chunk"],
    "EchoBytes":    ["strLen", "opaqueLen", "boundedLen", "chunk"],
    "EchoZbytes":   ["u", "opaqueLen", "chunk"],
    "EchoArrays":   ["u", "arrLen", "boundedLen", "chunk"],
    "EchoUnion":    ["arm", "i", "strLen", "chunk"],
    "EchoOptional": ["optPresent", "u", "i", "chunk"],
    "EchoList":     ["u", "depth", "chunk"],
    "EchoNested":   ["i", "u", "depth", "chunk"],
}

DEFECTS = [
    "NoDefect",
    "RpcVersWrong", "ProgramUnknown", "VersionUnsupported", "ProcedureUnknown",
    "ProcedureNull", "AuthFlavorUnsupported", "CredBodyOverlong",
    "ArgsTruncated", "ArgsTrailingGarbage", "StringLenOverflow",
    "StringLenBeyondMessage", "StringExceedsBound", "OpaqueExceedsBound",
    "ArrayCountExceedsBound",
    "ArrayCountHuge", "DiscriminantUnmatched", "BoolNotZeroOrOne",
    "EnumNotDeclared", "RecordMarkHuge", "RecordMarkZeroLength",
    "CallSplitAcrossFragments", "CallSplitPathological",
    "GssInitEstablishes", "GssInitContinues", "GssInitMechFails",
    "GssDataValid", "GssCredVersionWrong", "GssProcUnknown",
    "GssServicePrivacy", "GssHandleUnknown", "GssVerifierNotGss",
    "GssMicWrong", "GssSeqReplayed",
    "AuthSysValid",
    "GssIntegDataValid", "GssIntegChecksumWrong", "GssIntegSeqMismatch",
    "GssDestroyContext", "GssDestroyUnauthenticated",
    "GssSeqAboveMax", "GssSeqWindowJump", "GssSeqTooOld", "GssSeqOutOfOrder",
    "GssCredTruncated", "GssCredHandleOverruns",
    "GssNoMechanism",
    "GssContinueInitUnknownHandle", "GssInitTokenMalformed",
    "GssContinueInitTokenMalformed", "GssInitMechFailsWithToken",
    "GssIntegFramingBad", "GssIntegEmptyArgs", "GssIntegSplitAcrossFragments",
    "GssIntegReplyMicFails", "GssIntegReplyMicOversize",
    "ReassemblyCapExceeded",
]

TARGETS = ["TScalars", "TBytes", "TArrays", "TStrict"]

OUTCOMES = ["Success", "ProgUnavail", "ProgMismatch", "ProcUnavail",
            "GarbageArgs", "RpcMismatch", "AuthError", "Closed", "NoReply"]


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
        raise TagError("unknown %s tag %r; add it to itf_to_cases.py and to "
                       "the C driver" % (what, tag))


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


def load_states(paths, var):
    for path in paths:
        with open(path) as f:
            trace = json.load(f)
        for state in trace["states"]:
            yield state, path


def collect_values(paths):
    seen, cases = set(), []
    for state, path in load_states(paths, "current"):
        cur = state["current"]
        proc_tag = tag_of(cur["proc"])
        relevant = VALUE_RELEVANT.get(proc_tag)
        if relevant is None:
            raise TagError("no relevance entry for procedure %r; add one to "
                           "itf_to_cases.py" % proc_tag)

        row = []
        for field in VALUE_ORDER:
            if field != "proc" and field not in relevant:
                row.append(0)
                continue
            row.append(index_of(VALUE_FIELDS[field], tag_of(cur[field]), field))

        key = tuple(row)
        if key not in seen:
            seen.add(key)
            cases.append(row)
    return cases


def collect_defects(paths):
    seen, cases = set(), []
    for state, path in load_states(paths, "current"):
        cur = state["current"]
        dv = cur["defect"]
        defect = index_of(DEFECTS, tag_of(dv), "defect")
        param = payload_int(dv)
        target = index_of(TARGETS, tag_of(cur["target"]), "target")

        ev = state["expected"]
        outcome = index_of(OUTCOMES, tag_of(ev), "outcome")
        lo = hi = -1
        if tag_of(ev) in ("ProgMismatch", "RpcMismatch"):
            rng = ev["value"]
            lo, hi = itf_int(rng["lo"]), itf_int(rng["hi"])

        key = (defect, param, target, outcome, lo, hi)
        if key not in seen:
            seen.add(key)
            cases.append(key)
    return cases


def emit_enum(out, name, prefix, tags):
    # De-duplicate while preserving order: several value fields share the
    # LenCls tags, and they must map to one C enum, not several.
    seen, uniq = set(), []
    for t in tags:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    out.append("enum %s {" % name)
    for i, t in enumerate(uniq):
        out.append("    %s_%s = %d," % (prefix, t.upper(), i))
    out.append("};")
    out.append("")


def main():
    if len(sys.argv) < 4:
        print("usage: %s <out.h> --values <traces...> --defects <traces...>"
              % sys.argv[0], file=sys.stderr)
        return 2

    out_path = sys.argv[1]
    args = sys.argv[2:]
    value_paths, defect_paths, bucket = [], [], None
    for a in args:
        if a == "--values":
            bucket = value_paths
        elif a == "--defects":
            bucket = defect_paths
        elif bucket is None:
            print("stray argument %r before --values/--defects" % a,
                  file=sys.stderr)
            return 2
        else:
            bucket.append(a)

    values = collect_values(value_paths)
    defects = collect_defects(defect_paths)

    o = []
    # The header written into the GENERATED file.  Fenced off because reuse
    # otherwise reads these string literals as this script's own license tags
    # and fails to parse the trailing quote as part of the expression.
    # REUSE-IgnoreStart
    o.append("/* SPDX-FileCopyrightText: 2026 Ben Jarvis")
    o.append(" *")
    o.append(" * SPDX-License-Identifier: LGPL-2.1-only")
    # REUSE-IgnoreEnd
    o.append(" *")
    o.append(" * GENERATED FILE -- DO NOT EDIT.")
    o.append(" *")
    o.append(" * Produced by quint/regen_cases.sh from the Quint models in")
    o.append(" * quint/values.qnt and quint/defects.qnt.  Each row is one test")
    o.append(" * case; the C driver in conformance.c maps the symbolic classes")
    o.append(" * to wire bytes and checks the predicted outcome.")
    o.append(" */")
    o.append("")
    o.append("#pragma once")
    o.append("")
    o.append("#include <stdint.h>")
    o.append("")

    # One shared enum per distinct class family.
    emit_enum(o, "conf_proc_cls", "CLS", VALUE_FIELDS["proc"])
    emit_enum(o, "conf_int_cls", "CLS", VALUE_FIELDS["i"])
    emit_enum(o, "conf_uint_cls", "CLS", VALUE_FIELDS["u"])
    emit_enum(o, "conf_long_cls", "CLS", VALUE_FIELDS["l"])
    emit_enum(o, "conf_ulong_cls", "CLS", VALUE_FIELDS["ul"])
    emit_enum(o, "conf_float_cls", "CLS", VALUE_FIELDS["f"])
    emit_enum(o, "conf_bool_cls", "CLS", VALUE_FIELDS["b"])
    emit_enum(o, "conf_color_cls", "CLS", VALUE_FIELDS["col"])
    emit_enum(o, "conf_len_cls", "CLS", VALUE_FIELDS["strLen"])
    emit_enum(o, "conf_opt_cls", "CLS", VALUE_FIELDS["optPresent"])
    emit_enum(o, "conf_arm_cls", "CLS", VALUE_FIELDS["arm"])
    emit_enum(o, "conf_chunk_cls", "CLS", VALUE_FIELDS["chunk"])
    emit_enum(o, "conf_defect", "DEF", DEFECTS)
    emit_enum(o, "conf_target", "TGT", TARGETS)
    emit_enum(o, "conf_outcome", "EXP", OUTCOMES)

    o.append("struct conf_value_case {")
    for field in VALUE_ORDER:
        o.append("    uint8_t %s;" % VALUE_MEMBER[field])
    o.append("};")
    o.append("")
    o.append("struct conf_defect_case {")
    o.append("    uint8_t defect;")
    o.append("    uint8_t target;")
    o.append("    uint8_t expect;")
    o.append("    int64_t param;     /* defect payload, -1 when it has none */")
    o.append("    int32_t expect_lo; /* version range for the *MISMATCH outcomes */")
    o.append("    int32_t expect_hi;")
    o.append("};")
    o.append("")

    o.append("static const struct conf_value_case conf_value_cases[] = {")
    for row in values:
        o.append("    { %s }," % ", ".join(str(x) for x in row))
    o.append("};")
    o.append("")
    o.append("static const struct conf_defect_case conf_defect_cases[] = {")
    for d, param, t, outcome, lo, hi in defects:
        o.append("    { %d, %d, %d, %d, %d, %d }," % (d, t, outcome, param, lo, hi))
    o.append("};")
    o.append("")
    o.append("#define CONF_NUM_VALUE_CASES "
             "(sizeof(conf_value_cases) / sizeof(conf_value_cases[0]))")
    o.append("#define CONF_NUM_DEFECT_CASES "
             "(sizeof(conf_defect_cases) / sizeof(conf_defect_cases[0]))")
    o.append("")

    with open(out_path, "w") as f:
        f.write("\n".join(o))

    print("%s: %d value cases, %d defect cases"
          % (out_path, len(values), len(defects)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TagError as e:
        print("error: %s" % e, file=sys.stderr)
        sys.exit(1)
