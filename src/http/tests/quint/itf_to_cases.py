#!/usr/bin/env python3
# SPDX-FileCopyrightText: 2026 Ben Jarvis
#
# SPDX-License-Identifier: LGPL-2.1-only

"""Convert Quint ITF traces of http10.qnt into a C case table.

http10.qnt enumerates HTTP/1.0 requests and their required responses
symbolically.  This script turns the resulting traces into a C header that
conformance.c compiles in, so the test binary carries its cases as static
data -- no JSON parser, no Python, and no quint at run time.  CMake runs
generate_cases.sh, which runs this; the header lives in the build tree so it
can never drift from the model.

Two trace sets go in and two tables come out: the positive matrix from
http10_requests and the defect taxonomy from http10_defects.  They share the
outcome vocabulary (module http10), so the enums for it are emitted once and
both tables index them.

Every tag the model can emit must appear in the tables below.  An unknown tag
is a hard error rather than a silently skipped case: if the model gains a
variant, the C driver needs a corresponding arm, and failing loudly here is
what forces that.
"""

import json
import sys

# Tag orderings.  These define the numeric values of the generated C enums, so
# reordering a list renumbers the enum -- harmless (the header is regenerated
# atomically with the tables) but avoid it for reviewable diffs.

# --- module http10: the shared vocabulary ----------------------------------

DELIVERIES = ["OneWrite", "TwoWrites", "Dribble"]

OUTCOMES = ["Status", "NotSuccess", "SimpleResponse"]

BODY_EXPECTS = ["BodyEchoed", "BodyAbsent", "BodyAny"]

PERSISTS = ["MustClose", "MayPersist"]

PROBE_EXPECTS = ["ProbeAbsent", "ProbeValue", "ProbeEmpty", "ProbeTwice",
                 "ProbeAny"]

# --- module http10_requests ------------------------------------------------

METHODS = ["MGet", "MHead", "MPost"]

URIS = ["UriRoot", "UriPath", "UriQuery", "UriEscaped", "UriLong"]

HDRS = ["HdrNone", "HdrPlain", "HdrPadded", "HdrEmpty", "HdrMixedCase",
        "HdrFolded", "HdrDuplicate", "HdrMany"]

BODIES = ["BodyNone", "BodyEmpty", "BodyOne", "BodySmall", "BodyLarge"]

CONNS = ["ConnDefault", "ConnKeepAlive"]

# --- module http10_client --------------------------------------------------

CLIENT_OUTCOMES = ["CbComplete", "CbFailed"]

CLIENT_BODIES = ["BodyDelivered", "BodyNone", "BodyUnchecked"]

CLIENT_METHODS = ["CGet", "CHead"]

CLIENT_DEFECTS = [
    "RspWellFormed",
    "RspHeaderEmptyValue",
    "RspHeaderFolded",
    "RspHeaderPadded",
    "RspHeaderNoColon",
    "RspHeaderNameEmpty",
    "RspHeaderSpaceBeforeColon",
    "RspHeaderBlockOverlong",
    "RspNoReasonPhrase",
    "RspMinorVersionUnknown",
    "RspVersionMalformed",
    "RspMajorVersionUnsupported",
    "RspStatusNotNumeric",
    "RspStatusOutOfRange",
    "RspStatusMissing",
    "RspNoStatusLine",
    "RspStatus",
    "RspStatusNoBody",
    "RspBodyCloseDelimited",
    "RspContentLengthNotNumeric",
    "RspContentLengthNegative",
    "RspContentLengthDuplicateConflicting",
    "RspBodyShortOfContentLength",
    "RspBodyLongerThanContentLength",
    "RspHeadWithContentLength",
    "RspPeerClosesWithoutResponse",
    "RspPeerClosesMidStatusLine",
    "RspPeerClosesMidHeaders",
]

# --- module http10_defects -------------------------------------------------

DEFECTS = [
    "NoDefect",
    "MethodUnknown",
    "MethodLowercase",
    "MethodEmpty",
    "RequestLineOneToken",
    "RequestLineExtraToken",
    "RequestLineNoVersion",
    "VersionMalformed",
    "VersionMajorUnsupported",
    "VersionMinorUnknown",
    "UriTooLong",
    "HeaderNoColon",
    "HeaderNameEmpty",
    "HeaderSpaceBeforeColon",
    "HeaderLineOverlong",
    "HeaderBlockOverlong",
    "HeaderBlockUnterminated",
    "BareLfLineEndings",
    "ContentLengthNotNumeric",
    "ContentLengthNegative",
    "ContentLengthDuplicateConflicting",
    "BodyShortOfContentLength",
    "PostWithoutContentLength",
]


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


def outcome_of(variant):
    """(outcome index, status).  Status is -1 for the arms that carry none."""
    tag = tag_of(variant)
    idx = index_of(OUTCOMES, tag, "outcome")
    if tag == "Status":
        return idx, itf_int(variant["value"])
    return idx, -1


def load_states(paths):
    for path in paths:
        with open(path) as f:
            trace = json.load(f)
        for state in trace["states"]:
            yield state


def collect_requests(paths):
    seen, cases = set(), []
    for state in load_states(paths):
        cur = state["current"]
        outcome, status = outcome_of(state["expected"])
        key = (
            index_of(METHODS, tag_of(cur["method"]), "method"),
            index_of(URIS, tag_of(cur["uri"]), "uri"),
            index_of(HDRS, tag_of(cur["hdr"]), "header shape"),
            index_of(BODIES, tag_of(cur["body"]), "body"),
            index_of(CONNS, tag_of(cur["conn"]), "connection"),
            index_of(DELIVERIES, tag_of(cur["delivery"]), "delivery"),
            outcome,
            status,
            index_of(BODY_EXPECTS, tag_of(state["expectBody"]),
                     "body expectation"),
            index_of(PROBE_EXPECTS, tag_of(state["expectProbe"]),
                     "probe expectation"),
            index_of(PERSISTS, tag_of(state["expectPersist"]),
                     "persistence expectation"),
        )
        if key not in seen:
            seen.add(key)
            cases.append(key)
    return cases


def collect_defects(paths):
    seen, cases = set(), []
    for state in load_states(paths):
        cur = state["current"]
        outcome, status = outcome_of(state["expected"])
        key = (
            index_of(DEFECTS, tag_of(cur["defect"]), "defect"),
            index_of(DELIVERIES, tag_of(cur["delivery"]), "delivery"),
            outcome,
            status,
            index_of(PERSISTS, tag_of(state["expectPersist"]),
                     "persistence expectation"),
        )
        if key not in seen:
            seen.add(key)
            cases.append(key)
    return cases


def collect_client(paths):
    seen, cases = set(), []
    for state in load_states(paths):
        cur = state["current"]
        dv = cur["defect"]
        dtag = tag_of(dv)
        outcome = state["expected"]
        otag = tag_of(outcome)
        key = (
            index_of(CLIENT_DEFECTS, dtag, "response defect"),
            # A defect that carries a number needs it on the wire: the status
            # to send, or the range to sit outside of.
            payload_int(dv),
            index_of(DELIVERIES, tag_of(cur["delivery"]), "delivery"),
            index_of(CLIENT_OUTCOMES, otag, "client outcome"),
            itf_int(outcome["value"]) if otag == "CbComplete" else -1,
            index_of(CLIENT_BODIES, tag_of(state["expectBody"]),
                     "body expectation"),
            index_of(PROBE_EXPECTS, tag_of(state["expectProbe"]),
                     "probe expectation"),
            index_of(CLIENT_METHODS, tag_of(state["expectMethod"]), "method"),
        )
        if key not in seen:
            seen.add(key)
            cases.append(key)
    return cases


def payload_int(variant):
    """Integer payload of a variant, or -1 when it carries none."""
    val = variant.get("value")
    if isinstance(val, dict) and "#tup" in val:
        return -1
    return itf_int(val)


def emit_enum(out, name, prefix, tags):
    out.append("enum %s {" % name)
    for i, t in enumerate(tags):
        out.append("    %s_%s = %d," % (prefix, t.upper(), i))
    out.append("};")
    out.append("")


def emit_names(out, fn, enum, tags):
    """A name table, so a failure report says MethodUnknown and not 7."""
    out.append("static const char *%s(int v)" % fn)
    out.append("{")
    out.append("    static const char *names[] = {")
    for t in tags:
        out.append("        \"%s\"," % t)
    out.append("    };")
    out.append("")
    out.append("    if (v < 0 || v >= (int) (sizeof(names) / "
               "sizeof(names[0]))) {")
    out.append("        return \"?\";")
    out.append("    }")
    out.append("")
    out.append("    return names[v];")
    out.append("} /* %s */" % fn)
    out.append("")


def main():
    if len(sys.argv) < 4:
        print("usage: %s <out.h> <requests.itf.json>... -- "
              "<defects.itf.json>... -- <client.itf.json>..." % sys.argv[0],
              file=sys.stderr)
        return 2

    out_path = sys.argv[1]

    rest = sys.argv[2:]
    groups = []
    current = []
    for arg in rest:
        if arg == "--":
            groups.append(current)
            current = []
        else:
            current.append(arg)
    groups.append(current)

    if len(groups) != 3:
        print("error: expected three trace groups separated by --",
              file=sys.stderr)
        return 2

    requests = collect_requests(groups[0])
    defects = collect_defects(groups[1])
    client = collect_client(groups[2])

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
    o.append(" * Produced by quint/generate_cases.sh from the Quint model in")
    o.append(" * quint/http10.qnt.  Each row of http_request_cases is one")
    o.append(" * legal HTTP/1.0 request; each row of http_defect_cases is one")
    o.append(" * malformed one.  The driver in conformance.c maps the symbolic")
    o.append(" * classes to wire bytes and checks the server's response")
    o.append(" * against the prediction carried alongside them.")
    o.append(" */")
    o.append("")
    o.append("#pragma once")
    o.append("")
    o.append("#include <stdint.h>")
    o.append("")

    # Shared vocabulary.
    emit_enum(o, "http_delivery", "HDLV", DELIVERIES)
    emit_enum(o, "http_outcome", "HOUT", OUTCOMES)
    emit_enum(o, "http_body_expect", "HBODY", BODY_EXPECTS)
    emit_enum(o, "http_persist_expect", "HPERSIST", PERSISTS)
    emit_enum(o, "http_probe_expect", "HPROBE", PROBE_EXPECTS)

    # Positive matrix.
    emit_enum(o, "http_method_cls", "HMETH", METHODS)
    emit_enum(o, "http_uri_cls", "HURI", URIS)
    emit_enum(o, "http_hdr_cls", "HHDR", HDRS)
    emit_enum(o, "http_body_cls", "HBDY", BODIES)
    emit_enum(o, "http_conn_cls", "HCONN", CONNS)

    # Defect taxonomy.
    emit_enum(o, "http_defect", "HDEF", DEFECTS)

    # Client direction.
    emit_enum(o, "http_client_outcome", "HCOUT", CLIENT_OUTCOMES)
    emit_enum(o, "http_client_body", "HCBODY", CLIENT_BODIES)
    emit_enum(o, "http_client_method", "HCMETH", CLIENT_METHODS)
    emit_enum(o, "http_client_defect", "HCDEF", CLIENT_DEFECTS)

    emit_names(o, "http_delivery_name", "http_delivery", DELIVERIES)
    emit_names(o, "http_method_name", "http_method_cls", METHODS)
    emit_names(o, "http_uri_name", "http_uri_cls", URIS)
    emit_names(o, "http_hdr_name", "http_hdr_cls", HDRS)
    emit_names(o, "http_body_name", "http_body_cls", BODIES)
    emit_names(o, "http_conn_name", "http_conn_cls", CONNS)
    emit_names(o, "http_defect_name", "http_defect", DEFECTS)
    emit_names(o, "http_probe_expect_name", "http_probe_expect", PROBE_EXPECTS)
    emit_names(o, "http_client_defect_name", "http_client_defect",
               CLIENT_DEFECTS)

    o.append("struct http_request_case {")
    o.append("    uint8_t method;")
    o.append("    uint8_t uri;")
    o.append("    uint8_t hdr;")
    o.append("    uint8_t body;")
    o.append("    uint8_t conn;")
    o.append("    uint8_t delivery;")
    o.append("    uint8_t expect;        /* HOUT_*: the required outcome    */")
    o.append("    uint8_t expect_body;   /* HBODY_*                          */")
    o.append("    uint8_t expect_probe;  /* HPROBE_*                         */")
    o.append("    uint8_t expect_persist;/* HPERSIST_*                       */")
    o.append("    int16_t expect_status; /* status for HOUT_STATUS, else -1  */")
    o.append("};")
    o.append("")

    o.append("static const struct http_request_case http_request_cases[] = {")
    for (method, uri, hdr, body, conn, delivery, outcome, status,
         body_expect, probe_expect, persist) in requests:
        o.append("    { %d, %d, %d, %d, %d, %d, %d, %d, %d, %d, %d },"
                 % (method, uri, hdr, body, conn, delivery, outcome,
                    body_expect, probe_expect, persist, status))
    o.append("};")
    o.append("")
    o.append("#define HTTP_NUM_REQUEST_CASES "
             "(sizeof(http_request_cases) / sizeof(http_request_cases[0]))")
    o.append("")

    o.append("struct http_defect_case {")
    o.append("    uint8_t defect;")
    o.append("    uint8_t delivery;")
    o.append("    uint8_t expect;        /* HOUT_*                           */")
    o.append("    uint8_t expect_persist;/* HPERSIST_*                       */")
    o.append("    int16_t expect_status; /* status for HOUT_STATUS, else -1  */")
    o.append("};")
    o.append("")

    o.append("static const struct http_defect_case http_defect_cases[] = {")
    for defect, delivery, outcome, status, persist in defects:
        o.append("    { %d, %d, %d, %d, %d }," %
                 (defect, delivery, outcome, persist, status))
    o.append("};")
    o.append("")
    o.append("#define HTTP_NUM_DEFECT_CASES "
             "(sizeof(http_defect_cases) / sizeof(http_defect_cases[0]))")
    o.append("")

    o.append("struct http_client_case {")
    o.append("    uint8_t defect;")
    o.append("    uint8_t delivery;")
    o.append("    uint8_t expect;        /* HCOUT_*                          */")
    o.append("    uint8_t expect_body;   /* HCBODY_*                         */")
    o.append("    uint8_t expect_probe;  /* HPROBE_*                         */")
    o.append("    uint8_t method;        /* HCMETH_*                         */")
    o.append("    int16_t param;         /* defect payload, -1 when none     */")
    o.append("    int16_t expect_status; /* status for HCOUT_CBCOMPLETE      */")
    o.append("};")
    o.append("")

    o.append("static const struct http_client_case http_client_cases[] = {")
    for (defect, param, delivery, outcome, status, body, probe,
         method) in client:
        o.append("    { %d, %d, %d, %d, %d, %d, %d, %d }," %
                 (defect, delivery, outcome, body, probe, method, param,
                  status))
    o.append("};")
    o.append("")
    o.append("#define HTTP_NUM_CLIENT_CASES "
             "(sizeof(http_client_cases) / sizeof(http_client_cases[0]))")
    o.append("")

    with open(out_path, "w") as f:
        f.write("\n".join(o))

    print("%s: %d request cases, %d defect cases, %d client cases" %
          (out_path, len(requests), len(defects), len(client)))
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except TagError as e:
        print("error: %s" % e, file=sys.stderr)
        sys.exit(1)
