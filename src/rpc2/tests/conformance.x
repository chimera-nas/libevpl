/*
 * SPDX-FileCopyrightText: 2026 Ben Jarvis
 * SPDX-License-Identifier: BSD-3-Clause
 *
 * XDR/RPC2 conformance test program.
 *
 * This .x exists purely to exercise xdrzcc's code generator and libevpl's
 * RPC2 layer.  It aims to instantiate every XDR construct xdrzcc supports,
 * in every container shape, so that the generated marshall/unmarshall paths
 * are all reachable from a single RPC program.
 *
 * Every procedure is an ECHO: the server returns its argument unchanged (or,
 * where echoing hostile input would be unsafe, a probe result describing what
 * it decoded).  That makes the happy path self-checking without an oracle,
 * and leaves the model to drive value permutations and wire-level defects.
 *
 * Deliberately ABSENT, because xdrzcc does not support them (each is a
 * separate finding for the compiler's own test suite, not something this
 * file can exercise):
 *
 *   - hyper / unsigned hyper / quadruple / bare "unsigned": no lexer token.
 *   - negative constants: the lexer has no '-' rule; "const X = -1;" warns
 *     and then silently parses as 1.
 *   - "case 1:": case labels must be identifiers, not numbers.
 *   - string inside an array or vector ("string s<>"): the string branch is
 *     tested before the vector branch in codegen, so the shape is dropped.
 *   - a typedef re-decorated at the use site ("mytype m<>;"): the modifier is
 *     silently discarded, changing the wire format.  See the workaround note
 *     in chimera's nfs4.x.
 *   - mutual recursion (A refers to B refers to A): the header emission loop
 *     does not terminate.
 *
 * Declared bounds on string<N>, opaque<N> and T<N> are all enforced at decode
 * time, and the bound-exceeding cases in the model check each of them.
 */

const FIXED_OPAQUE_LEN = 16;
const FIXED_ARRAY_LEN  = 4;
const BOUNDED_MAX      = 8;

/* ------------------------------------------------------------------ *
 * Scalars: every numeric width and format xdrzcc can emit.
 * ------------------------------------------------------------------ */

enum color {
    RED   = 0,
    GREEN = 1,
    BLUE  = 2
};

struct scalars {
    int32_t  s32;
    uint32_t u32;
    int64_t  s64;
    uint64_t u64;
    float    f32;
    double   f64;
    bool     b;
    color    c;
};

/* ------------------------------------------------------------------ *
 * Byte strings: the four distinct representations, each with its own
 * decode path (in-place aliasing, dbuf copy, fixed memcpy, zero-copy).
 * ------------------------------------------------------------------ */

struct bytes {
    string   s;
    string   bounded_s<BOUNDED_MAX>;
    opaque   v<>;
    opaque   bounded<BOUNDED_MAX>;
    opaque   f[FIXED_OPAQUE_LEN];
};

/* zcopaque gets its own procedure: it is the only field type that never
 * copies, so a failure here is a refcount/iovec bug rather than a codec bug
 * and is worth isolating. */
struct zbytes {
    uint32_t head;
    zcopaque z<>;
    uint32_t tail;
};

/* ------------------------------------------------------------------ *
 * Arrays: fixed and variable, over both a builtin and a struct element.
 * ------------------------------------------------------------------ */

struct point {
    int32_t x;
    int32_t y;
};

struct arrays {
    uint32_t fixed_u32[FIXED_ARRAY_LEN];
    uint32_t var_u32<>;
    uint32_t bounded_u32<BOUNDED_MAX>;
    point    fixed_pt[2];
    point    var_pt<>;
};

/* ------------------------------------------------------------------ *
 * Unions.  "tagged" has a default arm and a void arm; "strict" has
 * neither, so an unmatched discriminant reaches the no-arm path that
 * RFC 4506 requires to be treated as invalid.
 * ------------------------------------------------------------------ */

enum kind {
    K_NONE = 0,
    K_INT  = 1,
    K_STR  = 2,
    K_PT   = 3
};

union tagged switch (kind k) {
case K_NONE:
    void;
case K_INT:
    int32_t i;
case K_STR:
    string s;
case K_PT:
    point p;
default:
    void;
};

union strict switch (kind k) {
case K_INT:
    int32_t i;
case K_PT:
    point p;
};

/* Echoing a "strict" union decoded from an unmatched discriminant would
 * re-marshall an uninitialized arm, so the server reports what it decoded
 * instead of echoing it. */
struct probe_result {
    uint32_t seen_k;
    int32_t  seen_i;
};

/* ------------------------------------------------------------------ *
 * Optional pointer followed by a trailing field: regression shape for
 * length accounting in the contig decoder (cf. xdrzcc tests/optional.x).
 * ------------------------------------------------------------------ */

struct opt_msg {
    uint32_t head;
    point   *opt;
    uint32_t tail;
};

/* ------------------------------------------------------------------ *
 * Linked list.  A member named "next*" that is optional turns the
 * containing struct into a list encoded as repeated <1, elem> ... 0.
 * ------------------------------------------------------------------ */

struct lnode {
    uint32_t value;
    lnode   *nextnode;
};

struct list_msg {
    lnode   *head;
    uint32_t trailer;
};

/* ------------------------------------------------------------------ *
 * Nesting and self-recursion.  "chain" is a self-recursive optional, so
 * the generated codec for rec cannot be force-inlined.
 * ------------------------------------------------------------------ */

struct rec {
    uint32_t depth;
    rec     *chain;
};

struct nested {
    point   inner_pt;
    scalars inner_scalars;
    rec    *chain;
    uint32_t tail;
};

program CONFORMANCE_PROGRAM {
    version CONFORMANCE_V1 {
        scalars      ECHO_SCALARS(scalars)   = 1;
        bytes        ECHO_BYTES(bytes)       = 2;
        zbytes       ECHO_ZBYTES(zbytes)     = 3;
        arrays       ECHO_ARRAYS(arrays)     = 4;
        tagged       ECHO_UNION(tagged)      = 5;
        probe_result PROBE_STRICT(strict)    = 6;
        opt_msg      ECHO_OPTIONAL(opt_msg)  = 7;
        list_msg     ECHO_LIST(list_msg)     = 8;
        nested       ECHO_NESTED(nested)     = 9;
    } = 1;
} = 44;
