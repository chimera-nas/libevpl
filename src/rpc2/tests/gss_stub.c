/*
 * SPDX-FileCopyrightText: 2026 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * Deterministic RPCSEC_GSS provider for the conformance test.  See gss_stub.h
 * for why this exists in place of a real mechanism.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "evpl/evpl.h"
#include "evpl/evpl_rpc2_gss.h"

#include "gss_stub.h"

static int gss_stub_accept_mode = GSS_STUB_ACCEPT_COMPLETE;
static int gss_stub_verify_mode = GSS_STUB_VERIFY_HONEST;
static int gss_stub_mic_mode    = GSS_STUB_MIC_HONEST;
static int gss_stub_wrap_mode   = GSS_STUB_WRAP_HONEST;

void
gss_stub_set_behaviour(
    int accept_mode,
    int verify_mode,
    int mic_mode)
{
    gss_stub_accept_mode = accept_mode;
    gss_stub_verify_mode = verify_mode;
    gss_stub_mic_mode    = mic_mode;
} /* gss_stub_set_behaviour */

void
gss_stub_set_wrap_mode(int wrap_mode)
{
    gss_stub_wrap_mode = wrap_mode;
} /* gss_stub_set_wrap_mode */

/*
 * FNV-1a over the message, emitted big-endian.  The point is not
 * cryptographic strength -- it is that the driver can compute the identical
 * value and so present a verifier the server will accept, which is what makes
 * the success paths reachable rather than only the rejections.
 */
void
gss_stub_mic(
    const void *msg,
    size_t      msg_len,
    uint8_t     out[GSS_STUB_MIC_LEN])
{
    const uint8_t *p = msg;
    uint64_t       h = 1469598103934665603ULL;
    size_t         i;

    for (i = 0; i < msg_len; i++) {
        h ^= p[i];
        h *= 1099511628211ULL;
    }

    for (i = 0; i < GSS_STUB_MIC_LEN; i++) {
        out[i] = (uint8_t) (h >> (56 - 8 * i));
    }
} /* gss_stub_mic */

/*
 * Keystream for the toy seal: FNV over a fixed key and the byte offset, so it
 * is position-dependent (a token is not a repeating XOR of one byte) and
 * reproducible from nothing but the offset, which is what lets the driver and
 * the provider agree without sharing state.
 */
static inline uint8_t
gss_stub_keystream(size_t off)
{
    uint64_t h = 1469598103934665603ULL ^ 0x6b726235u; /* "krb5" */
    size_t   i;

    for (i = 0; i < sizeof(off); i++) {
        h ^= (uint8_t) (off >> (8 * i));
        h *= 1099511628211ULL;
    }

    return (uint8_t) (h >> 24);
} /* gss_stub_keystream */

size_t
gss_stub_seal(
    const void *plain,
    size_t      plain_len,
    void       *out,
    size_t      out_cap)
{
    const uint8_t *in = plain;
    uint8_t       *o  = out;
    size_t         i;

    if (out_cap < plain_len + GSS_STUB_SEAL_OVERHEAD) {
        return 0;
    }

    o[0] = (uint8_t) (plain_len >> 24);
    o[1] = (uint8_t) (plain_len >> 16);
    o[2] = (uint8_t) (plain_len >> 8);
    o[3] = (uint8_t) plain_len;

    for (i = 0; i < plain_len; i++) {
        o[4 + i] = in[i] ^ gss_stub_keystream(i);
    }

    gss_stub_mic(plain, plain_len, o + 4 + plain_len);

    return plain_len + GSS_STUB_SEAL_OVERHEAD;
} /* gss_stub_seal */

/* Per-context cookie.  Only its existence matters to libevpl, which treats it
 * as opaque; the stub keeps a marker so destroy() can assert it owns it. */
struct gss_stub_ctx {
    uint32_t magic;
    int      legs;
};

#define GSS_STUB_MAGIC 0x5f475353u

static int
gss_stub_accept(
    void       *provider_arg,
    void      **gss_ctx,
    const void *in_token,
    size_t      in_len,
    void      **out_token,
    size_t     *out_len,
    int        *complete,
    char       *principal,
    size_t      principal_sz)
{
    struct gss_stub_ctx *ctx = *gss_ctx;
    uint8_t             *tok;

    if (!ctx) {
        ctx = calloc(1, sizeof(*ctx));
        if (!ctx) {
            return -1;
        }
        ctx->magic = GSS_STUB_MAGIC;
        *gss_ctx   = ctx;
    }

    ctx->legs++;

    if (gss_stub_accept_mode == GSS_STUB_ACCEPT_FAIL) {
        return -1;
    }

    /* Every leg returns a token to relay, which is what a real mechanism does
     * and what keeps the reply-construction path exercised.  Its length is
     * deliberately not a multiple of four: GSS tokens are arbitrary octet
     * strings, so the server has to pad the opaque it marshals them into, and
     * an aligned token would leave that padding untested. */
    tok = malloc(GSS_STUB_TOKEN_LEN);
    if (!tok) {
        return -1;
    }
    memcpy(tok, "STUB!", GSS_STUB_TOKEN_LEN);
    *out_token = tok;
    *out_len   = GSS_STUB_TOKEN_LEN;

    /* A failure that still emits a token: the server must not send it, and
     * must not leak it either. */
    if (gss_stub_accept_mode == GSS_STUB_ACCEPT_FAIL_TOK) {
        return -1;
    }

    if (gss_stub_accept_mode == GSS_STUB_ACCEPT_CONTINUE && ctx->legs < 2) {
        *complete = 0;
        return 0;
    }

    *complete = 1;
    snprintf(principal, principal_sz, "stub@LIBEVPL.TEST");
    return 0;
} /* gss_stub_accept */

static int
gss_stub_get_mic(
    void       *provider_arg,
    void       *gss_ctx,
    const void *msg,
    size_t      msg_len,
    void      **mic,
    size_t     *mic_len)
{
    uint8_t *out;

    /* Only the integrity databody is signed with anything other than a
     * four-byte message; see gss_stub.h. */
    if (msg_len != sizeof(uint32_t)) {
        if (gss_stub_mic_mode == GSS_STUB_MIC_FAIL_BODY) {
            return -1;
        }
        if (gss_stub_mic_mode == GSS_STUB_MIC_HUGE_BODY) {
            out = malloc(GSS_STUB_MIC_HUGE_LEN);
            if (!out) {
                return -1;
            }
            memset(out, 0xa5, GSS_STUB_MIC_HUGE_LEN);
            *mic     = out;
            *mic_len = GSS_STUB_MIC_HUGE_LEN;
            return 0;
        }
    }

    out = malloc(GSS_STUB_MIC_LEN);

    if (!out) {
        return -1;
    }

    gss_stub_mic(msg, msg_len, out);
    *mic     = out;
    *mic_len = GSS_STUB_MIC_LEN;
    return 0;
} /* gss_stub_get_mic */

static int
gss_stub_verify_mic(
    void       *provider_arg,
    void       *gss_ctx,
    const void *msg,
    size_t      msg_len,
    const void *mic,
    size_t      mic_len)
{
    uint8_t expect[GSS_STUB_MIC_LEN];

    if (gss_stub_verify_mode == GSS_STUB_VERIFY_REJECT) {
        return -1;
    }

    if (mic_len != GSS_STUB_MIC_LEN) {
        return -1;
    }

    gss_stub_mic(msg, msg_len, expect);
    return memcmp(expect, mic, GSS_STUB_MIC_LEN) == 0 ? 0 : -1;
} /* gss_stub_verify_mic */

/*
 * Privacy (krb5p).  gss_stub_seal() is the whole mechanism; see its comment in
 * gss_stub.h for why a reversible toy is the right shape here and what it has
 * to guarantee.  Both directions allocate with malloc(), matching the
 * ownership the vtable specifies: the caller frees what it is handed.
 */
static int
gss_stub_wrap(
    void       *provider_arg,
    void       *gss_ctx,
    const void *in,
    size_t      in_len,
    void       *out,
    size_t      out_cap,
    size_t     *r_out_len)
{
    size_t len;

    if (gss_stub_wrap_mode == GSS_STUB_WRAP_FAIL) {
        return -1;
    }

    len = gss_stub_seal(in, in_len, out, out_cap);
    if (len == 0) {
        return -1;
    }

    *r_out_len = len;
    return 0;
} /* gss_stub_wrap */

static int
gss_stub_unwrap(
    void       *provider_arg,
    void       *gss_ctx,
    const void *in,
    size_t      in_len,
    void       *out,
    size_t      out_cap,
    size_t     *r_out_len)
{
    const uint8_t *tok = in;
    uint8_t        mic[GSS_STUB_MIC_LEN];
    uint8_t       *plain = out;
    uint32_t       plain_len;
    size_t         i;

    if (in_len < GSS_STUB_SEAL_OVERHEAD) {
        return -1;
    }

    plain_len = ((uint32_t) tok[0] << 24) | ((uint32_t) tok[1] << 16) |
        ((uint32_t) tok[2] << 8) | tok[3];

    /* The length is inside the token, so a truncated or oversized claim is
     * itself evidence of tampering rather than something to trust. */
    if ((size_t) plain_len + GSS_STUB_SEAL_OVERHEAD != in_len) {
        return -1;
    }

    /* A plaintext is never larger than its token, so a caller that sized the
     * buffer from the token always has room; refuse rather than truncate if
     * one did not. */
    if (plain_len > out_cap) {
        return -1;
    }

    for (i = 0; i < plain_len; i++) {
        plain[i] = tok[4 + i] ^ gss_stub_keystream(i);
    }

    /* Tamper-evidence: a flipped bit anywhere in the sealed body changes the
     * recovered plaintext, and the MIC over that plaintext no longer matches. */
    gss_stub_mic(plain, plain_len, mic);
    if (memcmp(mic, tok + 4 + plain_len, GSS_STUB_MIC_LEN) != 0) {
        return -1;
    }

    *r_out_len = plain_len;
    return 0;
} /* gss_stub_unwrap */

static void
gss_stub_destroy(
    void *provider_arg,
    void *gss_ctx)
{
    struct gss_stub_ctx *ctx = gss_ctx;

    if (ctx && ctx->magic == GSS_STUB_MAGIC) {
        ctx->magic = 0;
        free(ctx);
    }
} /* gss_stub_destroy */

static const struct evpl_rpc2_gss_provider gss_stub_vtable = {
    .accept     = gss_stub_accept,
    .get_mic    = gss_stub_get_mic,
    .verify_mic = gss_stub_verify_mic,
    .wrap       = gss_stub_wrap,
    .unwrap     = gss_stub_unwrap,
    .destroy    = gss_stub_destroy,
};

const struct evpl_rpc2_gss_provider *
gss_stub_provider(void)
{
    return &gss_stub_vtable;
} /* gss_stub_provider */
