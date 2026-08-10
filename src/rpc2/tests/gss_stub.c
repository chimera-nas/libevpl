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
 * Privacy (krb5p) is not implemented by rpc2.c, which rejects the service with
 * AUTH_TOOWEAK before ever reaching a provider.  These exist to complete the
 * vtable and to fail loudly if that ever changes without the stub keeping up.
 */
static int
gss_stub_wrap(
    void       *provider_arg,
    void       *gss_ctx,
    const void *in,
    size_t      in_len,
    void      **out,
    size_t     *out_len)
{
    return -1;
} /* gss_stub_wrap */

static int
gss_stub_unwrap(
    void       *provider_arg,
    void       *gss_ctx,
    const void *in,
    size_t      in_len,
    void      **out,
    size_t     *out_len)
{
    return -1;
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
