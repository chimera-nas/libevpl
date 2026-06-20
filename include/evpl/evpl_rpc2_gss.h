// SPDX-FileCopyrightText: 2025-2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

/*
 * RPCSEC_GSS provider interface (RFC 2203 / RFC 5403).
 *
 * libevpl's rpc2 layer implements the RPCSEC_GSS wire framing and state
 * machine (the rpc_gss_cred_t credential, the context-establishment
 * handshake over the program NULL procedure, the per-request verifier and
 * sequence window, and integrity/privacy wrapping of the argument and
 * result streams).  It deliberately does NOT link a GSS mechanism such as
 * Kerberos -- libevpl is a generic networking library.
 *
 * Instead, a host application (e.g. the chimera NFS server) registers a
 * provider: a small vtable wrapping the GSSAPI primitives.  libevpl calls
 * into it to accept security contexts and to sign/verify/seal individual
 * messages, while owning all of the RPC-level framing itself.
 *
 * All callbacks return 0 on success and -1 on failure.  Buffers returned
 * through the `out`/`out_len` out-parameters are allocated by the provider
 * with malloc(); libevpl frees them with free() after use.
 */

#include <stdint.h>
#include <stddef.h>

struct evpl_rpc2_thread;

/* RPCSEC_GSS services (rpc_gss_service_t, RFC 2203 sec 5). */
#define EVPL_RPC2_GSS_SVC_NONE      1   /* krb5  -- authentication only      */
#define EVPL_RPC2_GSS_SVC_INTEGRITY 2   /* krb5i -- per-message MIC          */
#define EVPL_RPC2_GSS_SVC_PRIVACY   3   /* krb5p -- per-message wrap/encrypt */

/* Maximum length of a textual principal name we surface to the host. */
#define EVPL_RPC2_GSS_PRINCIPAL_MAX 256

struct evpl_rpc2_gss_provider {
    /*
     * Feed one leg of the context-establishment token exchange into
     * gss_accept_sec_context().  *gss_ctx is an opaque per-context cookie:
     * NULL on the first call (the provider allocates one), and the value
     * the provider stored on prior calls thereafter.
     *
     * On a successful but incomplete exchange, sets *complete=0 and returns
     * an output token to relay to the client.  On completion, sets
     * *complete=1, fills `principal` with the authenticated source name
     * (NUL-terminated), and may still return a final output token.
     *
     * Returns 0 on success (continue or complete), -1 on a GSS error.
     */
    int  (*accept)(
        void       *provider_arg,
        void      **gss_ctx,
        const void *in_token,
        size_t      in_len,
        void      **out_token,
        size_t     *out_len,
        int        *complete,
        char       *principal,
        size_t      principal_sz);

    /* Compute a MIC (gss_get_mic) over msg; used for reply verifiers. */
    int  (*get_mic)(
        void       *provider_arg,
        void       *gss_ctx,
        const void *msg,
        size_t      msg_len,
        void      **mic,
        size_t     *mic_len);

    /* Verify a MIC (gss_verify_mic); used for call verifiers / krb5i. */
    int  (*verify_mic)(
        void       *provider_arg,
        void       *gss_ctx,
        const void *msg,
        size_t      msg_len,
        const void *mic,
        size_t      mic_len);

    /* Seal a message (gss_wrap, conf_req=1); krb5p only. */
    int  (*wrap)(
        void       *provider_arg,
        void       *gss_ctx,
        const void *in,
        size_t      in_len,
        void      **out,
        size_t     *out_len);

    /* Unseal a message (gss_unwrap); krb5p only. */
    int  (*unwrap)(
        void       *provider_arg,
        void       *gss_ctx,
        const void *in,
        size_t      in_len,
        void      **out,
        size_t     *out_len);

    /* Destroy a context (gss_delete_sec_context). */
    void (*destroy)(
        void *provider_arg,
        void *gss_ctx);
};

/*
 * Register a GSS provider on an rpc2 thread.  Must be called before the
 * thread begins servicing RPCSEC_GSS traffic (typically at server start,
 * once per rpc2 thread).  Passing NULL disables RPCSEC_GSS on the thread:
 * flavor-6 calls are then rejected with AUTH_REJECTEDCRED.
 *
 * The provider vtable and provider_arg must outlive the thread.
 */
void
evpl_rpc2_set_gss_provider(
    struct evpl_rpc2_thread             *thread,
    const struct evpl_rpc2_gss_provider *provider,
    void                                *provider_arg);
