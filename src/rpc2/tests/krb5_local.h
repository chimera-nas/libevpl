/*
 * SPDX-FileCopyrightText: 2026 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL-2.1-only
 *
 * A self-contained Kerberos realm for tests: real MIT krb5, no KDC.
 *
 * gss_stub.c exists because a real mechanism cannot be told to fail on demand,
 * and the defect taxonomy is most of what the RPCSEC_GSS model asserts.  This
 * is the other half of the picture: it cannot fail on command, but everything
 * it does is real -- real AES keys, real AP-REQ tokens, real MICs -- so it is
 * what says that libevpl's framing and an actual GSS mechanism interoperate.
 * The two are complementary and both are registered.
 *
 * The trick is that a KDC's only job in this exchange is to issue a service
 * ticket.  Owning the service key means the ticket can be minted directly, so
 * both ends run the real gssapi_krb5 mechanism with nothing outside the
 * process: no KDC, no realm, no keytab file, no ccache file.
 *
 * Because rpc2 implements only the ACCEPTOR half of RPCSEC_GSS (a real client
 * initiates via rpc.gssd), a driver has to play the initiator itself.  Both
 * halves are exposed here: the provider for evpl_rpc2_set_gss_provider(), and
 * the initiator entry points a driver needs to build a call the acceptor will
 * accept.
 */
#pragma once

#include <stddef.h>

struct evpl_rpc2_gss_provider;
struct krb5_local;

/*
 * Stand up the realm.  Returns NULL when krb5 is unavailable or refuses --
 * callers should skip rather than fail, the same way the KVM kerberos tests
 * do.  `reason` (optional) receives a static string explaining a NULL.
 */
struct krb5_local *
krb5_local_create(
    const char **reason);

/*
 * As krb5_local_create(), but naming the principal the initiator presents.
 *
 * "user" builds a one-component name and "svc/host" a two-component service
 * principal; the realm is the harness's own either way.  A consumer that maps
 * an authenticated principal to a local identity -- chimera's NFS server maps
 * a service principal to root and an unknown user to anonymous -- has to be
 * able to choose which of those it is presenting.  NULL takes the default.
 */
struct krb5_local *
krb5_local_create_as(
    const char  *client_principal,
    const char **reason);

void
krb5_local_destroy(
    struct krb5_local *kl);

/* The acceptor, for evpl_rpc2_set_gss_provider(). */
/* The initiator's vtable.  Distinct from the acceptor's because the two sign
 * with different contexts; see the comment on krb5_local_i_get_mic. */
const struct evpl_rpc2_gss_provider *
krb5_local_initiator_provider(
    void);

const struct evpl_rpc2_gss_provider *
krb5_local_provider(
    void);

/* The same provider with verify_mic_iov withheld, so a test can drive rpc2's
 * gathering fallback even on a host whose krb5 has the IOV extension. */
const struct evpl_rpc2_gss_provider *
krb5_local_provider_noiov(
    void);

void *
krb5_local_arg(
    struct krb5_local *kl);

/*
 * Whether this build's krb5 offers gss_verify_mic_iov().  The provider only
 * advertises verify_mic_iov when it does, which is what lets a test drive both
 * the scattered path and the gathering fallback rather than whichever one the
 * host happens to have.
 */
int
krb5_local_have_iov(
    void);

/* Ask the provider to hide verify_mic_iov, forcing rpc2's gather fallback. */
void
krb5_local_set_iov_enabled(
    struct krb5_local *kl,
    int                enabled);

/*
 * Initiator side.  The AP-REQ to put in an RPCSEC_GSS_INIT call; the caller
 * frees it with free().
 */
int
krb5_local_init_token(
    struct krb5_local *kl,
    void             **token,
    size_t            *token_len);

/* A real MIC over msg, as the initiator.  Caller frees with free(). */
int
krb5_local_get_mic(
    struct krb5_local *kl,
    const void        *msg,
    size_t             msg_len,
    void             **mic,
    size_t            *mic_len);

/* Verify a MIC the acceptor produced (a reply verifier). */
int
krb5_local_verify_mic(
    struct krb5_local *kl,
    const void        *msg,
    size_t             msg_len,
    const void        *mic,
    size_t             mic_len);

/* Seal/unseal as the initiator, for krb5p. */
int
krb5_local_wrap(
    struct krb5_local *kl,
    const void        *in,
    size_t             in_len,
    void             **out,
    size_t            *out_len);

int
krb5_local_unwrap(
    struct krb5_local *kl,
    const void        *in,
    size_t             in_len,
    void             **out,
    size_t            *out_len);
