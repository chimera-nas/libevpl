// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * krb5_local for builds without MIT krb5.
 *
 * Compiled in place of krb5_local.c so the driver needs no conditional
 * compilation of its own: asking for the Kerberos mechanism on a host that
 * has none simply reports why, and the caller skips.  Keeping the branch in
 * the build rather than in the code means the krb5 path is either wholly
 * present or wholly absent, never half-compiled.
 */

#include <stddef.h>

#include "krb5_local.h"

struct krb5_local *
krb5_local_create(const char **reason)
{
    if (reason) {
        *reason = "built without MIT krb5";
    }
    return NULL;
} /* krb5_local_create */

struct krb5_local *
krb5_local_create_as(
    const char  *client_principal,
    const char **reason)
{
    (void) client_principal;
    return krb5_local_create(reason);
} /* krb5_local_create_as */

void
krb5_local_destroy(struct krb5_local *kl)
{
    (void) kl;
} /* krb5_local_destroy */

const struct evpl_rpc2_gss_provider *
krb5_local_provider(void)
{
    return NULL;
} /* krb5_local_provider */

const struct evpl_rpc2_gss_provider *
krb5_local_initiator_provider(void)
{
    return NULL;
} /* krb5_local_initiator_provider */

const struct evpl_rpc2_gss_provider *
krb5_local_provider_noiov(void)
{
    return NULL;
} /* krb5_local_provider_noiov */

void *
krb5_local_arg(struct krb5_local *kl)
{
    (void) kl;
    return NULL;
} /* krb5_local_arg */

int
krb5_local_have_iov(void)
{
    return 0;
} /* krb5_local_have_iov */

void
krb5_local_set_iov_enabled(
    struct krb5_local *kl,
    int                enabled)
{
    (void) kl;
    (void) enabled;
} /* krb5_local_set_iov_enabled */

int
krb5_local_init_token(
    struct krb5_local *kl,
    void             **token,
    size_t            *token_len)
{
    (void) kl;
    (void) token;
    (void) token_len;
    return -1;
} /* krb5_local_init_token */

int
krb5_local_get_mic(
    struct krb5_local *kl,
    const void        *msg,
    size_t             msg_len,
    void             **mic,
    size_t            *mic_len)
{
    (void) kl;
    (void) msg;
    (void) msg_len;
    (void) mic;
    (void) mic_len;
    return -1;
} /* krb5_local_get_mic */

int
krb5_local_verify_mic(
    struct krb5_local *kl,
    const void        *msg,
    size_t             msg_len,
    const void        *mic,
    size_t             mic_len)
{
    (void) kl;
    (void) msg;
    (void) msg_len;
    (void) mic;
    (void) mic_len;
    return -1;
} /* krb5_local_verify_mic */

int
krb5_local_wrap(
    struct krb5_local *kl,
    const void        *in,
    size_t             in_len,
    void             **out,
    size_t            *out_len)
{
    (void) kl;
    (void) in;
    (void) in_len;
    (void) out;
    (void) out_len;
    return -1;
} /* krb5_local_wrap */

int
krb5_local_unwrap(
    struct krb5_local *kl,
    const void        *in,
    size_t             in_len,
    void             **out,
    size_t            *out_len)
{
    (void) kl;
    (void) in;
    (void) in_len;
    (void) out;
    (void) out_len;
    return -1;
} /* krb5_local_unwrap */
