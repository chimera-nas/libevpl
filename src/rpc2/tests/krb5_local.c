// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdlib.h>
#include <string.h>
#include <stdio.h>

#include <krb5.h>
#include <gssapi/gssapi.h>
#include <gssapi/gssapi_krb5.h>

#if defined(__has_include)
#if __has_include(<gssapi/gssapi_ext.h>)
#include <gssapi/gssapi_ext.h>
#endif /* __has_include */
#endif /* defined(__has_include) */

#include "evpl/evpl.h"
#include "evpl/evpl_rpc2.h"
#include "evpl/evpl_rpc2_gss.h"
#include "krb5_local.h"

/*
 * Exported by libkrb5 but not declared in its public headers.  These are what
 * mint a ticket without a KDC: the first seals the ticket's encrypted part
 * under the service key, the second serialises the result.  Both have been
 * stable exports for the life of MIT krb5, and the failure mode if a release
 * ever drops them is a test that does not link -- not a runtime surprise.
 */
extern krb5_error_code krb5_encrypt_tkt_part(
    krb5_context,
    const krb5_keyblock *,
    krb5_ticket *);

extern krb5_error_code encode_krb5_ticket(
    const krb5_ticket *,
    krb5_data **);

#define KRB5_LOCAL_REALM   "TEST.LIBEVPL"
#define KRB5_LOCAL_SERVICE "libevpl"
#define KRB5_LOCAL_HOST    "localhost"
#define KRB5_LOCAL_USER    "conformance"

struct krb5_local {
    krb5_context   ctx;
    krb5_principal client;
    krb5_principal server;
    krb5_keytab    keytab;
    krb5_ccache    ccache;

    /* The initiator's context, established lazily by the first init_token. */
    gss_cred_id_t  init_cred;
    gss_ctx_id_t   init_ctx;

    /* The acceptor's credential; contexts are per-exchange and owned by rpc2
     * through the provider's gss_ctx cookie. */
    gss_cred_id_t  accept_cred;

    int            iov_enabled;
};

/* ------------------------------------------------------------------ */
/* Realm construction                                                   */
/* ------------------------------------------------------------------ */

/*
 * Mint the service ticket a KDC would have issued, and leave it in the
 * initiator's memory ccache.  This is the whole trick: an AP-REQ needs only
 * the service ticket, and the service key is ours, so nothing has to be asked
 * of anybody.
 */
static int
krb5_local_mint(
    struct krb5_local   *kl,
    const krb5_keyblock *svckey)
{
    krb5_enc_tkt_part enc;
    krb5_ticket       tkt;
    krb5_creds        creds;
    krb5_keyblock     seskey;
    krb5_data        *tktdata = NULL;
    krb5_timestamp    now;
    int               rc = -1;

    memset(&enc, 0, sizeof(enc));
    memset(&tkt, 0, sizeof(tkt));
    memset(&creds, 0, sizeof(creds));
    memset(&seskey, 0, sizeof(seskey));

    if (krb5_c_make_random_key(kl->ctx, svckey->enctype, &seskey)) {
        return -1;
    }

    if (krb5_timeofday(kl->ctx, &now)) {
        goto out;
    }

    enc.flags                        = TKT_FLG_INITIAL;
    enc.session                      = &seskey;
    enc.client                       = kl->client;
    enc.times.authtime               = now;
    enc.times.starttime              = now;
    enc.times.endtime                = now + 3600;
    enc.transited.tr_type            = KRB5_DOMAIN_X500_COMPRESS;
    enc.transited.tr_contents.data   = NULL;
    enc.transited.tr_contents.length = 0;

    tkt.server    = kl->server;
    tkt.enc_part2 = &enc;

    if (krb5_encrypt_tkt_part(kl->ctx, svckey, &tkt)) {
        goto out;
    }

    if (encode_krb5_ticket(&tkt, &tktdata)) {
        goto out;
    }

    creds.client       = kl->client;
    creds.server       = kl->server;
    creds.keyblock     = seskey;
    creds.times        = enc.times;
    creds.ticket_flags = enc.flags;
    creds.ticket       = *tktdata;

    if (krb5_cc_initialize(kl->ctx, kl->ccache, kl->client)) {
        goto out;
    }

    if (krb5_cc_store_cred(kl->ctx, kl->ccache, &creds)) {
        goto out;
    }

    rc = 0;

 out:
    if (tktdata) {
        krb5_free_data(kl->ctx, tktdata);
    }
    if (tkt.enc_part.ciphertext.data) {
        free(tkt.enc_part.ciphertext.data);
    }
    krb5_free_keyblock_contents(kl->ctx, &seskey);
    return rc;
} /* krb5_local_mint */

struct krb5_local *
krb5_local_create_as(
    const char  *client_principal,
    const char **reason)
{
    struct krb5_local *kl;
    krb5_keyblock      svckey;
    krb5_keytab_entry  kte;
    OM_uint32          maj, min;
    const char        *why = "krb5 unavailable";

    kl = calloc(1, sizeof(*kl));

    if (!kl) {
        goto fail;
    }

    kl->init_cred   = GSS_C_NO_CREDENTIAL;
    kl->accept_cred = GSS_C_NO_CREDENTIAL;
    kl->init_ctx    = GSS_C_NO_CONTEXT;
    kl->iov_enabled = 1;

    memset(&svckey, 0, sizeof(svckey));
    memset(&kte, 0, sizeof(kte));

    /* Each case shakes hands again, so the same client sends many AP-REQs
     * within a second.  The replay cache exists to refuse exactly that, and
     * here it would be refusing the test rather than an attacker -- and would
     * write cache files besides, which a self-contained realm should not. */
    setenv("KRB5RCACHETYPE", "none", 1);

    if (krb5_init_context(&kl->ctx)) {
        why = "krb5_init_context failed";
        goto fail;
    }

    {
        char        namebuf[256];
        char       *slash;
        const char *name = client_principal ? client_principal : KRB5_LOCAL_USER;
        int         built;

        if (strlen(name) >= sizeof(namebuf)) {
            why = "client principal too long";
            goto fail;
        }

        strcpy(namebuf, name);
        slash = strchr(namebuf, '/');

        /* A two-component name ("nfs/host") is a service principal, which is
         * a different thing to the acceptor than a one-component user name --
         * and what a consumer maps to a local identity turns on exactly that
         * distinction. */
        if (slash) {
            *slash = '\0';
            built = krb5_build_principal(kl->ctx, &kl->client,
                                         strlen(KRB5_LOCAL_REALM),
                                         KRB5_LOCAL_REALM, namebuf, slash + 1,
                                         NULL);
        } else {
            built = krb5_build_principal(kl->ctx, &kl->client,
                                         strlen(KRB5_LOCAL_REALM),
                                         KRB5_LOCAL_REALM, namebuf, NULL);
        }

        if (built ||
            krb5_build_principal(kl->ctx, &kl->server, strlen(KRB5_LOCAL_REALM),
                                 KRB5_LOCAL_REALM, KRB5_LOCAL_SERVICE,
                                 KRB5_LOCAL_HOST, NULL)) {
            why = "krb5_build_principal failed";
            goto fail;
        }
    }

    /* AES-256 rather than whatever the host's default happens to be, so the
     * enctype is a property of the test and not of /etc/krb5.conf. */
    if (krb5_c_make_random_key(kl->ctx, ENCTYPE_AES256_CTS_HMAC_SHA1_96,
                               &svckey)) {
        why = "no aes256 support";
        goto fail;
    }

    if (krb5_kt_resolve(kl->ctx, "MEMORY:evpl_krb5_local", &kl->keytab) ||
        krb5_cc_resolve(kl->ctx, "MEMORY:evpl_krb5_local", &kl->ccache)) {
        why = "MEMORY: keytab/ccache unavailable";
        goto fail;
    }

    kte.principal = kl->server;
    kte.vno       = 1;
    kte.key       = svckey;

    if (krb5_kt_add_entry(kl->ctx, kl->keytab, &kte)) {
        why = "krb5_kt_add_entry failed";
        goto fail;
    }

    if (krb5_local_mint(kl, &svckey)) {
        why = "could not mint a service ticket";
        goto fail;
    }

    maj = gss_krb5_import_cred(&min, kl->ccache, NULL, NULL, &kl->init_cred);

    if (GSS_ERROR(maj)) {
        why = "gss_krb5_import_cred (initiator) failed";
        goto fail;
    }

    maj = gss_krb5_import_cred(&min, NULL, kl->server, kl->keytab,
                               &kl->accept_cred);

    if (GSS_ERROR(maj)) {
        why = "gss_krb5_import_cred (acceptor) failed";
        goto fail;
    }

    krb5_free_keyblock_contents(kl->ctx, &svckey);

    return kl;

 fail:
    if (reason) {
        *reason = why;
    }
    if (kl) {
        krb5_local_destroy(kl);
    }
    return NULL;
} /* krb5_local_create_as */

struct krb5_local *
krb5_local_create(const char **reason)
{
    return krb5_local_create_as(NULL, reason);
} /* krb5_local_create */

void
krb5_local_destroy(struct krb5_local *kl)
{
    OM_uint32 min;

    if (!kl) {
        return;
    }

    if (kl->init_ctx != GSS_C_NO_CONTEXT) {
        gss_delete_sec_context(&min, &kl->init_ctx, GSS_C_NO_BUFFER);
    }
    if (kl->init_cred != GSS_C_NO_CREDENTIAL) {
        gss_release_cred(&min, &kl->init_cred);
    }
    if (kl->accept_cred != GSS_C_NO_CREDENTIAL) {
        gss_release_cred(&min, &kl->accept_cred);
    }

    if (kl->ctx) {
        if (kl->keytab) {
            krb5_kt_close(kl->ctx, kl->keytab);
        }
        if (kl->ccache) {
            krb5_cc_destroy(kl->ctx, kl->ccache);
        }
        if (kl->client) {
            krb5_free_principal(kl->ctx, kl->client);
        }
        if (kl->server) {
            krb5_free_principal(kl->ctx, kl->server);
        }
        krb5_free_context(kl->ctx);
    }

    free(kl);
} /* krb5_local_destroy */

void *
krb5_local_arg(struct krb5_local *kl)
{
    return kl;
} /* krb5_local_arg */

int
krb5_local_have_iov(void)
{
#ifdef GSS_IOV_BUFFER_TYPE_MIC_TOKEN
    return 1;
#else  /* ifdef GSS_IOV_BUFFER_TYPE_MIC_TOKEN */
    return 0;
#endif /* ifdef GSS_IOV_BUFFER_TYPE_MIC_TOKEN */
} /* krb5_local_have_iov */

void
krb5_local_set_iov_enabled(
    struct krb5_local *kl,
    int                enabled)
{
    kl->iov_enabled = enabled;
} /* krb5_local_set_iov_enabled */

/* ------------------------------------------------------------------ */
/* Initiator                                                            */
/* ------------------------------------------------------------------ */

/*
 * Establish (or re-establish) the initiator context.
 *
 * RPCSEC_GSS creates one security context per handshake, and the driver runs
 * a handshake per case, so each case needs its own: a MIC only verifies
 * against the acceptor context grown from the same AP-REQ.  Cases that skip
 * the handshake entirely -- a DATA call naming a handle the server never
 * issued, say -- still have to put SOMETHING in the verifier, so one is
 * created on demand for them too and the token thrown away.
 */
static int
krb5_local_new_context(
    struct krb5_local *kl,
    void             **token,
    size_t            *token_len)
{
    OM_uint32       maj, min, flags;
    gss_name_t      target = GSS_C_NO_NAME;
    gss_buffer_desc nb, tok = GSS_C_EMPTY_BUFFER;
    char            name[256];
    int             rc = -1;

    snprintf(name, sizeof(name), "%s/%s@%s", KRB5_LOCAL_SERVICE,
             KRB5_LOCAL_HOST, KRB5_LOCAL_REALM);

    nb.value  = name;
    nb.length = strlen(name);

    maj = gss_import_name(&min, &nb, (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME,
                          &target);

    if (GSS_ERROR(maj)) {
        return -1;
    }

    /* Start from nothing: a stale context would sign with the wrong session
     * key for the acceptor context this handshake is about to create. */
    if (kl->init_ctx != GSS_C_NO_CONTEXT) {
        gss_delete_sec_context(&min, &kl->init_ctx, GSS_C_NO_BUFFER);
        kl->init_ctx = GSS_C_NO_CONTEXT;
    }

    maj = gss_init_sec_context(&min, kl->init_cred, &kl->init_ctx, target,
                               GSS_C_NO_OID,
                               GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG |
                               GSS_C_SEQUENCE_FLAG,
                               0, GSS_C_NO_CHANNEL_BINDINGS, GSS_C_NO_BUFFER,
                               NULL, &tok, &flags, NULL);

    if (!GSS_ERROR(maj) && tok.length) {
        if (token) {
            *token = malloc(tok.length);
            if (*token) {
                memcpy(*token, tok.value, tok.length);
                *token_len = tok.length;
                rc         = 0;
            }
        } else {
            rc = 0;
        }
    }

    gss_release_buffer(&min, &tok);
    gss_release_name(&min, &target);
    return rc;
} /* krb5_local_new_context */

int
krb5_local_init_token(
    struct krb5_local *kl,
    void             **token,
    size_t            *token_len)
{
    return krb5_local_new_context(kl, token, token_len);
} /* krb5_local_init_token */

/* Whatever context is current, creating one if a case never shook hands. */
static int
krb5_local_ensure_context(struct krb5_local *kl)
{
    if (kl->init_ctx != GSS_C_NO_CONTEXT) {
        return 0;
    }

    return krb5_local_new_context(kl, NULL, NULL);
} /* krb5_local_ensure_context */

static int
krb5_local_buf_out(
    gss_buffer_desc *in,
    void           **out,
    size_t          *out_len)
{
    *out = malloc(in->length ? in->length : 1);

    if (!*out) {
        return -1;
    }

    memcpy(*out, in->value, in->length);
    *out_len = in->length;
    return 0;
} /* krb5_local_buf_out */

int
krb5_local_get_mic(
    struct krb5_local *kl,
    const void        *msg,
    size_t             msg_len,
    void             **mic,
    size_t            *mic_len)
{
    OM_uint32       maj, min;
    gss_buffer_desc in, out = GSS_C_EMPTY_BUFFER;
    int             rc;

    if (krb5_local_ensure_context(kl)) {
        return -1;
    }

    in.value  = (void *) msg;
    in.length = msg_len;

    maj = gss_get_mic(&min, kl->init_ctx, GSS_C_QOP_DEFAULT, &in, &out);

    if (GSS_ERROR(maj)) {
        return -1;
    }

    rc = krb5_local_buf_out(&out, mic, mic_len);
    gss_release_buffer(&min, &out);
    return rc;
} /* krb5_local_get_mic */

int
krb5_local_verify_mic(
    struct krb5_local *kl,
    const void        *msg,
    size_t             msg_len,
    const void        *mic,
    size_t             mic_len)
{
    OM_uint32       maj, min;
    gss_buffer_desc in, tok;

    if (krb5_local_ensure_context(kl)) {
        return -1;
    }

    in.value   = (void *) msg;
    in.length  = msg_len;
    tok.value  = (void *) mic;
    tok.length = mic_len;

    maj = gss_verify_mic(&min, kl->init_ctx, &in, &tok, NULL);

    return GSS_ERROR(maj) ? -1 : 0;
} /* krb5_local_verify_mic */

int
krb5_local_wrap(
    struct krb5_local *kl,
    const void        *in_buf,
    size_t             in_len,
    void             **out,
    size_t            *out_len)
{
    OM_uint32       maj, min;
    gss_buffer_desc in, o = GSS_C_EMPTY_BUFFER;
    int             conf, rc;

    if (krb5_local_ensure_context(kl)) {
        return -1;
    }

    in.value  = (void *) in_buf;
    in.length = in_len;

    maj = gss_wrap(&min, kl->init_ctx, 1, GSS_C_QOP_DEFAULT, &in, &conf, &o);

    if (GSS_ERROR(maj)) {
        return -1;
    }

    rc = krb5_local_buf_out(&o, out, out_len);
    gss_release_buffer(&min, &o);
    return rc;
} /* krb5_local_wrap */

int
krb5_local_unwrap(
    struct krb5_local *kl,
    const void        *in_buf,
    size_t             in_len,
    void             **out,
    size_t            *out_len)
{
    OM_uint32       maj, min;
    gss_buffer_desc in, o = GSS_C_EMPTY_BUFFER;
    int             conf, rc;
    gss_qop_t       qop;

    if (krb5_local_ensure_context(kl)) {
        return -1;
    }

    in.value  = (void *) in_buf;
    in.length = in_len;

    maj = gss_unwrap(&min, kl->init_ctx, &in, &o, &conf, &qop);

    if (GSS_ERROR(maj)) {
        return -1;
    }

    rc = krb5_local_buf_out(&o, out, out_len);
    gss_release_buffer(&min, &o);
    return rc;
} /* krb5_local_unwrap */

/* ------------------------------------------------------------------ */
/* Acceptor: the provider rpc2 calls into                               */
/*                                                                      */
/* Deliberately the same shape as a production provider (chimera's      */
/* nfs_gss.c): the point of running rpc2's framing against this is that */
/* it is a real mechanism behaving as one, not a stub with predictable  */
/* answers.                                                             */
/* ------------------------------------------------------------------ */

struct krb5_local_ctx {
    gss_ctx_id_t ctx;
};

static int
krb5_local_accept(
    void       *arg,
    void      **gss_ctx,
    const void *in_token,
    size_t      in_len,
    void      **out_token,
    size_t     *out_len,
    int        *complete,
    char       *principal,
    size_t      principal_sz)
{
    struct krb5_local     *kl = arg;
    struct krb5_local_ctx *lc = *gss_ctx;
    OM_uint32              maj, min, flags;
    gss_buffer_desc        in, out = GSS_C_EMPTY_BUFFER, nb = GSS_C_EMPTY_BUFFER;
    gss_name_t             src = GSS_C_NO_NAME;

    if (!lc) {
        lc = calloc(1, sizeof(*lc));
        if (!lc) {
            return -1;
        }
        lc->ctx  = GSS_C_NO_CONTEXT;
        *gss_ctx = lc;
    }

    in.value  = (void *) in_token;
    in.length = in_len;

    maj = gss_accept_sec_context(&min, &lc->ctx, kl->accept_cred, &in,
                                 GSS_C_NO_CHANNEL_BINDINGS, &src, NULL,
                                 &out, &flags, NULL, NULL);

    if (GSS_ERROR(maj)) {
        /* A rejection may still carry a token the peer should see; rpc2
         * relays it and frees it. */
        if (out.length && krb5_local_buf_out(&out, out_token, out_len) == 0) {
            gss_release_buffer(&min, &out);
            return -1;
        }
        gss_release_buffer(&min, &out);
        return -1;
    }

    *complete = (maj == GSS_S_COMPLETE);

    if (*complete && src != GSS_C_NO_NAME) {
        if (gss_display_name(&min, src, &nb, NULL) == GSS_S_COMPLETE) {
            size_t n = nb.length < principal_sz - 1 ? nb.length
                                                    : principal_sz - 1;
            memcpy(principal, nb.value, n);
            principal[n] = '\0';
            gss_release_buffer(&min, &nb);
        }
    }

    gss_release_name(&min, &src);

    *out_token = NULL;
    *out_len   = 0;

    if (out.length) {
        krb5_local_buf_out(&out, out_token, out_len);
    }

    gss_release_buffer(&min, &out);

    return 0;
} /* krb5_local_accept */

static int
krb5_local_p_get_mic(
    void       *arg,
    void       *gss_ctx,
    const void *msg,
    size_t      msg_len,
    void      **mic,
    size_t     *mic_len)
{
    struct krb5_local_ctx *lc = gss_ctx;
    OM_uint32              maj, min;
    gss_buffer_desc        in, out = GSS_C_EMPTY_BUFFER;
    int                    rc;

    (void) arg;

    in.value  = (void *) msg;
    in.length = msg_len;

    maj = gss_get_mic(&min, lc->ctx, GSS_C_QOP_DEFAULT, &in, &out);

    if (GSS_ERROR(maj)) {
        return -1;
    }

    rc = krb5_local_buf_out(&out, mic, mic_len);
    gss_release_buffer(&min, &out);
    return rc;
} /* krb5_local_p_get_mic */

static int
krb5_local_p_verify_mic(
    void       *arg,
    void       *gss_ctx,
    const void *msg,
    size_t      msg_len,
    const void *mic,
    size_t      mic_len)
{
    struct krb5_local_ctx *lc = gss_ctx;
    OM_uint32              maj, min;
    gss_buffer_desc        in, tok;

    (void) arg;

    in.value   = (void *) msg;
    in.length  = msg_len;
    tok.value  = (void *) mic;
    tok.length = mic_len;

    maj = gss_verify_mic(&min, lc->ctx, &in, &tok, NULL);

    return GSS_ERROR(maj) ? -1 : 0;
} /* krb5_local_p_verify_mic */

#ifdef GSS_IOV_BUFFER_TYPE_MIC_TOKEN

/* The scattered form.  This is the entry point that lets rpc2 verify a krb5i
 * databody where it already lies in the receive buffers instead of gathering
 * an NFS-WRITE-sized payload into one block. */
static int
krb5_local_p_verify_mic_iov(
    void                    *arg,
    void                    *gss_ctx,
    const struct evpl_iovec *iov,
    int                      niov,
    const void              *mic,
    size_t                   mic_len)
{
    struct krb5_local_ctx *lc = gss_ctx;
    gss_iov_buffer_desc    stack[16], *bufs = stack;
    OM_uint32              maj, min;
    int                    i, rc = -1;

    (void) arg;

    if (niov + 1 > (int) (sizeof(stack) / sizeof(stack[0]))) {
        bufs = calloc(niov + 1, sizeof(*bufs));
        if (!bufs) {
            return -1;
        }
    }

    for (i = 0; i < niov; i++) {
        bufs[i].type          = GSS_IOV_BUFFER_TYPE_DATA;
        bufs[i].buffer.value  = evpl_iovec_data(&iov[i]);
        bufs[i].buffer.length = evpl_iovec_length(&iov[i]);
    }

    bufs[niov].type          = GSS_IOV_BUFFER_TYPE_MIC_TOKEN;
    bufs[niov].buffer.value  = (void *) mic;
    bufs[niov].buffer.length = mic_len;

    maj = gss_verify_mic_iov(&min, lc->ctx, NULL, bufs, niov + 1);

    rc = GSS_ERROR(maj) ? -1 : 0;

    if (bufs != stack) {
        free(bufs);
    }

    return rc;
} /* krb5_local_p_verify_mic_iov */

#endif /* ifdef GSS_IOV_BUFFER_TYPE_MIC_TOKEN */

static int
krb5_local_p_wrap(
    void       *arg,
    void       *gss_ctx,
    const void *in_buf,
    size_t      in_len,
    void       *out,
    size_t      out_cap,
    size_t     *r_out_len)
{
    struct krb5_local_ctx *lc = gss_ctx;
    OM_uint32              maj, min;
    gss_buffer_desc        in, o = GSS_C_EMPTY_BUFFER;
    int                    conf;

    (void) arg;

    in.value   = (void *) in_buf;
    in.length  = in_len;
    *r_out_len = 0;

    maj = gss_wrap(&min, lc->ctx, 1, GSS_C_QOP_DEFAULT, &in, &conf, &o);

    if (GSS_ERROR(maj)) {
        return -1;
    }

    /* The mechanism owns o and the caller owns out; refuse rather than
     * truncate if the caller sized its buffer too small, since a silently
     * short token is exactly the kind of thing this suite exists to catch. */
    if (o.length > out_cap) {
        gss_release_buffer(&min, &o);
        return -1;
    }

    memcpy(out, o.value, o.length);
    *r_out_len = o.length;
    gss_release_buffer(&min, &o);
    return 0;
} /* krb5_local_p_wrap */

static int
krb5_local_p_unwrap(
    void       *arg,
    void       *gss_ctx,
    const void *in_buf,
    size_t      in_len,
    void       *out,
    size_t      out_cap,
    size_t     *r_out_len)
{
    struct krb5_local_ctx *lc = gss_ctx;
    OM_uint32              maj, min;
    gss_buffer_desc        in, o = GSS_C_EMPTY_BUFFER;
    int                    conf;
    gss_qop_t              qop;

    (void) arg;

    in.value   = (void *) in_buf;
    in.length  = in_len;
    *r_out_len = 0;

    maj = gss_unwrap(&min, lc->ctx, &in, &o, &conf, &qop);

    if (GSS_ERROR(maj)) {
        return -1;
    }

    /* The mechanism owns o and the caller owns out; refuse rather than
     * truncate if the caller sized its buffer too small, since a silently
     * short token is exactly the kind of thing this suite exists to catch. */
    if (o.length > out_cap) {
        gss_release_buffer(&min, &o);
        return -1;
    }

    memcpy(out, o.value, o.length);
    *r_out_len = o.length;
    gss_release_buffer(&min, &o);
    return 0;
} /* krb5_local_p_unwrap */

static void
krb5_local_p_destroy(
    void *arg,
    void *gss_ctx)
{
    struct krb5_local_ctx *lc = gss_ctx;
    OM_uint32              min;

    (void) arg;

    if (!lc) {
        return;
    }

    if (lc->ctx != GSS_C_NO_CONTEXT) {
        gss_delete_sec_context(&min, &lc->ctx, GSS_C_NO_BUFFER);
    }

    free(lc);
} /* krb5_local_p_destroy */

/*
 * Initiator half of the provider vtable.
 *
 * The acceptor entries above each carry a per-context krb5_local_ctx; the
 * initiator does not, because a client establishes one context at a time
 * against one peer and the whole point of this harness is that both ends live
 * in the same process.  So *gss_ctx is the krb5_local itself, and the mechanism
 * state it hands back is the init_ctx already inside it.
 */
static int
krb5_local_p_init(
    void       *arg,
    void      **gss_ctx,
    const char *target,
    const void *in_token,
    size_t      in_len,
    void      **out_token,
    size_t     *out_len,
    int        *complete)
{
    struct krb5_local *kl = arg;
    OM_uint32          maj, min, flags;
    gss_buffer_desc    in = GSS_C_EMPTY_BUFFER, tok = GSS_C_EMPTY_BUFFER;
    gss_name_t         name = GSS_C_NO_NAME;
    gss_buffer_desc    nb;
    char               principal[256];

    (void) target;

    *out_token = NULL;
    *out_len   = 0;
    *complete  = 0;

    snprintf(principal, sizeof(principal), "%s/%s@%s", KRB5_LOCAL_SERVICE,
             KRB5_LOCAL_HOST, KRB5_LOCAL_REALM);

    nb.value  = principal;
    nb.length = strlen(principal);

    if (GSS_ERROR(gss_import_name(&min, &nb,
                                  (gss_OID) GSS_KRB5_NT_PRINCIPAL_NAME,
                                  &name))) {
        return -1;
    }

    if (!in_token) {
        /* First leg: start clean, so a context left over from an earlier case
         * cannot sign with a session key this handshake never agreed. */
        if (kl->init_ctx != GSS_C_NO_CONTEXT) {
            gss_delete_sec_context(&min, &kl->init_ctx, GSS_C_NO_BUFFER);
            kl->init_ctx = GSS_C_NO_CONTEXT;
        }
    } else {
        in.value  = (void *) in_token;
        in.length = in_len;
    }

    maj = gss_init_sec_context(&min, kl->init_cred, &kl->init_ctx, name,
                               GSS_C_NO_OID,
                               GSS_C_INTEG_FLAG | GSS_C_CONF_FLAG |
                               GSS_C_SEQUENCE_FLAG,
                               0, GSS_C_NO_CHANNEL_BINDINGS,
                               in_token ? &in : GSS_C_NO_BUFFER,
                               NULL, &tok, &flags, NULL);

    gss_release_name(&min, &name);

    if (GSS_ERROR(maj)) {
        return -1;
    }

    if (tok.length) {
        *out_token = malloc(tok.length);
        if (!*out_token) {
            gss_release_buffer(&min, &tok);
            return -1;
        }
        memcpy(*out_token, tok.value, tok.length);
        *out_len = tok.length;
    }

    gss_release_buffer(&min, &tok);

    *complete = (maj == GSS_S_COMPLETE);
    *gss_ctx  = kl;

    return 0;
} /* krb5_local_p_init */

/*
 * The initiator's own vtable entries.
 *
 * These cannot be the acceptor's.  Every acceptor entry above is handed the
 * per-context krb5_local_ctx that accept() minted, and signs with that
 * context's session key; an initiator signs with kl->init_ctx, which is a
 * different context entirely -- the one this side of the handshake built.
 * Passing a krb5_local where a krb5_local_ctx is expected does not fail
 * cleanly, it walks into the mechanism with the wrong pointer, which is
 * exactly what a segfault inside kg_seal looks like.
 *
 * So the two roles get two vtables, and gss_ctx means something different in
 * each: a minted context for the acceptor, the krb5_local itself for the
 * initiator, which is where init_ctx lives.
 */
static int
krb5_local_i_get_mic(
    void       *arg,
    void       *gss_ctx,
    const void *msg,
    size_t      msg_len,
    void      **mic,
    size_t     *mic_len)
{
    (void) arg;
    return krb5_local_get_mic(gss_ctx, msg, msg_len, mic, mic_len);
} /* krb5_local_i_get_mic */

static int
krb5_local_i_verify_mic(
    void       *arg,
    void       *gss_ctx,
    const void *msg,
    size_t      msg_len,
    const void *mic,
    size_t      mic_len)
{
    (void) arg;
    return krb5_local_verify_mic(gss_ctx, msg, msg_len, mic, mic_len);
} /* krb5_local_i_verify_mic */

static int
krb5_local_i_wrap(
    void       *arg,
    void       *gss_ctx,
    const void *in,
    size_t      in_len,
    void       *out,
    size_t      out_cap,
    size_t     *r_out_len)
{
    void  *tok;
    size_t tl;

    (void) arg;

    if (krb5_local_wrap(gss_ctx, in, in_len, &tok, &tl)) {
        return -1;
    }

    if (tl > out_cap) {
        free(tok);
        return -1;
    }

    memcpy(out, tok, tl);
    *r_out_len = tl;
    free(tok);
    return 0;
} /* krb5_local_i_wrap */

static int
krb5_local_i_unwrap(
    void       *arg,
    void       *gss_ctx,
    const void *in,
    size_t      in_len,
    void       *out,
    size_t      out_cap,
    size_t     *r_out_len)
{
    void  *plain;
    size_t pl;

    (void) arg;

    if (krb5_local_unwrap(gss_ctx, in, in_len, &plain, &pl)) {
        return -1;
    }

    if (pl > out_cap) {
        free(plain);
        return -1;
    }

    memcpy(out, plain, pl);
    *r_out_len = pl;
    free(plain);
    return 0;
} /* krb5_local_i_unwrap */

/* The initiator's context belongs to the krb5_local, which krb5_local_destroy
 * already tears down; nothing extra to release per context. */
static void
krb5_local_i_destroy(
    void *arg,
    void *gss_ctx)
{
    (void) arg;
    (void) gss_ctx;
} /* krb5_local_i_destroy */

static const struct evpl_rpc2_gss_provider krb5_local_initiator_vtable = {
    .init       = krb5_local_p_init,
    .get_mic    = krb5_local_i_get_mic,
    .verify_mic = krb5_local_i_verify_mic,
    .wrap       = krb5_local_i_wrap,
    .unwrap     = krb5_local_i_unwrap,
    .destroy    = krb5_local_i_destroy,
};

const struct evpl_rpc2_gss_provider *
krb5_local_initiator_provider(void)
{
    return &krb5_local_initiator_vtable;
} /* krb5_local_initiator_provider */

static const struct evpl_rpc2_gss_provider krb5_local_vtable = {
    .accept     = krb5_local_accept,
    .get_mic    = krb5_local_p_get_mic,
    .verify_mic = krb5_local_p_verify_mic,
    .wrap       = krb5_local_p_wrap,
    .unwrap     = krb5_local_p_unwrap,
#ifdef GSS_IOV_BUFFER_TYPE_MIC_TOKEN
    .verify_mic_iov = krb5_local_p_verify_mic_iov,
#endif /* ifdef GSS_IOV_BUFFER_TYPE_MIC_TOKEN */
    .destroy        = krb5_local_p_destroy,
};

/* The same vtable with the scattered entry point withheld, so a test can
 * drive rpc2's gathering fallback on a host that does have the IOV
 * extension -- otherwise which path runs is a property of the build. */
static const struct evpl_rpc2_gss_provider krb5_local_vtable_noiov = {
    .accept     = krb5_local_accept,
    .get_mic    = krb5_local_p_get_mic,
    .verify_mic = krb5_local_p_verify_mic,
    .wrap       = krb5_local_p_wrap,
    .unwrap     = krb5_local_p_unwrap,
    .destroy    = krb5_local_p_destroy,
};

const struct evpl_rpc2_gss_provider *
krb5_local_provider(void)
{
    return &krb5_local_vtable;
} /* krb5_local_provider */

const struct evpl_rpc2_gss_provider *
krb5_local_provider_noiov(void)
{
    return &krb5_local_vtable_noiov;
} /* krb5_local_provider_noiov */
