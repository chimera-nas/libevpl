// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509v3.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include "core/evpl.h"
#include "core/evpl_shared.h"
extern struct evpl_shared *evpl_shared;
#include "core/protocol.h"
#include "core/logging.h"
#include "core/macros.h"
#include "core/tls/tls.h"
#include "core/tls/openssl.h"
#define evpl_tls_abort_if(cond, ...) evpl_core_abort_if(cond, __VA_ARGS__)
#define evpl_tls_info(...)           evpl_core_info(__VA_ARGS__)

/*
 * ALPN protocol list in OpenSSL wire format (each entry: 1-byte length followed
 * by the protocol name), in client-preference / server-selection order.
 * Process-wide; configured via evpl_tls_set_alpn_protocols() before the first
 * TLS connection.
 */
static unsigned char evpl_tls_alpn_wire[256];
static unsigned int  evpl_tls_alpn_wire_len;

SYMBOL_EXPORT void
evpl_tls_set_alpn_protocols(
    const char *const *protocols,
    int                count)
{
    unsigned int off = 0;
    int          i;
    size_t       plen;

    for (i = 0; i < count; i++) {
        plen = strlen(protocols[i]);
        evpl_tls_abort_if(plen == 0 || plen > 255, "invalid ALPN protocol");
        evpl_tls_abort_if(off + 1 + plen > sizeof(evpl_tls_alpn_wire),
                          "ALPN protocol list too long");
        evpl_tls_alpn_wire[off++] = (unsigned char) plen;
        memcpy(&evpl_tls_alpn_wire[off], protocols[i], plen);
        off += plen;
    }

    evpl_tls_alpn_wire_len = off;
} /* evpl_tls_set_alpn_protocols */

static int
evpl_tls_alpn_select_cb(
    SSL                  *ssl,
    const unsigned char **out,
    unsigned char        *outlen,
    const unsigned char  *in,
    unsigned int          inlen,
    void                 *arg)
{
    /* SSL_select_next_proto wants a non-const "server" list; ours is static. */
    if (evpl_tls_alpn_wire_len == 0) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    if (SSL_select_next_proto((unsigned char **) out, outlen,
                              evpl_tls_alpn_wire, evpl_tls_alpn_wire_len,
                              in, inlen) != OPENSSL_NPN_NEGOTIATED) {
        return SSL_TLSEXT_ERR_NOACK;
    }

    return SSL_TLSEXT_ERR_OK;
} /* evpl_tls_alpn_select_cb */

struct evpl_tls_shared {
    evpl_mutex_t lock;
    SSL_CTX     *client_ctx;
    SSL_CTX     *server_ctx;
};

static int
evpl_tls_generate_self_signed_cert(SSL_CTX *ctx)
{
    EVP_PKEY     *pkey     = NULL;
    X509         *cert     = NULL;
    X509_NAME    *name     = NULL;
    EVP_PKEY_CTX *pkey_ctx = NULL;
    int           rc       = 0;

    pkey = EVP_PKEY_new();
    evpl_tls_abort_if(!pkey, "Failed to create private key");

    pkey_ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    evpl_tls_abort_if(!pkey_ctx, "Failed to create RSA key context");

    rc = EVP_PKEY_keygen_init(pkey_ctx);
    evpl_tls_abort_if(rc <= 0, "Failed to initialize key generation");

    rc = EVP_PKEY_CTX_set_rsa_keygen_bits(pkey_ctx, 2048);
    evpl_tls_abort_if(rc <= 0, "Failed to set RSA key size");

    rc = EVP_PKEY_keygen(pkey_ctx, &pkey);
    evpl_tls_abort_if(rc <= 0, "Failed to generate RSA key");

    cert = X509_new();
    evpl_tls_abort_if(!cert, "Failed to create certificate");

    rc = X509_set_version(cert, 2);
    evpl_tls_abort_if(rc <= 0, "Failed to set certificate version");

    ASN1_INTEGER_set(X509_get_serialNumber(cert), 1);

    X509_gmtime_adj(X509_get_notBefore(cert), 0);
    X509_gmtime_adj(X509_get_notAfter(cert), 365 * 24 * 60 * 60);

    X509_set_pubkey(cert, pkey);

    name = X509_get_subject_name(cert);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char *) "US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "ST", MBSTRING_ASC, (unsigned char *) "Self-Signed", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "L", MBSTRING_ASC, (unsigned char *) "Self-Signed", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char *) "Self-Signed", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "OU", MBSTRING_ASC, (unsigned char *) "Self-Signed", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char *) "localhost", -1, -1, 0);

    X509_set_issuer_name(cert, name);

    X509V3_CTX      ctx_v3;
    X509V3_set_ctx(&ctx_v3, cert, cert, NULL, NULL, 0);

    X509_EXTENSION *ext = X509V3_EXT_conf_nid(NULL, &ctx_v3, NID_basic_constraints, "CA:FALSE");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    ext = X509V3_EXT_conf_nid(NULL, &ctx_v3, NID_subject_key_identifier, "hash");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    ext = X509V3_EXT_conf_nid(NULL, &ctx_v3, NID_subject_alt_name, "DNS:localhost,IP:127.0.0.1");
    if (ext) {
        X509_add_ext(cert, ext, -1);
        X509_EXTENSION_free(ext);
    }

    rc = X509_sign(cert, pkey, EVP_sha256());
    evpl_tls_abort_if(rc <= 0, "Failed to sign certificate");

    rc = SSL_CTX_use_certificate(ctx, cert);
    evpl_tls_abort_if(rc <= 0, "Failed to use certificate in SSL context");

    rc = SSL_CTX_use_PrivateKey(ctx, pkey);
    evpl_tls_abort_if(rc <= 0, "Failed to use private key in SSL context");

    rc = SSL_CTX_check_private_key(ctx);
    evpl_tls_abort_if(rc <= 0, "Private key does not match certificate");

    if (pkey_ctx) {
        EVP_PKEY_CTX_free(pkey_ctx);
    }
    if (cert) {
        X509_free(cert);
    }
    if (pkey) {
        EVP_PKEY_free(pkey);
    }
    return rc;
} /* evpl_tls_generate_self_signed_cert */

static SSL_CTX *
evpl_tls_create_ctx(int is_server)
{
    SSL_CTX                   *ctx;
    struct evpl_global_config *config = evpl_shared->config;
    int                        rc;

    ctx = SSL_CTX_new(is_server ? TLS_server_method() : TLS_client_method());
    evpl_tls_abort_if(!ctx, "Failed to create SSL context");

    SSL_CTX_set_mode(ctx, SSL_MODE_ENABLE_PARTIAL_WRITE);
    SSL_CTX_set_mode(ctx, SSL_MODE_ACCEPT_MOVING_WRITE_BUFFER);

    /* Enable kTLS if configured */
    if (config->tls_ktls_enabled) {
#ifdef __linux__
        SSL_CTX_set_options(ctx, SSL_OP_ENABLE_KTLS);
        SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
        SSL_CTX_set_max_proto_version(ctx, TLS1_2_VERSION);
#endif /* ifdef __linux__ */
    }

    /* Set cipher list if configured */
    if (config->tls_cipher_list) {
        rc = SSL_CTX_set_cipher_list(ctx, config->tls_cipher_list);
        evpl_tls_abort_if(rc <= 0, "Failed to set cipher list: %s", config->tls_cipher_list);
    } else if (config->tls_ktls_enabled) {
        /* Default cipher list for kTLS: the kernel offload depends on the
         * record cipher (AES-128-GCM), not the key exchange, so prefer
         * ECDHE -- hardened crypto policies (e.g. RHEL DEFAULT) drop the
         * plain-RSA key exchange entirely, and a server offering only
         * AES128-GCM-SHA256 fails those clients with "no shared cipher".
         * Keep the RSA-kex variant as a last-resort fallback. */
        rc = SSL_CTX_set_cipher_list(ctx,
                                     "ECDHE-ECDSA-AES128-GCM-SHA256:"
                                     "ECDHE-RSA-AES128-GCM-SHA256:"
                                     "AES128-GCM-SHA256");
        evpl_tls_abort_if(rc <= 0, "Failed to set default kTLS cipher list");
    }

    if (is_server && evpl_tls_alpn_wire_len > 0) {
        SSL_CTX_set_alpn_select_cb(ctx, evpl_tls_alpn_select_cb, NULL);
    }

    if (is_server) {
        SSL_CTX_set_ecdh_auto(ctx, 1);

        if (config->tls_cert_file && config->tls_key_file) {
            rc = SSL_CTX_use_certificate_file(ctx, config->tls_cert_file, SSL_FILETYPE_PEM);

            evpl_tls_abort_if(rc <= 0, "Failed to load certificate file: %s", config->tls_cert_file);

            rc = SSL_CTX_use_PrivateKey_file(ctx, config->tls_key_file, SSL_FILETYPE_PEM);

            evpl_tls_abort_if(rc <= 0, "Failed to load private key file: %s", config->tls_key_file);

            rc = SSL_CTX_check_private_key(ctx);

            evpl_tls_abort_if(rc <= 0, "Private key does not match certificate");

        } else {
            evpl_tls_info("No certificate files provided, generating self-signed certificate");
            rc = evpl_tls_generate_self_signed_cert(ctx);
            evpl_tls_abort_if(rc <= 0, "Failed to generate self-signed certificate");
        }
    }

    if (config->tls_ca_file) {
        rc = SSL_CTX_load_verify_locations(ctx, config->tls_ca_file, NULL);

        evpl_tls_abort_if(rc <= 0, "Failed to load CA file: %s", config->tls_ca_file);
    }

    if (config->tls_verify_peer) {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    } else {
        SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
    }

    return ctx;
} /* evpl_tls_create_ctx */

static void *
evpl_tls_framework_init(void)
{
    struct evpl_tls_shared *shared;

    SSL_library_init();
    SSL_load_error_strings();
    OpenSSL_add_all_algorithms();

    shared = evpl_zalloc(sizeof(*shared));
    evpl_mutex_init(&shared->lock, NULL);

    return shared;
} /* evpl_tls_framework_init */

static void
evpl_tls_framework_cleanup(void *private_data)
{
    struct evpl_tls_shared *shared = private_data;

    if (shared->client_ctx) {
        SSL_CTX_free(shared->client_ctx);
    }
    if (shared->server_ctx) {
        SSL_CTX_free(shared->server_ctx);
    }
    evpl_mutex_destroy(&shared->lock);
    evpl_free(shared);
} /* evpl_tls_framework_cleanup */


SSL *
evpl_tls_session_create(
    struct evpl *evpl,
    int          is_server)
{
    struct evpl_tls_shared *shared = evpl_framework_private(evpl, EVPL_FRAMEWORK_TLS);
    SSL_CTX               **ctx;
    SSL                    *ssl;

    evpl_core_abort_if(!shared, "TLS framework not initialized");
    evpl_mutex_lock(&shared->lock);
    ctx = is_server ? &shared->server_ctx : &shared->client_ctx;
    if (!*ctx) {
        *ctx = evpl_tls_create_ctx(is_server);
    }
    ssl = SSL_new(*ctx);
    evpl_core_abort_if(!ssl, "failed to create TLS session");
    if (!is_server && evpl_tls_alpn_wire_len) {
        evpl_core_abort_if(SSL_set_alpn_protos(ssl, evpl_tls_alpn_wire, evpl_tls_alpn_wire_len),
                           "failed to set ALPN protocols");
    }
    evpl_mutex_unlock(&shared->lock);
    return ssl;
} /* evpl_tls_session_create */
static void *
evpl_tls_framework_create(
    struct evpl *evpl,
    void        *shared)
{
    return shared;
} /* evpl_tls_framework_create */

static void
evpl_tls_framework_destroy(
    struct evpl *evpl,
    void        *state)
{
} /* evpl_tls_framework_destroy */

struct evpl_framework evpl_framework_tls = {
    .id      = EVPL_FRAMEWORK_TLS,
    .name    = "TLS",
    .init    = evpl_tls_framework_init,
    .cleanup = evpl_tls_framework_cleanup,
    .create  = evpl_tls_framework_create,
    .destroy = evpl_tls_framework_destroy,
};
