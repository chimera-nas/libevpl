// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/tls/schannel_internal.h"
#include <stdio.h>

unsigned char evpl_schannel_alpn[256];
unsigned int  evpl_schannel_alpn_length;

SYMBOL_EXPORT void
evpl_tls_set_alpn_protocols(
    const char *const *protocols,
    int                count)
{
    unsigned int offset = 0;
    int          i;

    for (i = 0; i < count; i++) {
        size_t length = strlen(protocols[i]);
        evpl_core_abort_if(!length || length > 255 || offset + length + 1 > sizeof(evpl_schannel_alpn),
                           "Invalid TLS ALPN protocol list");
        evpl_schannel_alpn[offset++] = (unsigned char) length;
        memcpy(evpl_schannel_alpn + offset, protocols[i], length);
        offset += (unsigned int) length;
    }
    evpl_schannel_alpn_length = offset;
} /* evpl_tls_set_alpn_protocols */

static char *
evpl_schannel_file(const char *path)
{
    FILE *file = fopen(path, "rb");
    long  length;
    char *data;

    evpl_core_abort_if(!file, "Cannot open TLS file: %s", path);
    evpl_core_abort_if(fseek(file, 0, SEEK_END), "Cannot seek TLS file: %s", path);
    length = ftell(file);
    evpl_core_abort_if(length <= 0 || length > 4 * 1024 * 1024, "Invalid TLS file size: %s", path);
    rewind(file);
    data = evpl_zalloc((size_t) length + 1);
    evpl_core_abort_if(fread(data, 1, (size_t) length, file) != (size_t) length, "Cannot read TLS file: %s", path);
    fclose(file);
    return data;
} /* evpl_schannel_file */

static BYTE *
evpl_schannel_der(
    const char *pem,
    DWORD       length,
    DWORD      *size)
{
    BYTE *der;

    evpl_core_abort_if(!CryptStringToBinaryA(pem, length, CRYPT_STRING_BASE64HEADER, NULL, size, NULL, NULL),
                       "Invalid TLS PEM encoding (0x%lx)", GetLastError());
    der = evpl_malloc(*size);
    evpl_core_abort_if(!CryptStringToBinaryA(pem, length, CRYPT_STRING_BASE64HEADER, der, size, NULL, NULL),
                       "Cannot decode TLS PEM");
    return der;
} /* evpl_schannel_der */

static HCERTSTORE
evpl_schannel_certificates(const char *path)
{
    char        *text = evpl_schannel_file(path), *begin = text, *end;
    HCERTSTORE   store = CertOpenStore(CERT_STORE_PROV_MEMORY, 0, 0, 0, NULL);
    unsigned int count = 0;

    evpl_core_abort_if(!store, "Cannot create TLS certificate store");
    while ((begin = strstr(begin, "-----BEGIN CERTIFICATE-----")) != NULL) {
        BYTE *der;
        DWORD size;
        end = strstr(begin, "-----END CERTIFICATE-----");
        evpl_core_abort_if(!end, "Incomplete certificate in %s", path);
        end += strlen("-----END CERTIFICATE-----");
        der  = evpl_schannel_der(begin, (DWORD) (end - begin), &size);
        evpl_core_abort_if(!CertAddEncodedCertificateToStore(store, X509_ASN_ENCODING, der, size,
                                                             CERT_STORE_ADD_ALWAYS, NULL), "Invalid certificate in %s",
                           path);
        evpl_free(der);
        begin = end;
        count++;
    }
    evpl_free(text);
    evpl_core_abort_if(!count, "No certificates in %s", path);
    return store;
} /* evpl_schannel_certificates */

static void
evpl_schannel_load_identity(
    struct evpl_schannel_shared *shared,
    const char                  *cert_path,
    const char                  *key_path)
{
    NCRYPT_PROV_HANDLE    provider = shared->provider;
    HCERTSTORE            store    = evpl_schannel_certificates(cert_path);
    char                 *pem      = evpl_schannel_file(key_path);
    BYTE                 *der;
    DWORD                 size, public_size = 0;
    SECURITY_STATUS       status;
    CERT_PUBLIC_KEY_INFO *public_key;
    NCryptBuffer          name_buffer = { (ULONG) ((wcslen(shared->key_name) + 1) * sizeof(WCHAR)),
                                          NCRYPTBUFFER_PKCS_KEY_NAME, shared->key_name };
    NCryptBufferDesc      import_parameters = { NCRYPTBUFFER_VERSION, 1, &name_buffer };

    der = evpl_schannel_der(pem, 0, &size);
    if (strstr(pem, "-----BEGIN RSA PRIVATE KEY-----")) {
        BYTE *blob      = NULL;
        DWORD blob_size = 0;
        evpl_core_abort_if(!CryptDecodeObjectEx(X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, PKCS_RSA_PRIVATE_KEY,
                                                der, size, CRYPT_DECODE_ALLOC_FLAG, NULL, &blob, &blob_size),
                           "Invalid PKCS#1 RSA key");
        status = NCryptImportKey(provider, 0, LEGACY_RSAPRIVATE_BLOB, &import_parameters, &shared->key, blob, blob_size,
                                 NCRYPT_SILENT_FLAG);
        SecureZeroMemory(blob, blob_size);
        LocalFree(blob);
    } else {
        evpl_core_abort_if(!strstr(pem, "-----BEGIN PRIVATE KEY-----"),
                           "Schannel requires an unencrypted PKCS#8 or PKCS#1 RSA PEM private key");
        status = NCryptImportKey(provider, 0, NCRYPT_PKCS8_PRIVATE_KEY_BLOB, &import_parameters, &shared->key, der, size
                                 ,
                                 NCRYPT_SILENT_FLAG);
    }
    SecureZeroMemory(der, size);
    SecureZeroMemory(pem, strlen(pem));
    evpl_free(der);
    evpl_free(pem);
    evpl_core_abort_if(status, "Cannot import TLS private key (0x%lx)", (unsigned long) status);
    evpl_core_abort_if(!CryptExportPublicKeyInfo(shared->key, CERT_NCRYPT_KEY_SPEC, X509_ASN_ENCODING, NULL, &
                                                 public_size),
                       "Cannot export TLS public key");
    public_key = evpl_malloc(public_size);
    evpl_core_abort_if(!CryptExportPublicKeyInfo(shared->key, CERT_NCRYPT_KEY_SPEC, X509_ASN_ENCODING, public_key, &
                                                 public_size),
                       "Cannot export TLS public key");
    /* Find the matching leaf regardless of PEM bundle order; its store retains
     * intermediate certificates for Schannel's chain construction. */
    while ((shared->certificate = CertEnumCertificatesInStore(store, shared->certificate)) != NULL) {
        if (CertComparePublicKeyInfo(X509_ASN_ENCODING, public_key, &shared->certificate->pCertInfo->
                                     SubjectPublicKeyInfo)) {
            break;
        }
    }
    evpl_free(public_key);
    shared->identity_store = store;
    evpl_core_abort_if(!shared->certificate, "TLS certificate and private key do not match");
} /* evpl_schannel_load_identity */

static void
evpl_schannel_generate_identity(struct evpl_schannel_shared *shared)
{
    NCRYPT_PROV_HANDLE         provider = shared->provider;
    DWORD                      bits = 2048, name_size = 0;
    CERT_NAME_BLOB             name;
    CRYPT_ALGORITHM_IDENTIFIER signature = { szOID_RSA_SHA256RSA, { 0, NULL } };
    SYSTEMTIME                 end;
    CERT_ALT_NAME_ENTRY        names[2]     = { 0 };
    CERT_ALT_NAME_INFO         alternatives = { 2, names };
    CERT_EXTENSION             extension    = { szOID_SUBJECT_ALT_NAME2, FALSE, { 0, NULL } };
    CERT_EXTENSIONS            extensions   = { 1, &extension };
    BYTE                       loopback[4]  = { 127, 0, 0, 1 };

    evpl_core_abort_if(NCryptCreatePersistedKey(provider, &shared->key, NCRYPT_RSA_ALGORITHM, shared->key_name, 0, 0),
                       "Cannot create TLS key");
    evpl_core_abort_if(NCryptSetProperty(shared->key, NCRYPT_LENGTH_PROPERTY, (BYTE *) &bits, sizeof(bits), 0) ||
                       NCryptFinalizeKey(shared->key, 0), "Cannot generate TLS key");
    evpl_core_abort_if(!CertStrToNameW(X509_ASN_ENCODING, L"CN=localhost", CERT_X500_NAME_STR, NULL, NULL, &name_size,
                                       NULL),
                       "Cannot encode TLS certificate name");
    name.cbData = name_size;
    name.pbData = evpl_malloc(name_size);
    evpl_core_abort_if(!CertStrToNameW(X509_ASN_ENCODING, L"CN=localhost", CERT_X500_NAME_STR, NULL, name.pbData, &name.
                                       cbData, NULL),
                       "Cannot encode TLS certificate name");
    GetSystemTime(&end);
    end.wYear++;
    if (end.wMonth == 2 && end.wDay == 29) {
        end.wDay = 28;
    }
    names[0].dwAltNameChoice  = CERT_ALT_NAME_DNS_NAME;
    names[0].pwszDNSName      = L"localhost";
    names[1].dwAltNameChoice  = CERT_ALT_NAME_IP_ADDRESS;
    names[1].IPAddress.cbData = sizeof(loopback);
    names[1].IPAddress.pbData = loopback;
    evpl_core_abort_if(!CryptEncodeObjectEx(X509_ASN_ENCODING, X509_ALTERNATE_NAME, &alternatives,
                                            CRYPT_ENCODE_ALLOC_FLAG, NULL, &extension.Value.pbData, &extension.Value.
                                            cbData),
                       "Cannot encode TLS subject alternatives");
    shared->certificate = CertCreateSelfSignCertificate(shared->key, &name, CERT_CREATE_SELFSIGN_NO_KEY_INFO,
                                                        NULL, &signature, NULL, &end, &extensions);
    LocalFree(extension.Value.pbData);
    evpl_free(name.pbData);
    evpl_core_abort_if(!shared->certificate, "Cannot create TLS certificate (0x%lx)", GetLastError());
} /* evpl_schannel_generate_identity */

static void *
evpl_schannel_init(void)
{
    struct evpl_schannel_shared *shared = evpl_zalloc(sizeof(*shared));

    DWORD                        random[4];

    evpl_core_abort_if(BCryptGenRandom(NULL, (BYTE *) random, sizeof(random), BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0,
                       "Cannot generate TLS key container name");
    swprintf(shared->key_name, sizeof(shared->key_name) / sizeof(WCHAR), L"libevpl-tls-%08lx%08lx%08lx%08lx",
             random[0], random[1], random[2], random[3]);
    evpl_core_abort_if(NCryptOpenStorageProvider(&shared->provider, MS_KEY_STORAGE_PROVIDER, 0),
                       "Cannot open CNG provider");
    shared->verify_peer = evpl_shared->config->tls_verify_peer;
    evpl_mutex_init(&shared->lock, NULL);
    SecInvalidateHandle(&shared->credentials[0]);
    SecInvalidateHandle(&shared->credentials[1]);
    return shared;
} /* evpl_schannel_init */

struct evpl_schannel_shared *
evpl_schannel_credentials(
    struct evpl *evpl,
    int          server)
{
    struct evpl_schannel_shared *shared       = evpl_framework_private(evpl, EVPL_FRAMEWORK_TLS);
    struct evpl_global_config   *config       = evpl_shared->config;
    SCH_CREDENTIALS              credentials  = { 0 };
    TLS_PARAMETERS               parameters   = { 0 };
    CRYPT_KEY_PROV_INFO          key_info     = { 0 };
    CERT_CHAIN_ENGINE_CONFIG     chain_config = { 0 };
    SECURITY_STATUS              status;

    evpl_mutex_lock(&shared->lock);
    if (!SecIsValidHandle(&shared->credentials[server])) {
        evpl_core_abort_if(config->tls_cipher_list,
                           "OpenSSL cipher-list syntax is not supported by Schannel; use Windows TLS policy");
        if (config->tls_ca_file && !shared->roots) {
            shared->roots               = evpl_schannel_certificates(config->tls_ca_file);
            chain_config.cbSize         = sizeof(chain_config);
            chain_config.hExclusiveRoot = shared->roots;
            evpl_core_abort_if(!CertCreateCertificateChainEngine(&chain_config, &shared->chain_engine),
                               "Cannot create TLS trust engine");
        }
        if (!shared->certificate && (server || (config->tls_cert_file && config->tls_key_file))) {
            if (config->tls_cert_file && config->tls_key_file) {
                evpl_schannel_load_identity(shared, config->tls_cert_file, config->tls_key_file);
            } else {
                evpl_schannel_generate_identity(shared);
            }
            /* Schannel cannot use ephemeral CNG keys on all supported Windows
             * versions. Give it a named user-scoped key; cleanup deletes it
             * after both credential handles have been released. */
            key_info.pwszContainerName = shared->key_name;
            key_info.pwszProvName      = MS_KEY_STORAGE_PROVIDER;
            key_info.dwFlags           = NCRYPT_SILENT_FLAG;
            evpl_core_abort_if(!CertSetCertificateContextProperty(shared->certificate, CERT_KEY_PROV_INFO_PROP_ID,
                                                                  0, &key_info), "Cannot associate TLS private key");
        }
        credentials.dwVersion = SCH_CREDENTIALS_VERSION;
        credentials.dwFlags   = server ? SCH_CRED_NO_SYSTEM_MAPPER : SCH_CRED_NO_DEFAULT_CREDS |
            SCH_CRED_MANUAL_CRED_VALIDATION;
        credentials.dwFlags              |= SCH_CRED_CACHE_ONLY_URL_RETRIEVAL_ON_CREATE;
        credentials.hRootStore            = server ? shared->roots : NULL;
        credentials.cTlsParameters        = 1;
        credentials.pTlsParameters        = &parameters;
        parameters.grbitDisabledProtocols = SP_PROT_SSL2 | SP_PROT_SSL3 | SP_PROT_TLS1_0 | SP_PROT_TLS1_1;
        if (shared->certificate && (server || config->tls_cert_file)) {
            credentials.cCreds = 1;
            credentials.paCred = &shared->certificate;
        }
        status = AcquireCredentialsHandleW(NULL, UNISP_NAME_W, server ? SECPKG_CRED_INBOUND : SECPKG_CRED_OUTBOUND,
                                           NULL, &credentials, NULL, NULL, &shared->credentials[server], NULL);
        evpl_core_abort_if(status != SEC_E_OK, "Cannot acquire Schannel credentials (0x%lx)", (unsigned long) status);
    }
    evpl_mutex_unlock(&shared->lock);
    return shared;
} /* evpl_schannel_credentials */

int
evpl_schannel_verify(
    struct evpl_schannel_shared *shared,
    CtxtHandle                  *context,
    int                          server)
{
    PCCERT_CONTEXT                   certificate = NULL;
    PCCERT_CHAIN_CONTEXT             chain       = NULL;
    CERT_CHAIN_PARA                  parameters  = { 0 };
    CERT_CHAIN_POLICY_PARA           policy      = { 0 };
    CERT_CHAIN_POLICY_STATUS         result      = { 0 };
    SSL_EXTRA_CERT_CHAIN_POLICY_PARA ssl         = { 0 };
    int                              valid       = 0;

    if (!shared->verify_peer) {
        return 1;
    }
    if (QueryContextAttributes(context, SECPKG_ATTR_REMOTE_CERT_CONTEXT, &certificate) != SEC_E_OK) {
        return 0;
    }
    parameters.cbSize        = sizeof(parameters);
    policy.cbSize            = sizeof(policy);
    result.cbSize            = sizeof(result);
    ssl.cbSize               = sizeof(ssl);
    ssl.dwAuthType           = server ? AUTHTYPE_CLIENT : AUTHTYPE_SERVER;
    policy.pvExtraPolicyPara = &ssl;
    /* Match libevpl's existing chain-verification API. There is currently no
     * peer hostname parameter. Do not perform blocking network retrieval from
     * the event loop; use supplied intermediates and the local trust store. */
    if (CertGetCertificateChain(shared->chain_engine, certificate, NULL, certificate->hCertStore, &parameters,
                                CERT_CHAIN_CACHE_ONLY_URL_RETRIEVAL, NULL, &chain)) {
        valid = CertVerifyCertificateChainPolicy(CERT_CHAIN_POLICY_SSL, chain, &policy, &result) && !result.dwError;
        CertFreeCertificateChain(chain);
    }
    CertFreeCertificateContext(certificate);
    return valid;
} /* evpl_schannel_verify */

static void
evpl_schannel_cleanup(void *data)
{
    struct evpl_schannel_shared *shared = data;
    int                          i;

    for (i = 0; i < 2; i++) {
        if (SecIsValidHandle(&shared->credentials[i])) {
            FreeCredentialsHandle(&shared->credentials[i]);
        }
    }
    if (shared->certificate) {
        CertFreeCertificateContext(shared->certificate);
    }
    if (shared->identity_store) {
        CertCloseStore(shared->identity_store, 0);
    }
    if (shared->key) {
        SECURITY_STATUS status = NCryptDeleteKey(shared->key, NCRYPT_SILENT_FLAG);
        if (status) {
            evpl_core_error("Cannot delete temporary TLS key container (0x%lx)", (unsigned long) status);
            NCryptFreeObject(shared->key);
        }
    }
    /* Release the provider after its key handles. This cleanup must run
     * before DLL teardown, while CNG's RPC bindings are still available. */
    NCryptFreeObject(shared->provider);
    if (shared->chain_engine) {
        CertFreeCertificateChainEngine(shared->chain_engine);
    }
    if (shared->roots) {
        CertCloseStore(shared->roots, 0);
    }
    evpl_mutex_destroy(&shared->lock);
    evpl_free(shared);
} /* evpl_schannel_cleanup */

static void *
evpl_schannel_create(
    struct evpl *evpl,
    void        *shared)
{
    (void) evpl;
    return shared;
} /* evpl_schannel_create */
static void
evpl_schannel_destroy(
    struct evpl *evpl,
    void        *state)
{
    (void) evpl;
    (void) state;
} /* evpl_schannel_destroy */
struct evpl_framework evpl_framework_tls = {
    .id      = EVPL_FRAMEWORK_TLS,
    .name    = "TLS",
    .init    = evpl_schannel_init,
    .cleanup = evpl_schannel_cleanup,
    .create  = evpl_schannel_create,
    .destroy = evpl_schannel_destroy,
};
