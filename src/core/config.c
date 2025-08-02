// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include <unistd.h>
#include <string.h>
#include <pthread.h>

#include "core/evpl.h"
#include "core/evpl_shared.h"
#include "evpl/evpl.h"
#include "core/macros.h"

extern struct evpl_shared *evpl_shared;

SYMBOL_EXPORT struct evpl_global_config *
evpl_global_config_init(void)
{
    struct evpl_global_config *config = evpl_zalloc(sizeof(*config));

    config->thread_default.poll_mode       = 1;
    config->thread_default.poll_iterations = 1000;
    config->thread_default.spin_ns         = 1000000UL;
    config->thread_default.wait_ms         = -1;

    config->max_pending        = 16;
    config->max_poll_fd        = 16;
    config->max_num_iovec      = 128;
    config->huge_pages         = 0;
    config->buffer_size        = 2 * 1024 * 1024;
    config->slab_size          = 1 * 1024 * 1024 * 1024;
    config->refcnt             = 1;
    config->iovec_ring_size    = 1024;
    config->dgram_ring_size    = 256;
    config->max_datagram_size  = 65536;
    config->max_datagram_batch = 16;
    config->resolve_timeout_ms = 5000;

    config->page_size = sysconf(_SC_PAGESIZE);

    if (config->page_size == -1) {
        config->page_size = 4096;
    }

    config->io_uring_enabled = 1;

    config->rdmacm_enabled                = 1;
    config->rdmacm_tos                    = 0;
    config->rdmacm_max_sge                = 31;
    config->rdmacm_cq_size                = 8192;
    config->rdmacm_sq_size                = 256;
    config->rdmacm_srq_size               = 8192;
    config->rdmacm_srq_min                = 256;
    config->rdmacm_srq_batch              = 16;
    config->rdmacm_datagram_size_override = 0;
    config->rdmacm_srq_prefill            = 0;
    config->rdmacm_retry_count            = 4;
    config->rdmacm_rnr_retry_count        = 4;

    config->xlio_enabled = 1;

    config->vfio_enabled = 1;

    config->tls_cert_file    = strdup("cert.pem");
    config->tls_key_file     = strdup("key.pem");
    config->tls_cipher_list  = NULL;
    config->tls_verify_peer  = 1;
    config->tls_ktls_enabled = 1;

    return config;
} /* evpl_config_init */

static void
evpl_global_config_free(struct evpl_global_config *config)
{
    if (config->tls_cert_file) {
        evpl_free(config->tls_cert_file);
    }

    if (config->tls_key_file) {
        evpl_free(config->tls_key_file);
    }

    if (config->tls_ca_file) {
        evpl_free(config->tls_ca_file);
    }

    if (config->tls_cipher_list) {
        evpl_free(config->tls_cipher_list);
    }

    evpl_free(config);
} /* evpl_global_config_free */

SYMBOL_EXPORT void
evpl_global_config_release(struct evpl_global_config *config)
{

    if (!evpl_shared) {
        evpl_global_config_free(config);
        return;
    }

    pthread_mutex_lock(&evpl_shared->lock);

    evpl_core_abort_if(config->refcnt == 0,
                       "config refcnt %d", config->refcnt);

    config->refcnt--;

    if (config->refcnt == 0) {
        evpl_global_config_free(config);
    }

    pthread_mutex_unlock(&evpl_shared->lock);
} /* evpl_release_config */

SYMBOL_EXPORT void
evpl_global_config_set_max_datagram_size(
    struct evpl_global_config *config,
    unsigned int               size)
{
    config->max_datagram_size = size;
} /* evpl_config_set_max_datagram_size */

SYMBOL_EXPORT void
evpl_global_config_set_huge_pages(
    struct evpl_global_config *config,
    int                        huge_pages)
{
    config->huge_pages = huge_pages;
} /* evpl_global_config_set_huge_pages */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_tos(
    struct evpl_global_config *config,
    uint8_t                    tos)
{
    config->rdmacm_tos = tos;
} /* evpl_global_config_set_rdmacm_tos */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_srq_prefill(
    struct evpl_global_config *config,
    int                        prefill)
{
    config->rdmacm_srq_prefill = prefill;
} /* evpl_global_config_set_rdmacm_srq_prefill */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_datagram_size_override(
    struct evpl_global_config *config,
    unsigned int               size)
{
    config->rdmacm_datagram_size_override = size;
} /* evpl_global_config_set_rdmacm_datagram_size_override */

SYMBOL_EXPORT void
evpl_global_config_set_spin_ns(
    struct evpl_global_config *config,
    uint64_t                   ns)
{
    config->thread_default.spin_ns = ns;
} /* evpl_global_config_set_spin_ns */

SYMBOL_EXPORT void
evpl_global_config_set_tls_cert(
    struct evpl_global_config *config,
    const char                *cert_file)
{
    if (config->tls_cert_file) {
        evpl_free(config->tls_cert_file);
    }

    config->tls_cert_file = strdup(cert_file);
} /* evpl_global_config_set_tls_cert */

SYMBOL_EXPORT void
evpl_global_config_set_tls_key(
    struct evpl_global_config *config,
    const char                *key_file)
{
    if (config->tls_key_file) {
        evpl_free(config->tls_key_file);
    }

    config->tls_key_file = strdup(key_file);
} /* evpl_global_config_set_tls_key */

SYMBOL_EXPORT void
evpl_global_config_set_tls_ca(
    struct evpl_global_config *config,
    const char                *ca_file)
{
    config->tls_ca_file = strdup(ca_file);
} /* evpl_global_config_set_tls_ca */

SYMBOL_EXPORT void
evpl_global_config_set_tls_cipher_list(
    struct evpl_global_config *config,
    const char                *cipher_list)
{
    if (config->tls_cipher_list) {
        evpl_free(config->tls_cipher_list);
    }

    config->tls_cipher_list = cipher_list ? strdup(cipher_list) : NULL;
} /* evpl_global_config_set_tls_cipher_list */

SYMBOL_EXPORT void
evpl_global_config_set_tls_verify_peer(
    struct evpl_global_config *config,
    int                        verify)
{
    config->tls_verify_peer = verify;
} /* evpl_global_config_set_tls_verify_peer */

SYMBOL_EXPORT void
evpl_global_config_set_tls_ktls_enabled(
    struct evpl_global_config *config,
    int                        enabled)
{
    config->tls_ktls_enabled = enabled;
} /* evpl_global_config_set_tls_ktls_enabled */


