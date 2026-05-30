// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <unistd.h>
#include <stdio.h>
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

    config->hf_time_mode           = 2;
    config->max_pending            = 16;
    config->max_poll_fd            = 16;
    config->max_num_iovec          = 128;
    config->huge_pages             = 0;
    config->huge_page_size         = 2 * 1024 * 1024;
    config->buffer_size            = 2 * 1024 * 1024;
    config->slab_size              = 1 * 1024 * 1024 * 1024;
    config->refcnt                 = 1;
    config->iovec_ring_size        = 1024;
    config->dgram_ring_size        = 1024;
    config->rdma_request_ring_size = 64;
    config->max_datagram_size      = 65536;
    config->max_datagram_batch     = 16;
    config->resolve_timeout_ms     = 5000;

    config->page_size = sysconf(_SC_PAGESIZE);

    if (config->page_size == -1) {
        config->page_size = 4096;
    }

    config->io_uring_enabled = 1;
    config->io_uring_entries = 8192;

    config->rdmacm_enabled                = 1;
    config->rdmacm_tos                    = 0;
    config->rdmacm_max_sge                = 31;
    config->rdmacm_cq_size                = 8192;
    config->rdmacm_sq_size                = 256;
    config->rdmacm_srq_size               = 8192;
    config->rdmacm_srq_min                = 256;
    config->rdmacm_srq_batch              = 16;
    config->rdmacm_max_inline             = 250;
    config->rdmacm_datagram_size_override = 0;
    config->rdmacm_srq_prefill            = 0;
    config->rdmacm_retry_count            = 4;
    config->rdmacm_rnr_retry_count        = 4;

    config->xlio_enabled = 1;

    config->vfio_enabled = 1;

    config->libaio_enabled     = 1;
    config->libaio_max_pending = 256;

    config->preallocate_slabs   = 0;
    config->preallocate_threads = 0;

    config->tls_cert_file    = NULL;
    config->tls_key_file     = NULL;
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
evpl_global_config_set_buffer_size(
    struct evpl_global_config *config,
    uint64_t                   size)
{
    config->buffer_size = size;
} /* evpl_global_config_set_buffer_size */

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
evpl_global_config_set_huge_page_size(
    struct evpl_global_config *config,
    uint64_t                   size)
{
    char path[64];

    /* A hugetlb page size is always a power of two strictly larger than the
     * base page.  Bound it sanely (the largest real page on any arch today is
     * 16 GiB) so a bogus value can never be encoded into MAP_HUGE_* or used to
     * size a slab. */
    if (size == 0 || (size & (size - 1)) != 0 ||
        size <= (uint64_t) config->page_size ||
        size > (16ULL << 30)) {
        evpl_core_error(
            "Ignoring invalid huge page size %llu: must be a power of two in "
            "(%u, 16GiB]; keeping %llu",
            (unsigned long long) size,
            config->page_size,
            (unsigned long long) config->huge_page_size);
        return;
    }

    /* Warn (but accept) if the running kernel exposes no hugetlb pool of this
     * size: the slab mmap will simply fall back to base pages.  This is a soft
     * check so a sandboxed /sys does not block a legitimate size. */
    snprintf(path, sizeof(path), "/sys/kernel/mm/hugepages/hugepages-%llukB",
             (unsigned long long) (size / 1024));
    if (access(path, F_OK) != 0) {
        evpl_core_info(
            "No %llukB hugetlb pool on this system (%s); slab allocation will "
            "fall back to base pages unless one is reserved",
            (unsigned long long) (size / 1024), path);
    }

    config->huge_page_size = size;
} /* evpl_global_config_set_huge_page_size */

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

SYMBOL_EXPORT struct evpl_thread_config *
evpl_thread_config_init(void)
{
    struct evpl_thread_config *config = evpl_zalloc(sizeof(*config));

    *config = evpl_shared->config->thread_default;

    return config;
} /* evpl_thread_config_init */

SYMBOL_EXPORT void
evpl_thread_config_release(struct evpl_thread_config *config)
{
    evpl_free(config);
} /* evpl_thread_config_release */


SYMBOL_EXPORT void
evpl_thread_config_set_poll_mode(
    struct evpl_thread_config *config,
    int                        poll_mode)
{
    config->poll_mode = poll_mode;
} /* evpl_thread_config_set_poll_mode */

SYMBOL_EXPORT void
evpl_thread_config_set_poll_iterations(
    struct evpl_thread_config *config,
    int                        iterations)
{
    config->poll_iterations = iterations;
} /* evpl_thread_config_set_poll_iterations */

SYMBOL_EXPORT void
evpl_thread_config_set_wait_ms(
    struct evpl_thread_config *config,
    int                        wait_ms)
{
    config->wait_ms = wait_ms;
} /* evpl_thread_config_set_wait_ms */

SYMBOL_EXPORT void
evpl_global_config_set_slab_size(
    struct evpl_global_config *config,
    uint64_t                   size)
{
    config->slab_size = size;
} /* evpl_global_config_set_slab_size */

SYMBOL_EXPORT void
evpl_global_config_set_max_num_iovec(
    struct evpl_global_config *config,
    unsigned int               max)
{
    config->max_num_iovec = max;
} /* evpl_global_config_set_max_num_iovec */

SYMBOL_EXPORT void
evpl_global_config_set_iovec_ring_size(
    struct evpl_global_config *config,
    unsigned int               size)
{
    config->iovec_ring_size = size;
} /* evpl_global_config_set_iovec_ring_size */

SYMBOL_EXPORT void
evpl_global_config_set_dgram_ring_size(
    struct evpl_global_config *config,
    unsigned int               size)
{
    config->dgram_ring_size = size;
} /* evpl_global_config_set_dgram_ring_size */

SYMBOL_EXPORT void
evpl_global_config_set_rdma_request_ring_size(
    struct evpl_global_config *config,
    unsigned int               size)
{
    config->rdma_request_ring_size = size;
} /* evpl_global_config_set_rdma_request_ring_size */

SYMBOL_EXPORT void
evpl_global_config_set_max_datagram_batch(
    struct evpl_global_config *config,
    unsigned int               batch)
{
    config->max_datagram_batch = batch;
} /* evpl_global_config_set_max_datagram_batch */

SYMBOL_EXPORT void
evpl_global_config_set_resolve_timeout_ms(
    struct evpl_global_config *config,
    unsigned int               timeout_ms)
{
    config->resolve_timeout_ms = timeout_ms;
} /* evpl_global_config_set_resolve_timeout_ms */

SYMBOL_EXPORT void
evpl_global_config_set_io_uring_enabled(
    struct evpl_global_config *config,
    int                        enabled)
{
    config->io_uring_enabled = enabled;
} /* evpl_global_config_set_io_uring_enabled */

SYMBOL_EXPORT void
evpl_global_config_set_io_uring_entries(
    struct evpl_global_config *config,
    unsigned int               entries)
{
    config->io_uring_entries = entries;
} /* evpl_global_config_set_io_uring_entries */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_enabled(
    struct evpl_global_config *config,
    int                        enabled)
{
    config->rdmacm_enabled = enabled;
} /* evpl_global_config_set_rdmacm_enabled */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_max_sge(
    struct evpl_global_config *config,
    unsigned int               max_sge)
{
    config->rdmacm_max_sge = max_sge;
} /* evpl_global_config_set_rdmacm_max_sge */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_cq_size(
    struct evpl_global_config *config,
    unsigned int               size)
{
    config->rdmacm_cq_size = size;
} /* evpl_global_config_set_rdmacm_cq_size */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_sq_size(
    struct evpl_global_config *config,
    unsigned int               size)
{
    config->rdmacm_sq_size = size;
} /* evpl_global_config_set_rdmacm_sq_size */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_srq_size(
    struct evpl_global_config *config,
    unsigned int               size)
{
    config->rdmacm_srq_size = size;
} /* evpl_global_config_set_rdmacm_srq_size */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_srq_min(
    struct evpl_global_config *config,
    unsigned int               min)
{
    config->rdmacm_srq_min = min;
} /* evpl_global_config_set_rdmacm_srq_min */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_max_inline(
    struct evpl_global_config *config,
    unsigned int               max_inline)
{
    config->rdmacm_max_inline = max_inline;
} /* evpl_global_config_set_rdmacm_max_inline */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_srq_batch(
    struct evpl_global_config *config,
    unsigned int               batch)
{
    config->rdmacm_srq_batch = batch;
} /* evpl_global_config_set_rdmacm_srq_batch */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_retry_count(
    struct evpl_global_config *config,
    unsigned int               retry_count)
{
    config->rdmacm_retry_count = retry_count;
} /* evpl_global_config_set_rdmacm_retry_count */

SYMBOL_EXPORT void
evpl_global_config_set_rdmacm_rnr_retry_count(
    struct evpl_global_config *config,
    unsigned int               retry_count)
{
    config->rdmacm_rnr_retry_count = retry_count;
} /* evpl_global_config_set_rdmacm_rnr_retry_count */

SYMBOL_EXPORT void
evpl_global_config_set_xlio_enabled(
    struct evpl_global_config *config,
    int                        enabled)
{
    config->xlio_enabled = enabled;
} /* evpl_global_config_set_xlio_enabled */

SYMBOL_EXPORT void
evpl_global_config_set_vfio_enabled(
    struct evpl_global_config *config,
    int                        enabled)
{
    config->vfio_enabled = enabled;
} /* evpl_global_config_set_vfio_enabled */

SYMBOL_EXPORT void
evpl_global_config_set_libaio_enabled(
    struct evpl_global_config *config,
    int                        enabled)
{
    config->libaio_enabled = enabled;
} /* evpl_global_config_set_libaio_enabled */

SYMBOL_EXPORT void
evpl_global_config_set_libaio_max_pending(
    struct evpl_global_config *config,
    unsigned int               max_pending)
{
    config->libaio_max_pending = max_pending;
} /* evpl_global_config_set_libaio_max_pending */

SYMBOL_EXPORT void
evpl_global_config_set_hf_time_mode(
    struct evpl_global_config *config,
    unsigned int               mode)
{
    config->hf_time_mode = mode;
} /* evpl_global_config_set_hf_time_mode */

SYMBOL_EXPORT void
evpl_global_config_set_max_pending(
    struct evpl_global_config *config,
    unsigned int               max)
{
    config->max_pending = max;
} /* evpl_global_config_set_max_pending */

SYMBOL_EXPORT void
evpl_global_config_set_max_poll_fd(
    struct evpl_global_config *config,
    unsigned int               max)
{
    config->max_poll_fd = max;
} /* evpl_global_config_set_max_poll_fd */

SYMBOL_EXPORT void
evpl_global_config_set_preallocate_slabs(
    struct evpl_global_config *config,
    unsigned int               slabs)
{
    config->preallocate_slabs = slabs;
} /* evpl_global_config_set_preallocate_slabs */

SYMBOL_EXPORT void
evpl_global_config_set_preallocate_threads(
    struct evpl_global_config *config,
    unsigned int               threads)
{
    config->preallocate_threads = threads;
} /* evpl_global_config_set_preallocate_threads */

