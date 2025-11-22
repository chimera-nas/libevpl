// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdint.h>

#ifndef EVPL_INCLUDED
#error "Do not include evpl_config.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_global_config;
struct evpl_thread_config;

struct evpl_global_config *
evpl_global_config_init(
    void);

void evpl_global_config_release(
    struct evpl_global_config *config);


void evpl_global_config_set_buffer_size(
    struct evpl_global_config *config,
    uint64_t                   size);

void evpl_global_config_set_spin_ns(
    struct evpl_global_config *config,
    uint64_t                   ns);

void evpl_global_config_set_max_datagram_size(
    struct evpl_global_config *config,
    unsigned int               size);

void evpl_global_config_set_huge_pages(
    struct evpl_global_config *config,
    int                        huge_pages);

void evpl_global_config_set_rdmacm_tos(
    struct evpl_global_config *config,
    uint8_t                    tos);

void evpl_global_config_set_rdmacm_datagram_size_override(
    struct evpl_global_config *config,
    unsigned int               size);

void evpl_global_config_set_rdmacm_srq_prefill(
    struct evpl_global_config *config,
    int                        prefill);

void evpl_global_config_set_tls_cert(
    struct evpl_global_config *config,
    const char                *cert_file);

void evpl_global_config_set_tls_key(
    struct evpl_global_config *config,
    const char                *key_file);

void evpl_global_config_set_tls_ca(
    struct evpl_global_config *config,
    const char                *ca_file);

void evpl_global_config_set_tls_cipher_list(
    struct evpl_global_config *config,
    const char                *cipher_list);

void evpl_global_config_set_tls_verify_peer(
    struct evpl_global_config *config,
    int                        verify);

void evpl_global_config_set_tls_ktls_enabled(
    struct evpl_global_config *config,
    int                        enabled);

struct evpl_thread_config *
evpl_thread_config_init(
    void);

void evpl_thread_config_release(
    struct evpl_thread_config *config);

void evpl_thread_config_set_poll_mode(
    struct evpl_thread_config *config,
    int                        poll_mode);

void evpl_thread_config_set_poll_iterations(
    struct evpl_thread_config *config,
    int                        iterations);

void evpl_thread_config_set_wait_ms(
    struct evpl_thread_config *config,
    int                        wait_ms);

void evpl_global_config_set_slab_size(
    struct evpl_global_config *config,
    uint64_t                   size);

void evpl_global_config_set_max_num_iovec(
    struct evpl_global_config *config,
    unsigned int               max);

void evpl_global_config_set_iovec_ring_size(
    struct evpl_global_config *config,
    unsigned int               size);

void evpl_global_config_set_dgram_ring_size(
    struct evpl_global_config *config,
    unsigned int               size);

void evpl_global_config_set_rdma_request_ring_size(
    struct evpl_global_config *config,
    unsigned int               size);

void evpl_global_config_set_max_datagram_batch(
    struct evpl_global_config *config,
    unsigned int               batch);

void evpl_global_config_set_resolve_timeout_ms(
    struct evpl_global_config *config,
    unsigned int               timeout_ms);

void evpl_global_config_set_io_uring_enabled(
    struct evpl_global_config *config,
    int                        enabled);

void evpl_global_config_set_rdmacm_enabled(
    struct evpl_global_config *config,
    int                        enabled);

void evpl_global_config_set_rdmacm_max_sge(
    struct evpl_global_config *config,
    unsigned int               max_sge);

void evpl_global_config_set_rdmacm_cq_size(
    struct evpl_global_config *config,
    unsigned int               size);

void evpl_global_config_set_rdmacm_sq_size(
    struct evpl_global_config *config,
    unsigned int               size);

void evpl_global_config_set_rdmacm_srq_size(
    struct evpl_global_config *config,
    unsigned int               size);

void evpl_global_config_set_rdmacm_srq_min(
    struct evpl_global_config *config,
    unsigned int               min);

void evpl_global_config_set_rdmacm_max_inline(
    struct evpl_global_config *config,
    unsigned int               max_inline);

void evpl_global_config_set_rdmacm_srq_batch(
    struct evpl_global_config *config,
    unsigned int               batch);

void evpl_global_config_set_rdmacm_retry_count(
    struct evpl_global_config *config,
    unsigned int               retry_count);

void evpl_global_config_set_rdmacm_rnr_retry_count(
    struct evpl_global_config *config,
    unsigned int               retry_count);

void evpl_global_config_set_xlio_enabled(
    struct evpl_global_config *config,
    int                        enabled);

void evpl_global_config_set_vfio_enabled(
    struct evpl_global_config *config,
    int                        enabled);

void evpl_global_config_set_hf_time_mode(
    struct evpl_global_config *config,
    unsigned int               mode);

void evpl_global_config_set_max_pending(
    struct evpl_global_config *config,
    unsigned int               max);

void evpl_global_config_set_max_poll_fd(
    struct evpl_global_config *config,
    unsigned int               max);