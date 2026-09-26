// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
#include "core/evpl.h"
#ifdef HAVE_LIBFABRIC
#include "evpl/evpl_libfabric.h"
#endif // ifdef HAVE_LIBFABRIC

/* API smoke coverage is intentionally separate from the configuration pair
* coverage. Most accessors have no public getter; inspecting stored values
* here checks the setter without pretending a backend used that setting. */
static void
mbt_config_defaults(struct evpl_global_config *config)
{
    struct evpl_global_config before;

    memcpy(&before, config, sizeof(before));
    evpl_global_config_set_core_mech(config, before.core_mech);
    evpl_global_config_set_buffer_size(config, before.buffer_size);
    evpl_global_config_set_spin_ns(config, before.thread_default.spin_ns);
    evpl_global_config_set_max_datagram_size(config, before.max_datagram_size);
    evpl_global_config_set_huge_pages(config, before.huge_pages);
    evpl_global_config_set_huge_page_size(config, before.huge_page_size);
    evpl_global_config_set_rdmacm_tos(config, before.rdmacm_tos);
    evpl_global_config_set_rdmacm_datagram_size_override(config, before.rdmacm_datagram_size_override);
    evpl_global_config_set_rdmacm_srq_prefill(config, before.rdmacm_srq_prefill);
    evpl_global_config_set_tls_verify_peer(config, before.tls_verify_peer);
    evpl_global_config_set_tls_ktls_enabled(config, before.tls_ktls_enabled);
    evpl_global_config_set_http_max_header_size(config, before.http_max_header_size);
    evpl_global_config_set_slab_size(config, before.slab_size);
    evpl_global_config_set_max_num_iovec(config, before.max_num_iovec);
    evpl_global_config_set_rpc2_max_message_size(config, before.rpc2_max_message_size);
    evpl_global_config_set_iovec_ring_size(config, before.iovec_ring_size);
    evpl_global_config_set_dgram_ring_size(config, before.dgram_ring_size);
    evpl_global_config_set_rdma_request_ring_size(config, before.rdma_request_ring_size);
    evpl_global_config_set_max_datagram_batch(config, before.max_datagram_batch);
    evpl_global_config_set_resolve_timeout_ms(config, before.resolve_timeout_ms);
    evpl_global_config_set_io_uring_enabled(config, before.io_uring_enabled);
    evpl_global_config_set_io_uring_entries(config, before.io_uring_entries);
    evpl_global_config_set_io_uring_sqpoll(config, before.io_uring_sqpoll);
    evpl_global_config_set_rdmacm_enabled(config, before.rdmacm_enabled);
    evpl_global_config_set_rdmacm_max_sge(config, before.rdmacm_max_sge);
    evpl_global_config_set_rdmacm_cq_size(config, before.rdmacm_cq_size);
    evpl_global_config_set_rdmacm_sq_size(config, before.rdmacm_sq_size);
    evpl_global_config_set_rdmacm_flush_batch(config, before.rdmacm_flush_batch);
    evpl_global_config_set_rdmacm_srq_size(config, before.rdmacm_srq_size);
    evpl_global_config_set_rdmacm_srq_min(config, before.rdmacm_srq_min);
    evpl_global_config_set_rdmacm_max_inline(config, before.rdmacm_max_inline);
    evpl_global_config_set_rdmacm_srq_batch(config, before.rdmacm_srq_batch);
    evpl_global_config_set_rdmacm_retry_count(config, before.rdmacm_retry_count);
    evpl_global_config_set_rdmacm_rnr_retry_count(config, before.rdmacm_rnr_retry_count);
    evpl_global_config_set_libfabric_enabled(config, before.libfabric_enabled);
    evpl_global_config_set_libfabric_srq_enabled(config, before.libfabric_srq_enabled);
    evpl_global_config_set_libfabric_cq_size(config, before.libfabric_cq_size);
    evpl_global_config_set_libfabric_tx_size(config, before.libfabric_tx_size);
    evpl_global_config_set_libfabric_rq_size(config, before.libfabric_rq_size);
    evpl_global_config_set_libfabric_rq_batch(config, before.libfabric_rq_batch);
    evpl_global_config_set_libfabric_inject_max(config, before.libfabric_inject_max);
    evpl_global_config_set_libfabric_datagram_size_override(config, before.libfabric_datagram_size_override);
    evpl_global_config_set_xlio_enabled(config, before.xlio_enabled);
    evpl_global_config_set_xlio_socket_buffer_size(config, before.xlio_socket_buffer_size);
    evpl_global_config_set_vfio_enabled(config, before.vfio_enabled);
    evpl_global_config_set_libaio_enabled(config, before.libaio_enabled);
    evpl_global_config_set_spdk_enabled(config, before.spdk_enabled);
    evpl_global_config_set_spdk_managed(config, before.spdk_managed);
    evpl_global_config_set_libaio_max_pending(config, before.libaio_max_pending);
    evpl_global_config_set_pread_enabled(config, before.pread_enabled);
    evpl_global_config_set_hf_time_mode(config, before.hf_time_mode);
    evpl_global_config_set_virtual_clock(config, before.virtual_clock);
    evpl_global_config_set_max_pending(config, before.max_pending);
    evpl_global_config_set_max_poll_fd(config, before.max_poll_fd);
    evpl_global_config_set_preallocate_slabs(config, before.preallocate_slabs);
    evpl_global_config_set_preallocate_threads(config, before.preallocate_threads);
    evpl_global_config_set_vfio_sgl_enabled(config, before.vfio_sgl_enabled);
    evpl_global_config_set_io_uring_zerocopy_rx(config, before.io_uring_zerocopy_rx);
    evpl_global_config_set_io_uring_zcrx_interface(config, before.io_uring_zcrx_interface);
    evpl_global_config_set_io_uring_zcrx_rxq(config, before.io_uring_zcrx_rxq);
    evpl_global_config_set_io_uring_zcrx_rxq_count(config, before.io_uring_zcrx_rxq_count);
    evpl_global_config_set_io_uring_zcrx_ifq_count(config, before.io_uring_zcrx_ifq_count);
    evpl_global_config_set_io_uring_zcrx_area_size(config, before.io_uring_zcrx_area_size);
    evpl_global_config_set_io_uring_zcrx_rq_entries(config, before.io_uring_zcrx_rq_entries);
    evpl_global_config_set_io_uring_zcrx_rx_buf_len(config, before.io_uring_zcrx_rx_buf_len);
    evpl_global_config_set_io_uring_zcrx_area_import(config, before.io_uring_zcrx_area_import);
    evpl_global_config_set_io_uring_registered_buffers(config, before.io_uring_registered_buffers);
    evpl_global_config_set_io_uring_registered_files(config, before.io_uring_registered_files);
    evpl_global_config_set_io_uring_send_zc(config, before.io_uring_send_zc);
    evpl_global_config_set_io_uring_recv_bundle(config, before.io_uring_recv_bundle);
#ifdef HAVE_LIBFABRIC
    evpl_global_config_set_libfabric_external_domain(config, NULL, NULL, NULL);
#endif // ifdef HAVE_LIBFABRIC
    evpl_test_abort_if(memcmp(config, &before, sizeof(before)), "setting defaults changed configuration");

    /* These setters copy strings. Use a disposable, never-initialized config
     * so certificate names need no credentials and providers need no hardware.
     * Mutating the input proves the stored value does not borrow its memory. */
    struct evpl_global_config *strings = evpl_global_config_init();
    char                       text[]  = "mbt-first";
    evpl_global_config_set_tls_cert(strings, text);
    evpl_global_config_set_tls_key(strings, text);
    evpl_global_config_set_tls_ca(strings, text);
    evpl_global_config_set_tls_cipher_list(strings, text);
    evpl_global_config_set_libfabric_provider(strings, text);
    evpl_global_config_set_spdk_sock_impl(strings, text);
    evpl_global_config_set_io_uring_zcrx_interface(strings, text);
    text[0] = 'X';
    evpl_test_abort_if(strcmp(strings->tls_cert_file, "mbt-first"), "tls_cert did not copy its input");
    evpl_global_config_set_tls_cert(strings, "mbt-second");
    evpl_test_abort_if(strcmp(strings->tls_cert_file, "mbt-second"), "tls_cert replacement failed");
    evpl_test_abort_if(strcmp(strings->tls_key_file, "mbt-first"), "tls_key did not copy its input");
    evpl_global_config_set_tls_key(strings, "mbt-second");
    evpl_test_abort_if(strcmp(strings->tls_key_file, "mbt-second"), "tls_key replacement failed");
    evpl_test_abort_if(strcmp(strings->tls_ca_file, "mbt-first"), "tls_ca did not copy its input");
    evpl_global_config_set_tls_ca(strings, "mbt-second");
    evpl_test_abort_if(strcmp(strings->tls_ca_file, "mbt-second"), "tls_ca replacement failed");
    evpl_global_config_set_tls_ca(strings, NULL);
    evpl_test_abort_if(strings->tls_ca_file, "tls_ca reset failed");
    evpl_test_abort_if(strcmp(strings->tls_cipher_list, "mbt-first"), "tls_cipher_list did not copy its input");
    evpl_global_config_set_tls_cipher_list(strings, "mbt-second");
    evpl_test_abort_if(strcmp(strings->tls_cipher_list, "mbt-second"), "tls_cipher_list replacement failed");
    evpl_global_config_set_tls_cipher_list(strings, NULL);
    evpl_test_abort_if(strings->tls_cipher_list, "tls_cipher_list reset failed");
    evpl_test_abort_if(strcmp(strings->libfabric_provider, "mbt-first"), "libfabric_provider did not copy its input");
    evpl_global_config_set_libfabric_provider(strings, "mbt-second");
    evpl_test_abort_if(strcmp(strings->libfabric_provider, "mbt-second"), "libfabric_provider replacement failed");
    evpl_global_config_set_libfabric_provider(strings, NULL);
    evpl_test_abort_if(strings->libfabric_provider, "libfabric_provider reset failed");
    evpl_test_abort_if(strcmp(strings->spdk_sock_impl, "mbt-first"), "spdk_sock_impl did not copy its input");
    evpl_global_config_set_spdk_sock_impl(strings, "mbt-second");
    evpl_test_abort_if(strcmp(strings->spdk_sock_impl, "mbt-second"), "spdk_sock_impl replacement failed");
    evpl_global_config_set_spdk_sock_impl(strings, NULL);
    evpl_test_abort_if(strings->spdk_sock_impl, "spdk_sock_impl reset failed");
    evpl_test_abort_if(strcmp(strings->io_uring_zcrx_interface, "mbt-first"),
                       "io_uring_zcrx_interface did not copy its input");
    evpl_global_config_set_io_uring_zcrx_interface(strings, "mbt-second");
    evpl_test_abort_if(strcmp(strings->io_uring_zcrx_interface, "mbt-second"),
                       "io_uring_zcrx_interface replacement failed");
    evpl_global_config_set_io_uring_zcrx_interface(strings, NULL);
    evpl_test_abort_if(strings->io_uring_zcrx_interface, "io_uring_zcrx_interface reset failed");
    evpl_global_config_release(strings);
} /* mbt_config_defaults */

static void
mbt_config_readers(const struct evpl_global_config *config)
{
    evpl_test_abort_if(evpl_get_slab_size() != config->slab_size, "slab size getter mismatch");
    evpl_test_abort_if(evpl_global_config_get_http_max_header_size() != config->http_max_header_size,
                       "HTTP header limit getter mismatch");
    unsigned int               rpc_limit = config->rpc2_max_message_size ? config->rpc2_max_message_size :
        EVPL_DEFAULT_RPC2_MAX_MESSAGE_SIZE(config->buffer_size);
    evpl_test_abort_if(evpl_config_rpc2_max_message_size() != rpc_limit, "RPC limit getter mismatch");
    struct evpl_thread_config *thread = evpl_thread_config_init();
    struct evpl_thread_config  before;
    memcpy(&before, thread, sizeof(before));
    evpl_thread_config_set_core_mech(thread, before.core_mech);
    evpl_thread_config_set_poll_mode(thread, before.poll_mode);
    evpl_thread_config_set_poll_iterations(thread, before.poll_iterations);
    evpl_thread_config_set_wait_ms(thread, before.wait_ms);
    evpl_thread_config_set_name(thread, before.name);
    evpl_thread_config_set_spdk_cpumask(thread, before.spdk_cpumask);
    evpl_test_abort_if(memcmp(thread, &before, sizeof(before)), "thread config round trip failed");
    evpl_thread_config_release(thread);
} /* mbt_config_readers */
