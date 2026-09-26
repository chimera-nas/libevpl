// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once
#include "evpl/evpl_export.h"

#include <stdint.h>
#include <stddef.h>

#ifndef EVPL_INCLUDED
#error "Do not include evpl_config.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_global_config;
struct evpl_thread_config;

/*
 * Event-loop core mechanism.  Every mechanism supported on the build platform
 * is compiled in and selectable at runtime: epoll on Linux, kqueue on macOS
 * and the BSDs, and select on both as a portable fallback.
 *
 * EVPL_CORE_MECH_DEFAULT picks the platform default -- epoll on Linux, kqueue
 * on macOS -- and always succeeds.  Requesting a mechanism that is not
 * available on the running platform (e.g. epoll on macOS) aborts at
 * evpl_init().
 */
enum evpl_core_mech {
    EVPL_CORE_MECH_DEFAULT = 0,   /* platform default (epoll/kqueue) */
    EVPL_CORE_MECH_EPOLL   = 1,
    EVPL_CORE_MECH_KQUEUE  = 2,
    EVPL_CORE_MECH_SELECT  = 3,
    EVPL_CORE_MECH_IOCP    = 4,
    /* Guest mode inside an SPDK application: each evpl is pumped by an
     * spdk_poller on the spdk_thread that created it.  Never the platform
     * default; requires the host to have initialized the SPDK env and thread
     * library, and evpl_create() must run on an spdk_thread. */
    EVPL_CORE_MECH_SPDK    = 5,
    EVPL_CORE_MECH_INHERIT = 6, /* per-context: use the global default */
};

EVPL_API struct evpl_global_config *
evpl_global_config_init(
    void);

EVPL_API void evpl_global_config_set_core_mech(
    struct evpl_global_config *config,
    enum evpl_core_mech        mech);

EVPL_API void evpl_global_config_release(
    struct evpl_global_config *config);


EVPL_API void evpl_global_config_set_buffer_size(
    struct evpl_global_config *config,
    uint64_t                   size);

EVPL_API void evpl_global_config_set_spin_ns(
    struct evpl_global_config *config,
    uint64_t                   ns);

EVPL_API void evpl_global_config_set_max_datagram_size(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_huge_pages(
    struct evpl_global_config *config,
    int                        huge_pages);

/* Select the hugetlb page size used to back slabs when huge pages are enabled.
 * Must be a power-of-two size of a hugetlb pool the kernel exposes (e.g.
 * 2 MiB or 1 GiB); invalid sizes are rejected and the default (2 MiB) kept.
 * The slab size should be a multiple of this, or the mapping falls back to
 * base pages. */
EVPL_API void evpl_global_config_set_huge_page_size(
    struct evpl_global_config *config,
    uint64_t                   size);

EVPL_API void evpl_global_config_set_rdmacm_tos(
    struct evpl_global_config *config,
    uint8_t                    tos);

EVPL_API void evpl_global_config_set_rdmacm_datagram_size_override(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_rdmacm_srq_prefill(
    struct evpl_global_config *config,
    int                        prefill);

EVPL_API void evpl_global_config_set_tls_cert(
    struct evpl_global_config *config,
    const char                *cert_file);

EVPL_API void evpl_global_config_set_tls_key(
    struct evpl_global_config *config,
    const char                *key_file);

EVPL_API void evpl_global_config_set_tls_ca(
    struct evpl_global_config *config,
    const char                *ca_file);

EVPL_API void evpl_global_config_set_tls_cipher_list(
    struct evpl_global_config *config,
    const char                *cipher_list);

EVPL_API void evpl_global_config_set_tls_verify_peer(
    struct evpl_global_config *config,
    int                        verify);

EVPL_API void evpl_global_config_set_tls_ktls_enabled(
    struct evpl_global_config *config,
    int                        enabled);

/*
 * Maximum size in bytes of an HTTP/1.x header block (request or status
 * line, all header lines, and the terminating blank line), applied in both
 * directions.  Inbound, a peer exceeding it gets the connection closed (a
 * server answers 400 Bad Request first).  Outbound, adding a header that
 * would overflow it makes evpl_http_request_add_header() fail.  Default
 * 8192, in line with Apache's request field limits.
 */
EVPL_API void evpl_global_config_set_http_max_header_size(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API struct evpl_thread_config *
evpl_thread_config_init(
    void);

EVPL_API void evpl_thread_config_release(
    struct evpl_thread_config *config);

/* Select a backend for this context/worker. DEFAULT selects the native
 * platform backend, even when the global default is SPDK. */
EVPL_API void evpl_thread_config_set_core_mech(
    struct evpl_thread_config *config,
    enum evpl_core_mech        mech);

EVPL_API void evpl_thread_config_set_poll_mode(
    struct evpl_thread_config *config,
    int                        poll_mode);

EVPL_API void evpl_thread_config_set_poll_iterations(
    struct evpl_thread_config *config,
    int                        iterations);

EVPL_API void evpl_thread_config_set_wait_ms(
    struct evpl_thread_config *config,
    int                        wait_ms);

/* Thread name, used e.g. to name the spdk_thread created for an evpl_thread
 * under EVPL_CORE_MECH_SPDK.  Truncated to the config field size. */
EVPL_API void evpl_thread_config_set_name(
    struct evpl_thread_config *config,
    const char                *name);

/* SPDK cpumask string (as accepted by spdk_cpuset_parse, e.g. "0x3" or
 * "[0,1]") constraining where the host scheduler may place the spdk_thread
 * created for an evpl_thread.  Empty (default) lets the host decide.  Only
 * meaningful under EVPL_CORE_MECH_SPDK. */
EVPL_API void evpl_thread_config_set_spdk_cpumask(
    struct evpl_thread_config *config,
    const char                *cpumask);

EVPL_API void evpl_global_config_set_slab_size(
    struct evpl_global_config *config,
    uint64_t                   size);

EVPL_API void evpl_global_config_set_max_num_iovec(
    struct evpl_global_config *config,
    unsigned int               max);

/*
 * Maximum size of a single RPC2 message, counted across every fragment of a
 * record.  A record mark claiming more than this is refused at the framing
 * layer and the connection is closed, so an unauthenticated peer cannot make
 * the transport buffer on its terms.  Defaults to 4 MiB; pass 0 to restore
 * the default.
 */
EVPL_API void evpl_global_config_set_rpc2_max_message_size(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_iovec_ring_size(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_dgram_ring_size(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_rdma_request_ring_size(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_max_datagram_batch(
    struct evpl_global_config *config,
    unsigned int               batch);

EVPL_API void evpl_global_config_set_resolve_timeout_ms(
    struct evpl_global_config *config,
    unsigned int               timeout_ms);

EVPL_API void evpl_global_config_set_io_uring_enabled(
    struct evpl_global_config *config,
    int                        enabled);

EVPL_API void evpl_global_config_set_io_uring_entries(
    struct evpl_global_config *config,
    unsigned int               entries);

EVPL_API void evpl_global_config_set_io_uring_sqpoll(
    struct evpl_global_config *config,
    int                        enabled);

/* Tri-state values for io_uring optional features */
#define EVPL_IO_URING_OFF  0
#define EVPL_IO_URING_ON   1
#define EVPL_IO_URING_AUTO 2

EVPL_API void evpl_global_config_set_io_uring_zerocopy_rx(
    struct evpl_global_config *config,
    unsigned int               mode);

EVPL_API void evpl_global_config_set_io_uring_zcrx_interface(
    struct evpl_global_config *config,
    const char                *ifname);

EVPL_API void evpl_global_config_set_io_uring_zcrx_rxq(
    struct evpl_global_config *config,
    unsigned int               rxq);

EVPL_API void evpl_global_config_set_io_uring_zcrx_rxq_count(
    struct evpl_global_config *config,
    unsigned int               count);
/* Register this many consecutive receive queues (starting at zcrx_rxq) as
 * zero-copy ifqs on each ring; accepted sockets use the ifq of the queue
 * they arrive on.  Default 1. */
EVPL_API void evpl_global_config_set_io_uring_zcrx_ifq_count(
    struct evpl_global_config *config,
    unsigned int               count);
/* SO_SNDBUF/SO_RCVBUF for XLIO sockets (the receive side is the advertised
 * TCP window). Default 16 MiB; 2 MiB caps one 200GbE stream near 100 Gbps. */
EVPL_API void evpl_global_config_set_xlio_socket_buffer_size(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_io_uring_zcrx_area_size(
    struct evpl_global_config *config,
    size_t                     size);

EVPL_API void evpl_global_config_set_io_uring_zcrx_rq_entries(
    struct evpl_global_config *config,
    unsigned int               entries);

EVPL_API void evpl_global_config_set_io_uring_zcrx_rx_buf_len(
    struct evpl_global_config *config,
    unsigned int               len);

EVPL_API void evpl_global_config_set_io_uring_zcrx_area_import(
    struct evpl_global_config *config,
    int                        enable);

EVPL_API void evpl_global_config_set_io_uring_registered_buffers(
    struct evpl_global_config *config,
    unsigned int               mode);

EVPL_API void evpl_global_config_set_io_uring_registered_files(
    struct evpl_global_config *config,
    unsigned int               mode);

EVPL_API void evpl_global_config_set_io_uring_send_zc(
    struct evpl_global_config *config,
    unsigned int               mode);

EVPL_API void evpl_global_config_set_io_uring_recv_bundle(
    struct evpl_global_config *config,
    unsigned int               mode);

EVPL_API void evpl_global_config_set_rdmacm_enabled(
    struct evpl_global_config *config,
    int                        enabled);

EVPL_API void evpl_global_config_set_rdmacm_max_sge(
    struct evpl_global_config *config,
    unsigned int               max_sge);

EVPL_API void evpl_global_config_set_rdmacm_cq_size(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_rdmacm_sq_size(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_rdmacm_flush_batch(
    struct evpl_global_config *config,
    unsigned int               batch);

EVPL_API void evpl_global_config_set_rdmacm_srq_size(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_rdmacm_srq_min(
    struct evpl_global_config *config,
    unsigned int               min);

EVPL_API void evpl_global_config_set_rdmacm_max_inline(
    struct evpl_global_config *config,
    unsigned int               max_inline);

EVPL_API void evpl_global_config_set_rdmacm_srq_batch(
    struct evpl_global_config *config,
    unsigned int               batch);

EVPL_API void evpl_global_config_set_rdmacm_retry_count(
    struct evpl_global_config *config,
    unsigned int               retry_count);

EVPL_API void evpl_global_config_set_rdmacm_rnr_retry_count(
    struct evpl_global_config *config,
    unsigned int               retry_count);

EVPL_API void evpl_global_config_set_libfabric_enabled(
    struct evpl_global_config *config,
    int                        enabled);

/* Share MSG receive buffers per thread/domain when supported (default on).
 * A receive CQ per connection preserves completion identity. Disable to use
 * private receive buffers; RDM always uses private receive queues. */
EVPL_API void evpl_global_config_set_libfabric_srq_enabled(
    struct evpl_global_config *config,
    int                        enabled);

/* Pin the libfabric provider by name (e.g. "verbs", "tcp"); NULL restores
 * libfabric's own auto-selection.  Ignored when an external domain is set.
 */
EVPL_API void evpl_global_config_set_libfabric_provider(
    struct evpl_global_config *config,
    const char                *provider);

EVPL_API void evpl_global_config_set_libfabric_cq_size(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_libfabric_tx_size(
    struct evpl_global_config *config,
    unsigned int               size);

/* Receive buffers per shared queue, or per endpoint without sharing. */
EVPL_API void evpl_global_config_set_libfabric_rq_size(
    struct evpl_global_config *config,
    unsigned int               size);

/* Refill after at least this many buffers are consumed; clamped to rq_size. */
EVPL_API void evpl_global_config_set_libfabric_rq_batch(
    struct evpl_global_config *config,
    unsigned int               batch);

EVPL_API void evpl_global_config_set_libfabric_inject_max(
    struct evpl_global_config *config,
    unsigned int               max);

EVPL_API void evpl_global_config_set_libfabric_datagram_size_override(
    struct evpl_global_config *config,
    unsigned int               size);

EVPL_API void evpl_global_config_set_xlio_enabled(
    struct evpl_global_config *config,
    int                        enabled);

EVPL_API void evpl_global_config_set_vfio_enabled(
    struct evpl_global_config *config,
    int                        enabled);

EVPL_API void evpl_global_config_set_libaio_enabled(
    struct evpl_global_config *config,
    int                        enabled);

EVPL_API void evpl_global_config_set_spdk_enabled(
    struct evpl_global_config *config,
    int                        enabled);

/* spdk_sock implementation for STREAM_SPDK_TCP ("posix", "uring", ...);
 * NULL (default) selects SPDK's default implementation. */
EVPL_API void evpl_global_config_set_spdk_sock_impl(
    struct evpl_global_config *config,
    const char                *impl_name);

EVPL_API void evpl_global_config_set_libaio_max_pending(
    struct evpl_global_config *config,
    unsigned int               max_pending);

/* The pread block backend, which services a device from its own thread with
 * blocking pread()/pwrite().  Enabled by default: it depends on nothing but
 * POSIX, so unlike the other block backends it is always compiled in. */
EVPL_API void evpl_global_config_set_pread_enabled(
    struct evpl_global_config *config,
    unsigned int               enabled);

EVPL_API void evpl_global_config_set_hf_time_mode(
    struct evpl_global_config *config,
    unsigned int               mode);

/*
 * Take the event loop off the machine's clock and put it on one the
 * application advances by hand, with evpl_virtual_clock_advance().
 *
 * Timer deadlines, the poll-mode spin window and every other internal
 * deadline are then measured against that clock alone, so nothing in the loop
 * happens because wall-clock time passed.  The core wait stops blocking as
 * well: with no way for time to move while the loop is inside it, a wait for
 * a deadline would be a wait for something that cannot happen.
 *
 * This exists so that time-dependent behaviour can be tested for what it is
 * rather than for how loaded the machine was -- a test advances the clock by a
 * known amount and drives the loop, instead of sleeping and hoping.  It is
 * process-wide and must be set before evpl_init().
 *
 * Do not enable it in production: a loop on this clock never sleeps, and any
 * timer in it stops firing the moment the application stops advancing time.
 */
EVPL_API void evpl_global_config_set_virtual_clock(
    struct evpl_global_config *config,
    int                        enabled);

EVPL_API void evpl_global_config_set_max_pending(
    struct evpl_global_config *config,
    unsigned int               max);

EVPL_API void evpl_global_config_set_max_poll_fd(
    struct evpl_global_config *config,
    unsigned int               max);

EVPL_API void evpl_global_config_set_preallocate_slabs(
    struct evpl_global_config *config,
    unsigned int               slabs);

EVPL_API void evpl_global_config_set_preallocate_threads(
    struct evpl_global_config *config,
    unsigned int               threads);

/* Prefer SGLs on capable VFIO NVMe controllers (default 1). Setting 0 uses
 * the mandatory PRP format, useful when qualifying either DMA representation. */
EVPL_API void evpl_global_config_set_vfio_sgl_enabled(
    struct evpl_global_config *config,
    int                        enabled);
