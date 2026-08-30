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
};

struct evpl_global_config *
evpl_global_config_init(
    void);

void evpl_global_config_set_core_mech(
    struct evpl_global_config *config,
    enum evpl_core_mech        mech);

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

/* Select the hugetlb page size used to back slabs when huge pages are enabled.
 * Must be a power-of-two size of a hugetlb pool the kernel exposes (e.g.
 * 2 MiB or 1 GiB); invalid sizes are rejected and the default (2 MiB) kept.
 * The slab size should be a multiple of this, or the mapping falls back to
 * base pages. */
void evpl_global_config_set_huge_page_size(
    struct evpl_global_config *config,
    uint64_t                   size);

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

/*
 * Maximum size in bytes of an HTTP/1.x header block (request or status
 * line, all header lines, and the terminating blank line), applied in both
 * directions.  Inbound, a peer exceeding it gets the connection closed (a
 * server answers 400 Bad Request first).  Outbound, adding a header that
 * would overflow it makes evpl_http_request_add_header() fail.  Default
 * 8192, in line with Apache's request field limits.
 */
void evpl_global_config_set_http_max_header_size(
    struct evpl_global_config *config,
    unsigned int               size);

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

/*
 * Maximum size of a single RPC2 message, counted across every fragment of a
 * record.  A record mark claiming more than this is refused at the framing
 * layer and the connection is closed, so an unauthenticated peer cannot make
 * the transport buffer on its terms.  Defaults to 4 MiB; pass 0 to restore
 * the default.
 */
void evpl_global_config_set_rpc2_max_message_size(
    struct evpl_global_config *config,
    unsigned int               size);

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

void evpl_global_config_set_io_uring_entries(
    struct evpl_global_config *config,
    unsigned int               entries);

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

void evpl_global_config_set_libaio_enabled(
    struct evpl_global_config *config,
    int                        enabled);

void evpl_global_config_set_libaio_max_pending(
    struct evpl_global_config *config,
    unsigned int               max_pending);

/* The pread block backend, which services a device from its own thread with
 * blocking pread()/pwrite().  Enabled by default: it depends on nothing but
 * POSIX, so unlike the other block backends it is always compiled in. */
void evpl_global_config_set_pread_enabled(
    struct evpl_global_config *config,
    unsigned int               enabled);

void evpl_global_config_set_hf_time_mode(
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
void evpl_global_config_set_virtual_clock(
    struct evpl_global_config *config,
    int                        enabled);

void evpl_global_config_set_max_pending(
    struct evpl_global_config *config,
    unsigned int               max);

void evpl_global_config_set_max_poll_fd(
    struct evpl_global_config *config,
    unsigned int               max);

void evpl_global_config_set_preallocate_slabs(
    struct evpl_global_config *config,
    unsigned int               slabs);

void evpl_global_config_set_preallocate_threads(
    struct evpl_global_config *config,
    unsigned int               threads);