// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

/*
 * Shared internal state for the spdk_sock TCP backend (STREAM_SPDK_TCP).
 * Included only by spdk_framework.c and spdk/tcp.c -- unlike evpl_spdk.h this
 * header includes SPDK headers.
 */

#include <stdint.h>
#include <stddef.h>
#include <netinet/in.h>

#include <spdk/sock.h>
#include <spdk/thread.h>

#include "core/evpl.h"
#include "evpl/evpl.h"

#define EVPL_SPDK_SOCK_REQ_MAX_IOV  64   /* iovecs per spdk_sock_request     */
#define EVPL_SPDK_SOCK_MAX_INFLIGHT 16   /* outstanding write reqs per sock  */
#define EVPL_SPDK_SOCK_PROGRESS_US  1000 /* interrupt-mode progress period   */

struct evpl_spdk_sock;
struct evpl_spdk_thread;

struct evpl_spdk_sock_request {
    /* iov[] must sit immediately after base: spdk_sock_writev_async locates
     * the iovec array via SPDK_SOCK_REQUEST_IOV, which assumes exactly this
     * layout. */
    struct spdk_sock_request       base;
    struct iovec                   iov[EVPL_SPDK_SOCK_REQ_MAX_IOV];
    struct evpl_spdk_sock         *sock;
    uint32_t                       niov;
    uint32_t                       total;
    struct evpl_spdk_sock_request *next;
};

/* Per-connection state, stored in evpl_bind_private (4096-byte budget). */
struct evpl_spdk_sock {
    struct evpl      *evpl;
    struct spdk_sock *sock;
    unsigned int      listen         : 1;
    unsigned int      connected      : 1;
    unsigned int      connecting     : 1;
    unsigned int      connect_failed : 1;
    unsigned int      in_group       : 1;
    unsigned int      writable       : 1;
    unsigned int      write_interest : 1;
    unsigned int      active         : 1;
    unsigned int      closed         : 1;
    uint32_t          outstanding;        /* submitted, uncompleted writes   */
    struct evpl_iovec recv1;              /* whole-buffer recv staging       */
    struct evpl_iovec recv2;
    /* Keeps spdk_sock_opts.src_addr alive for the whole async connect: the
     * posix impl shallow-copies the opts and dereferences the string across
     * connect-poller retries. */
    char              src_addr[INET6_ADDRSTRLEN];
};

/* Per-thread sock state; lives in the SPDK framework's per-thread private
 * (evpl_framework_private(evpl, EVPL_FRAMEWORK_SPDK)).  The group, poll and
 * interrupt registration are created lazily on first socket use, so SPDK
 * threads that never touch STREAM_SPDK_TCP pay only this allocation. */
struct evpl_spdk_thread {
    void                          *shared;     /* framework global private   */
    struct evpl                   *evpl;
    struct spdk_sock_group        *group;
    struct evpl_poll              *poll;
    int                            intr_registered;
    struct evpl_spdk_sock        **active;     /* write-interest sweep array */
    int                            num_active;
    int                            max_active;
    int                            num_socks;
    /* Interrupt-mode progress: the group epoll only reports EPOLLIN, so
     * in-flight connects and sndbuf-stalled writes need a timer to advance
     * while the reactor sleeps.  Counts (connecting socks + socks with
     * outstanding writes); the timer is armed while nonzero. */
    int                            progress;
    int                            progress_timer_armed;
    struct evpl_timer              progress_timer;
    struct evpl_spdk_sock_request *free_requests;
};

/* Implemented in spdk/tcp.c; called from the framework's per-thread destroy
 * so group teardown stays with the sock code. */
void
evpl_spdk_sock_thread_destroy(
    struct evpl             *evpl,
    struct evpl_spdk_thread *ctx);
