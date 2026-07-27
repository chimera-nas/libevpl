// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

/*
 * EVPL_CORE_MECH_SPDK: guest-mode integration with an SPDK application.
 *
 * The evpl is pumped by a period-0 spdk_poller on the spdk_thread that called
 * evpl_create(); libevpl never blocks and never owns a loop (evpl_run aborts).
 * All of libevpl's fds live in an internal epoll composed from the epoll
 * backend, so interrupt-mode reactors need exactly one fd registered with the
 * thread's fd_group, plus a timerfd that translates evpl timer deadlines and
 * pending-work kicks into fd_group wakeups.  This mirrors how SPDK's own
 * POSIX sock groups integrate (an internal epoll swept from a poller).
 *
 * This header is included by core/core.h in every translation unit, so it
 * must not pull in SPDK headers; SPDK types appear only as opaque pointers.
 */

#include <stdint.h>

#include "core/epoll.h"
#include "core/event.h"

#ifndef EVPL_HAVE_EPOLL
#error "EVPL_CORE_MECH_SPDK requires the epoll core mechanism"
#endif /* ifndef EVPL_HAVE_EPOLL */

struct spdk_thread;
struct spdk_poller;
struct spdk_interrupt;

struct evpl_core_spdk {
    /* Must be first: the spdk mechanism delegates fd handling to the epoll
     * backend, whose ops locate their state via evc->u.epoll.  Backend state
     * lives in a union inside struct evpl_core, so placing the epoll state
     * first makes evc->u.epoll and evc->u.spdk.epoll the same object. */
    struct evpl_core_epoll epoll;

    struct spdk_thread    *thread;         /* owning spdk_thread             */
    struct spdk_poller    *poller;         /* period-0 pump poller           */
    struct spdk_interrupt *intr;           /* epoll fd in the fd_group       */
    int                    timer_fd;       /* one-shot CLOCK_MONOTONIC       */
    struct evpl_event      timer_event;    /* drain-only; wakes the fd_group */
    unsigned int           interrupt_mode; /* reactor phase, via mode cb     */
    unsigned int           in_pump;        /* inside evpl_continue()         */
    unsigned int           last_wait_full; /* inner wait returned max_events */
    uint64_t               armed_ns;       /* current timerfd programming    */
};

extern const struct evpl_core_ops evpl_core_spdk_ops;

struct evpl_framework;
struct evpl_protocol;
struct evpl_block_protocol;

extern struct evpl_framework      evpl_framework_spdk;
extern struct evpl_protocol       evpl_spdk_tcp;
extern struct evpl_block_protocol evpl_block_protocol_spdk_bdev;
