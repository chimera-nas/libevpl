// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_poll.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_poll;

typedef void (*evpl_poll_enter_callback_t)(
    struct evpl *evpl,
    void        *private_data);

typedef void (*evpl_poll_exit_callback_t)(
    struct evpl *evpl,
    void        *private_data);

typedef void (*evpl_poll_callback_t)(
    struct evpl *evpl,
    void        *private_data);

struct evpl_poll *
evpl_add_poll(
    struct evpl               *evpl,
    evpl_poll_enter_callback_t enter_callback,
    evpl_poll_exit_callback_t  exit_callback,
    evpl_poll_callback_t       callback,
    void                      *private_data);

void
evpl_remove_poll(
    struct evpl      *evpl,
    struct evpl_poll *poll);

/* Mark loop activity so a poll-mode thread does not fall back to event mode
 * after spin_ns of apparent inactivity (e.g. after servicing a polled ring). */
void
evpl_activity(
    struct evpl *evpl);

/*
 * Pin the calling thread into poll mode while the (refcounted) pin count is
 * non-zero.  Use when a thread has work outstanding that can only be observed
 * by polling -- e.g. a request handed to another thread whose completion this
 * thread reaps from a polled ring -- so the loop never sleeps and misses it.
 */
void
evpl_poll_pin(
    struct evpl *evpl);

void
evpl_poll_unpin(
    struct evpl *evpl);
