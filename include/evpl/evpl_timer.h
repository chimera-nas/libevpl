// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdint.h>
#include <sys/time.h>

#ifndef EVPL_INCLUDED
#error "Do not include evpl_timer.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_timer;

typedef void (*evpl_timer_callback_t)(
    struct evpl       *evpl,
    struct evpl_timer *timer);

struct evpl_timer {
    evpl_timer_callback_t callback;
    uint64_t              interval;       /* microseconds */
    uint64_t              deadline;       /* stopwatch ticks (see evpl_now_ticks) */
    int                   oneshot;
};

/*
 * Add a periodic timer.  `callback` fires every `interval_us` microseconds
 * until evpl_remove_timer() is called.  The timer is re-armed automatically
 * after each firing, so the callback must not free the timer.
 */
void
evpl_add_timer(
    struct evpl          *evpl,
    struct evpl_timer    *timer,
    evpl_timer_callback_t callback,
    uint64_t              interval_us);

/*
 * Add a one-shot timer that fires once, `delay_us` microseconds from now, and
 * is then removed automatically.  The timer is removed from the timer set
 * before its callback runs, so the callback may free the timer or re-arm it.
 * Calling evpl_remove_timer() after it has fired is a harmless no-op.
 */
void
evpl_add_oneshot_timer(
    struct evpl          *evpl,
    struct evpl_timer    *timer,
    evpl_timer_callback_t callback,
    uint64_t              delay_us);

void
evpl_remove_timer(
    struct evpl       *evpl,
    struct evpl_timer *timer);