// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/evpl.h"
#include "core/timer.h"
#include "core/macros.h"

#include "core/timing.h"

static inline void
evpl_timer_heap_up(
    struct evpl *evpl,
    int          i)
{
    struct evpl_timer *tmp;

    while (i > 0) {
        int parent = (i - 1) / 2;

        if (evpl_ts_compare(&evpl->timers[parent]->deadline, &evpl->timers[i]->deadline) < 0) {
            break;
        }

        tmp                  = evpl->timers[i];
        evpl->timers[i]      = evpl->timers[parent];
        evpl->timers[parent] = tmp;
        i                    = parent;
    }

} /* evpl_timer_heap_up */

static inline int
evpl_timer_heap_down(
    struct evpl *evpl,
    int          i)
{
    int                min_child, child;
    struct evpl_timer *tmp;

    while (1) {
        min_child = -1;

        child = 2 * i + 1;
        if (child < evpl->num_timers) {
            min_child = child;
        }

        child = 2 * i + 2;
        if (child < evpl->num_timers &&
            evpl_ts_compare(&evpl->timers[child]->deadline, &evpl->timers[min_child]->deadline) < 0) {
            min_child = child;
        }

        if (min_child == -1 ||
            evpl_ts_compare(&evpl->timers[i]->deadline, &evpl->timers[min_child]->deadline) < 0) {
            break;
        }

        tmp                     = evpl->timers[i];
        evpl->timers[i]         = evpl->timers[min_child];
        evpl->timers[min_child] = tmp;
        i                       = min_child;
    }

    return i;
} /* evpl_timer_heap_down */



void
evpl_pop_timer(struct evpl *evpl)
{

    if (evpl->num_timers > 1) {
        evpl->timers[0] = evpl->timers[evpl->num_timers - 1];
    }
    evpl->num_timers--;

    evpl_timer_heap_down(evpl, 0);

} /* evpl_pop_timer */


void
evpl_timer_insert(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    int i;

    clock_gettime(CLOCK_MONOTONIC, &timer->deadline);
    timer->deadline.tv_sec  += timer->interval / 1000000;
    timer->deadline.tv_nsec += (timer->interval % 1000000) * 1000;

    evpl->timers[evpl->num_timers] = timer;

    i = evpl->num_timers++;

    evpl_timer_heap_up(evpl, i);
} /* evpl_timer_insert */


SYMBOL_EXPORT void
evpl_remove_timer(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    int i;

    for (i = 0; i < evpl->num_timers; i++) {
        if (evpl->timers[i] == timer) {
            break;
        }
    }

    if (i >= evpl->num_timers) {
        return;
    }

    evpl->num_timers--;

    if (i == evpl->num_timers) {
        return;
    }

    evpl->timers[i] = evpl->timers[evpl->num_timers];

    i = evpl_timer_heap_down(evpl, i);

    evpl_timer_heap_up(evpl, i);
} /* evpl_timer_remove */

SYMBOL_EXPORT void
evpl_add_timer(
    struct evpl          *evpl,
    struct evpl_timer    *timer,
    evpl_timer_callback_t callback,
    uint64_t              interval_us)
{
    timer->callback = callback;
    timer->interval = interval_us;

    evpl_timer_insert(evpl, timer);
} /* evpl_add_timer */