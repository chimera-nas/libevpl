
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
    uint64_t              interval;
    struct timespec       deadline;
};

void
evpl_add_timer(
    struct evpl          *evpl,
    struct evpl_timer    *timer,
    evpl_timer_callback_t callback,
    uint64_t              interval_us);

void
evpl_remove_timer(
    struct evpl       *evpl,
    struct evpl_timer *timer);