#pragma once

struct evpl;
struct evpl_timer;

#include "evpl/evpl.h"

void
evpl_pop_timer(
    struct evpl *evpl);

void
evpl_timer_insert(
    struct evpl       *evpl,
    struct evpl_timer *timer);