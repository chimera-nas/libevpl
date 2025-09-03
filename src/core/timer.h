// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

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