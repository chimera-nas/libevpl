// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#define EVPL_INTERNAL 1
#include "event.h"
#include "evpl/evpl.h"

struct evpl_fd_event {
    struct evpl_event        event;
    evpl_fd_event_callback_t read_callback;
    evpl_fd_event_callback_t write_callback;
    evpl_fd_event_callback_t error_callback;
};
