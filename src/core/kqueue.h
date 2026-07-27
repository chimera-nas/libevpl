// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <sys/event.h>

struct evpl_core_ops;

struct evpl_core_kqueue {
    int            fd;           /* kqueue descriptor */
    int            max_events;
    struct kevent *events;       /* buffer for kevent() results */
};

extern const struct evpl_core_ops evpl_core_kqueue_ops;
