// SPDX-FileCopyrightText: 2024 - 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <sys/epoll.h>

struct evpl_core_ops;

struct evpl_core_epoll {
    int                 fd;
    int                 max_events;
    struct epoll_event *events;
};

extern const struct evpl_core_ops evpl_core_epoll_ops;
