// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <sys/select.h>

struct evpl_core_ops;
struct evpl_event;

/*
 * select(2) keeps no kernel-side registration, so the backend maintains its
 * own fd -> event table and rebuilds the fd_sets on every wait.  Slots are
 * indexed by fd, which makes add/remove O(1) and the wait scan O(max_fd).
 */
struct evpl_core_select {
    struct evpl_event **events;      /* indexed by fd; NULL when unregistered */
    int                 num_slots;   /* allocated length of events            */
    int                 max_fd;      /* highest registered fd, -1 when empty  */
};

extern const struct evpl_core_ops evpl_core_select_ops;
