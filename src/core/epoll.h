// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

struct evpl_event;

struct evpl_core {
    int                 fd;
    int                 max_events;
    struct epoll_event *events;
};

int evpl_core_init(
    struct evpl_core *evc,
    int               max_events);

void evpl_core_destroy(
    struct evpl_core *evc);

void evpl_core_add(
    struct evpl_core  *evc,
    struct evpl_event *event);

void evpl_core_remove(
    struct evpl_core  *evc,
    struct evpl_event *event);

int evpl_core_wait(
    struct evpl_core *evc,
    int               max_msecs);

