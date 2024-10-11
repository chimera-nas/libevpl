/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

struct evpl_event;

struct evpl_core {
    int                 fd;
    int                 max_events;
    struct epoll_event *events;
    struct evpl_xlio_shared *xlio;
};

int evpl_core_init(
    struct evpl_core *evc,
    int               max_events,
    void            **framework_private);

void evpl_core_destroy(
    struct evpl_core *evc);

void evpl_core_add(
    struct evpl_core  *evc,
    struct evpl_event *event);

void evpl_core_wait(
    struct evpl_core *evc,
    int               max_msecs);

