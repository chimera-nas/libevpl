/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#ifndef __EVENTPOLL_CORE_H__
#define __EVENTPOLL_CORE_H__

struct eventpoll_event;

struct eventpoll_core {
    int                 fd;
    int                 max_events;
    struct epoll_event *events;
};

int eventpoll_core_init(
    struct eventpoll_core *evc,
    int                    max_events);
void eventpoll_core_destroy(
    struct eventpoll_core *evc);

void eventpoll_core_add(
    struct eventpoll_core  *evc,
    struct eventpoll_event *event);

void eventpoll_core_wait(
    struct eventpoll_core *evc,
    int                    max_msecs);


#endif // ifndef __EVENTPOLL_CORE_H__
