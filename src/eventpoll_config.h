/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#ifndef __EVENTPOLL_CONFIG_H__
#define __EVENTPOLL_CONFIG_H__

struct eventpoll_config;

struct eventpoll_config * eventpoll_config_init(void);

void eventpoll_config_release(struct eventpoll_config *config);

#endif
