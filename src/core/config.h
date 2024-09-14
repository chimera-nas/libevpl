/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

struct eventpoll_config;

struct eventpoll_config * eventpoll_config_init(
    void);

void eventpoll_config_release(
    struct eventpoll_config *config);
