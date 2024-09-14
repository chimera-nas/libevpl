/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

struct evpl_config;

struct evpl_config * evpl_config_init(
    void);

void evpl_config_release(
    struct evpl_config *config);
