// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

struct evpl_config *
evpl_config_init(
    void);

void evpl_config_release(
    struct evpl_config *config);

void evpl_config_set_rdmacm_datagram_size_override(
    struct evpl_config *config,
    unsigned int size);