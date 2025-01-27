// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_config.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_config;

struct evpl_config *
evpl_config_init(
    void);

void evpl_config_release(
    struct evpl_config *config);

void evpl_config_set_max_datagram_size(
    struct evpl_config *config,
    unsigned int        size);

void evpl_config_set_huge_pages(
    struct evpl_config *config,
    int                 huge_pages);

void evpl_config_set_rdmacm_datagram_size_override(
    struct evpl_config *config,
    unsigned int        size);