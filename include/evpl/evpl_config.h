// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#include <stdint.h>

#ifndef EVPL_INCLUDED
#error "Do not include evpl_config.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl_global_config;
struct evpl_thread_config;

struct evpl_global_config *
evpl_global_config_init(
    void);

void evpl_global_config_release(
    struct evpl_global_config *config);

void evpl_global_config_set_spin_ns(
    struct evpl_global_config *config,
    uint64_t                   ns);

void evpl_global_config_set_max_datagram_size(
    struct evpl_global_config *config,
    unsigned int               size);

void evpl_global_config_set_huge_pages(
    struct evpl_global_config *config,
    int                        huge_pages);

void evpl_global_config_set_rdmacm_tos(
    struct evpl_global_config *config,
    uint8_t                    tos);

void evpl_global_config_set_rdmacm_datagram_size_override(
    struct evpl_global_config *config,
    unsigned int               size);

void evpl_global_config_set_rdmacm_srq_prefill(
    struct evpl_global_config *config,
    int                        prefill);

struct evpl_thread_config *
evpl_thread_config_init(
    void);

void evpl_thread_config_release(
    struct evpl_thread_config *config);
