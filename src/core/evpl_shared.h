// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

struct evpl_allocator;

struct evpl_shared {
    pthread_mutex_t             lock;
    struct evpl_global_config  *config;
    struct evpl_endpoint       *endpoints;
    struct evpl_allocator      *allocator;
    struct evpl_framework      *framework[EVPL_NUM_FRAMEWORK];
    void                       *framework_private[EVPL_NUM_FRAMEWORK];
    struct evpl_protocol       *protocol[EVPL_NUM_PROTO];
    struct evpl_block_protocol *block_protocol[EVPL_NUM_BLOCK_PROTOCOL];
};
