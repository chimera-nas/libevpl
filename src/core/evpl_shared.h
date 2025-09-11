// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <pthread.h>

#define EVPL_INTERNAL 1

#include "evpl/evpl.h"
#include "protocol.h"
#include "allocator.h"

struct evpl_allocator;

struct evpl_shared {
    pthread_mutex_t             lock;
    struct evpl_global_config  *config;
    struct evpl_numa_config    *numa_config;
    struct evpl_endpoint       *endpoints;
    struct evpl_allocator      *allocator;
    struct evpl_framework      *framework[EVPL_NUM_FRAMEWORK];
    void                       *framework_private[EVPL_NUM_FRAMEWORK];
    struct evpl_protocol       *protocol[EVPL_NUM_PROTO];
    struct evpl_block_protocol *block_protocol[EVPL_NUM_BLOCK_PROTOCOL];
};

extern struct evpl_shared *evpl_shared;


static inline void
evpl_attach_framework_shared(enum evpl_framework_id framework_id)
{
    struct evpl_framework *framework = evpl_shared->framework[framework_id];

    pthread_mutex_lock(&evpl_shared->lock);

    if (!evpl_shared->framework_private[framework->id]) {

        evpl_shared->framework_private[framework->id] = framework->init();

        if (evpl_shared->framework_private[framework->id]) {
            evpl_allocator_reregister(evpl_shared->allocator);
        }
    }

    pthread_mutex_unlock(&evpl_shared->lock);
} /* evpl_attach_framework_shared */