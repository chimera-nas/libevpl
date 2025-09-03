// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <sys/time.h>
#include <pthread.h>

#include "core/address.h"


struct evpl_endpoint {
    char                  address[256];
    int                   port;
    struct timespec       last_resolved;
    struct evpl_address  *resolved_addr;
    pthread_rwlock_t      lock;
    struct evpl_endpoint *prev;
    struct evpl_endpoint *next;
};

struct evpl_address *
evpl_endpoint_resolve(
    struct evpl_endpoint *endpoint);