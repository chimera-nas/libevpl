// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once

#define EVPL_INTERNAL 1
#include "evpl/evpl.h"
#include "event.h"
#ifdef _WIN32
#include "core/iocp.h"
#else // ifdef _WIN32
#include "wakeup.h"
#endif // ifdef _WIN32

struct evpl_doorbell {
    struct evpl_doorbell_sender *sender;
};

struct evpl_doorbell_sender {
    atomic_uint                  refs;
    evpl_mutex_t                 lock;
    struct evpl                 *owner;
    struct evpl_doorbell        *receiver;
    evpl_doorbell_callback_t     callback;
    struct evpl_event            event;
#ifdef _WIN32
    struct evpl_iocp_request     notification;
    int                          queued;
#else // ifdef _WIN32
    struct evpl_wakeup           wakeup;
#endif // ifdef _WIN32
    struct evpl_doorbell_sender *prev, *next;
};

void evpl_doorbell_destroy_all(
    struct evpl *evpl);
