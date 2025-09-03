// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#define EVPL_INTERNAL 1
#include "event.h"
#include "evpl/evpl.h"

struct evpl_doorbell {
    struct evpl_event        event;
    evpl_doorbell_callback_t callback;
};