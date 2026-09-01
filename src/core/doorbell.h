// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#define EVPL_INTERNAL         1
#include "event.h"
#include "wakeup.h"
#include "evpl/evpl.h"

/* State magics rather than a 0/1/2 enum: a doorbell whose storage was never
 * zeroed reads as garbage, and garbage must report as "unknown" rather than
 * impersonate one of the real states. */
#define EVPL_DOORBELL_LIVE    0x11feb001
#define EVPL_DOORBELL_REMOVED 0xdeadb001

struct evpl_doorbell {
    struct evpl_event        event;
    struct evpl_wakeup       wakeup;
    evpl_doorbell_callback_t callback;
    /* Where this doorbell last changed lifecycle state, so a ring-after-remove
     * can name the remover as well as the ringer. */
    const char              *site_file;
    int                      site_line;
    int                      state;
};