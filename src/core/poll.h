// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#define EVPL_INTERNAL 1
#include "evpl/evpl.h"

struct evpl_poll {
    evpl_poll_enter_callback_t enter_callback;
    evpl_poll_exit_callback_t  exit_callback;
    evpl_poll_callback_t       callback;
    void                      *private_data;
};
