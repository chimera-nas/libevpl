// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

typedef void (*evpl_poll_callback_t)(
    struct evpl *evpl,
    void        *private_data);

struct evpl_poll {
    evpl_poll_callback_t callback;
    void                *private_data;
};
