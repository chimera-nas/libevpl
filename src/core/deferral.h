// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

struct evpl;

typedef void (*deferral_callback_t)(
    struct evpl *evpl,
    void        *private_data);

struct evpl_deferral {
    deferral_callback_t callback;
    void               *private_data;
    uint64_t            armed;
};

static void
evpl_deferral_init(
    struct evpl_deferral *deferral,
    deferral_callback_t   callback,
    void                 *private_data)
{
    deferral->callback     = callback;
    deferral->private_data = private_data;
} // evpl_deferral_init

void
evpl_defer(
    struct evpl          *evpl,
    struct evpl_deferral *deferral);
