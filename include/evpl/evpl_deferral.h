// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_deferral.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

typedef void (*deferral_callback_t)(
    struct evpl *evpl,
    void        *private_data);

struct evpl_deferral {
    deferral_callback_t callback;
    void               *private_data;
    uint64_t            armed;
};

void
evpl_deferral_init(
    struct evpl_deferral *deferral,
    deferral_callback_t   callback,
    void                 *private_data);

void
evpl_defer(
    struct evpl          *evpl,
    struct evpl_deferral *deferral);