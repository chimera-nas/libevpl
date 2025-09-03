// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/evpl.h"
#include "core/macros.h"

SYMBOL_EXPORT void
evpl_defer(
    struct evpl          *evpl,
    struct evpl_deferral *deferral)
{
    int index;

    if (!deferral->armed) {
        deferral->armed = 1;
        index           = evpl->num_active_deferrals;

        evpl->active_deferrals[index] = deferral;

        ++evpl->num_active_deferrals;
    }

} /* evpl_defer */

SYMBOL_EXPORT void
evpl_deferral_init(
    struct evpl_deferral *deferral,
    deferral_callback_t   callback,
    void                 *private_data)
{
    deferral->callback     = callback;
    deferral->private_data = private_data;
} // evpl_deferral_init

SYMBOL_EXPORT void
evpl_remove_deferral(
    struct evpl          *evpl,
    struct evpl_deferral *deferral)
{
    int i;

    if (!deferral->armed) {
        return;
    }

    for (i = 0; i < evpl->num_active_deferrals; ++i) {

        if (evpl->active_deferrals[i] != deferral) {
            continue;
        }

        deferral->armed = 0;

        if (i + 1 < evpl->num_active_deferrals) {
            evpl->active_deferrals[i] = evpl->active_deferrals[evpl->
                                                               num_active_deferrals
                                                               - 1];
        }

        --evpl->num_active_deferrals;
    }

} /* evpl_defer */