// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stddef.h>

#include "core/core.h"
#include "core/evpl.h"
#include "core/evpl_shared.h"
#include "evpl/evpl.h"

/*
 * Platform default: epoll where it exists (Linux), kqueue on the BSDs and
 * macOS, and select only where neither is available.  select is always
 * compiled in as a portable fallback but is never the default when a scalable
 * mechanism is present.
 */
#if defined(EVPL_HAVE_EPOLL)
#define EVPL_CORE_MECH_PLATFORM EVPL_CORE_MECH_EPOLL
#elif defined(EVPL_HAVE_KQUEUE)
#define EVPL_CORE_MECH_PLATFORM EVPL_CORE_MECH_KQUEUE
#elif defined(EVPL_HAVE_SELECT)
#define EVPL_CORE_MECH_PLATFORM EVPL_CORE_MECH_SELECT
#else /* if defined(EVPL_HAVE_EPOLL) */
#error No event core mechanism available on this platform
#endif /* if defined(EVPL_HAVE_EPOLL) */

const struct evpl_core_ops *
evpl_core_ops_lookup(unsigned int mech)
{
    if (mech == EVPL_CORE_MECH_DEFAULT) {
        mech = EVPL_CORE_MECH_PLATFORM;
    }

    switch (mech) {
#ifdef EVPL_HAVE_EPOLL
        case EVPL_CORE_MECH_EPOLL:
            return &evpl_core_epoll_ops;
#endif /* ifdef EVPL_HAVE_EPOLL */
#ifdef EVPL_HAVE_KQUEUE
        case EVPL_CORE_MECH_KQUEUE:
            return &evpl_core_kqueue_ops;
#endif /* ifdef EVPL_HAVE_KQUEUE */
#ifdef EVPL_HAVE_SELECT
        case EVPL_CORE_MECH_SELECT:
            return &evpl_core_select_ops;
#endif /* ifdef EVPL_HAVE_SELECT */
        default:
            return NULL;
    } /* switch */
} /* evpl_core_ops_lookup */

const char *
evpl_core_mech_name(unsigned int mech)
{
    switch (mech) {
        case EVPL_CORE_MECH_DEFAULT:
            return "default";
        case EVPL_CORE_MECH_EPOLL:
            return "epoll";
        case EVPL_CORE_MECH_KQUEUE:
            return "kqueue";
        case EVPL_CORE_MECH_SELECT:
            return "select";
        default:
            return "unknown";
    } /* switch */
} /* evpl_core_mech_name */

int
evpl_core_init(
    struct evpl_core *evc,
    int               max_events)
{
    unsigned int mech = evpl_shared->config->core_mech;

    evc->ops = evpl_core_ops_lookup(mech);

    /* evpl_init validates the configured mechanism up front, so an
     * unavailable one cannot reach here. */
    evpl_core_abort_if(!evc->ops,
                       "evpl_core_init: core mechanism %s is not available in this build",
                       evpl_core_mech_name(mech));

    return evc->ops->init(evc, max_events);
} /* evpl_core_init */
