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
#if defined(EVPL_HAVE_IOCP)
#define EVPL_CORE_MECH_PLATFORM EVPL_CORE_MECH_IOCP
#elif defined(EVPL_HAVE_EPOLL)
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
#ifdef EVPL_HAVE_IOCP
        case EVPL_CORE_MECH_IOCP: return &evpl_core_iocp_ops;
#endif /* ifdef EVPL_HAVE_IOCP */
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
#ifdef HAVE_SPDK
        case EVPL_CORE_MECH_SPDK:
            return &evpl_core_spdk_ops;
#endif /* ifdef HAVE_SPDK */
        default:
            return NULL;
    } /* switch */
} /* evpl_core_ops_lookup */

const char *
evpl_core_mech_name(unsigned int mech)
{
    switch (mech) {
        case EVPL_CORE_MECH_IOCP: return "iocp";
        case EVPL_CORE_MECH_DEFAULT:
            return "default";
        case EVPL_CORE_MECH_EPOLL:
            return "epoll";
        case EVPL_CORE_MECH_KQUEUE:
            return "kqueue";
        case EVPL_CORE_MECH_SELECT:
            return "select";
        case EVPL_CORE_MECH_SPDK:
            return "spdk";
        default:
            return "unknown";
    } /* switch */
} /* evpl_core_mech_name */

int
evpl_core_init(
    struct evpl_core *evc,
    int               max_events)
{
    unsigned int mech = evpl_from_core(evc)->config.core_mech;

    evc->ops = evpl_core_ops_lookup(mech);

    /* evpl_init validates the configured mechanism up front, so an
     * unavailable one cannot reach here. */
    evpl_core_abort_if(!evc->ops,
                       "evpl_core_init: core mechanism %s is not available in this build",
                       evpl_core_mech_name(mech));

    return evc->ops->init(evc, max_events);
} /* evpl_core_init */

/* Providers may close borrowed descriptors before withdrawing their watches.
 * If another subsystem has registered the reused number, removing the old
 * watch must not delete the new registration. Never dereference the previous
 * slot: a protocol may have recycled its event storage after closing the fd.
 * Completion-based cores own their registrations by handle and bypass this.
 */
SYMBOL_EXPORT void
evpl_core_add(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    if (evc->ops->flags & EVPL_CORE_OPS_FD_REGISTRY) {
        evpl_core_abort_if(event->fd < 0, "negative event descriptor");
        size_t needed = (size_t) event->fd + 1;
        if (needed > evc->num_fd_events) {
            size_t capacity = (needed + 63) & ~(size_t) 63;
            evc->fd_events = evpl_realloc(evc->fd_events, capacity * sizeof(*evc->fd_events));
            memset(evc->fd_events + evc->num_fd_events, 0,
                   (capacity - evc->num_fd_events) * sizeof(*evc->fd_events));
            evc->num_fd_events = capacity;
        }
        evc->fd_events[event->fd] = event;
    }
    evc->ops->add(evc, event);
} /* evpl_core_add */

SYMBOL_EXPORT void
evpl_core_remove(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    if (evc->ops->flags & EVPL_CORE_OPS_FD_REGISTRY) {
        if (event->fd < 0 || (size_t) event->fd >= evc->num_fd_events ||
            evc->fd_events[event->fd] != event) {
            return;
        }
        evc->fd_events[event->fd] = NULL;
    }
    evc->ops->remove(evc, event);
} /* evpl_core_remove */

SYMBOL_EXPORT void
evpl_core_destroy(struct evpl_core *evc)
{
    evc->ops->destroy(evc);
    evpl_free(evc->fd_events);
    evc->fd_events     = NULL;
    evc->num_fd_events = 0;
} /* evpl_core_destroy */
