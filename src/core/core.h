// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

/*
 * Event-loop core mechanism abstraction.
 *
 * Every mechanism supported on the build platform is compiled in, and one is
 * selected per evpl at creation time from the global config
 * (evpl_global_config_set_core_mech).  epoll is the default on Linux and
 * kqueue on macOS; select is available on both as a portable fallback.
 *
 * Each backend supplies a small ops vtable plus its own state struct, and the
 * state lives in a union inside struct evpl_core so no extra allocation or
 * pointer chase is needed on the wait path.  struct evpl_core remains the
 * first member of struct evpl, so evpl_from_core() still recovers the evpl.
 */

struct evpl_core;
struct evpl_event;

struct evpl_core_ops {
    const char *name;
    int         (*init)(
        struct evpl_core *evc,
        int               max_events);
    void        (*destroy)(
        struct evpl_core *evc);
    void        (*add)(
        struct evpl_core  *evc,
        struct evpl_event *event);
    void        (*remove)(
        struct evpl_core  *evc,
        struct evpl_event *event);
    int         (*wait)(
        struct evpl_core *evc,
        int               max_msecs);
};

#ifdef EVPL_HAVE_EPOLL
#include "core/epoll.h"
#endif /* ifdef EVPL_HAVE_EPOLL */

#ifdef EVPL_HAVE_KQUEUE
#include "core/kqueue.h"
#endif /* ifdef EVPL_HAVE_KQUEUE */

#ifdef EVPL_HAVE_SELECT
#include "core/select.h"
#endif /* ifdef EVPL_HAVE_SELECT */

struct evpl_core {
    const struct evpl_core_ops *ops;
    union {
#ifdef EVPL_HAVE_EPOLL
        struct evpl_core_epoll  epoll;
#endif /* ifdef EVPL_HAVE_EPOLL */
#ifdef EVPL_HAVE_KQUEUE
        struct evpl_core_kqueue kqueue;
#endif /* ifdef EVPL_HAVE_KQUEUE */
#ifdef EVPL_HAVE_SELECT
        struct evpl_core_select select;
#endif /* ifdef EVPL_HAVE_SELECT */
    } u;
};

/*
 * Resolve a configured mechanism (enum evpl_core_mech) to its ops.
 * EVPL_CORE_MECH_DEFAULT resolves to the platform default.  Returns NULL if
 * the mechanism is not available in this build.
 */
const struct evpl_core_ops *
evpl_core_ops_lookup(
    unsigned int mech);

/* Human-readable name for a mechanism, for diagnostics.  Never NULL. */
const char *
evpl_core_mech_name(
    unsigned int mech);

int evpl_core_init(
    struct evpl_core *evc,
    int               max_events);

static inline void
evpl_core_destroy(struct evpl_core *evc)
{
    evc->ops->destroy(evc);
} /* evpl_core_destroy */

static inline void
evpl_core_add(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    evc->ops->add(evc, event);
} /* evpl_core_add */

static inline void
evpl_core_remove(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    evc->ops->remove(evc, event);
} /* evpl_core_remove */

static inline int
evpl_core_wait(
    struct evpl_core *evc,
    int               max_msecs)
{
    return evc->ops->wait(evc, max_msecs);
} /* evpl_core_wait */
