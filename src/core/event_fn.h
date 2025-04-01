#pragma once

#include "core/event.h"
#include "core/evpl.h"


static inline void
evpl_event_read_interest(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);
    if (!(event->flags & (EVPL_READ_INTEREST | EVPL_WRITE_INTEREST))) {
        evpl->num_enabled_events++;
    }

    event->flags |= EVPL_READ_INTEREST;

    if ((event->flags & EVPL_READ_READY) == EVPL_READ_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_read_interest */

static inline void
evpl_event_read_disinterest(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);
    if ((event->flags & (EVPL_READ_INTEREST | EVPL_WRITE_INTEREST)) == EVPL_READ_INTEREST) {
        evpl->num_enabled_events--;
    }

    event->flags &= ~EVPL_READ_INTEREST;
} /* evpl_event_read_disinterest */

static inline void
evpl_event_write_interest(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    if (!(event->flags & (EVPL_READ_INTEREST | EVPL_WRITE_INTEREST))) {
        evpl->num_enabled_events++;
    }

    event->flags |= EVPL_WRITE_INTEREST;

    if ((event->flags & EVPL_WRITE_READY) == EVPL_WRITE_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_write_interest */

static inline void
evpl_event_write_disinterest(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);
    if ((event->flags & (EVPL_READ_INTEREST | EVPL_WRITE_INTEREST)) == EVPL_WRITE_INTEREST) {
        evpl->num_enabled_events--;
    }

    event->flags &= ~EVPL_WRITE_INTEREST;

} /* evpl_event_write_disinterest */

static inline void
evpl_event_mark_readable(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    event->flags |= EVPL_READABLE;

    if ((event->flags & EVPL_READ_READY) == EVPL_READ_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }
} /* evpl_event_mark_readable */

static inline void
evpl_event_mark_unreadable(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    event->flags &= ~EVPL_READABLE;
} /* evpl_event_mark_unreadable */

static inline void
evpl_event_mark_writable(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    event->flags |= EVPL_WRITABLE;

    if ((event->flags & EVPL_WRITE_READY) == EVPL_WRITE_READY &&
        !(event->flags & EVPL_ACTIVE)) {

        event->flags |= EVPL_ACTIVE;

        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_mark_writable */

static inline void
evpl_event_mark_unwritable(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    event->flags &= ~EVPL_WRITABLE;
} /* evpl_event_mark_unwritable */

static inline void
evpl_event_mark_error(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    evpl_core_assert(evpl == event->owner);

    event->flags |= EVPL_ERROR;

    if (!(event->flags & EVPL_ACTIVE)) {
        event->flags                                  |= EVPL_ACTIVE;
        evpl->active_events[evpl->num_active_events++] = event;
    }

} /* evpl_event_mark_error */