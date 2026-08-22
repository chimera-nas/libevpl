// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdint.h>

#include "fd_event.h"
#include "evpl/evpl.h"
#include "macros.h"
#include "logging.h"
#include "event_fn.h"

/* The public opaque struct is what consumers allocate; the real one must
 * fit inside it. */
_Static_assert(sizeof(struct evpl_fd_event) <= 10 * sizeof(uint64_t),
               "struct evpl_fd_event exceeds its public opaque size");

static void
evpl_fd_event_read_trampoline(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_fd_event *fd_event = container_of(event, struct evpl_fd_event, event);

    fd_event->read_callback(evpl, fd_event);
} /* evpl_fd_event_read_trampoline */

static void
evpl_fd_event_write_trampoline(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_fd_event *fd_event = container_of(event, struct evpl_fd_event, event);

    fd_event->write_callback(evpl, fd_event);
} /* evpl_fd_event_write_trampoline */

/* The dispatch loop invokes error_callback unconditionally when the event
 * mechanism flags an error, whether or not the consumer asked for one, so
 * the NULL check lives here rather than at add time. */
static void
evpl_fd_event_error_trampoline(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_fd_event *fd_event = container_of(event, struct evpl_fd_event, event);

    if (fd_event->error_callback) {
        fd_event->error_callback(evpl, fd_event);
    }
} /* evpl_fd_event_error_trampoline */

SYMBOL_EXPORT void
evpl_add_fd_event(
    struct evpl             *evpl,
    struct evpl_fd_event    *event,
    int                      fd,
    evpl_fd_event_callback_t read_callback,
    evpl_fd_event_callback_t write_callback,
    evpl_fd_event_callback_t error_callback)
{
    event->read_callback  = read_callback;
    event->write_callback = write_callback;
    event->error_callback = error_callback;

    evpl_add_event(evpl, &event->event, fd,
                   evpl_fd_event_read_trampoline,
                   evpl_fd_event_write_trampoline,
                   evpl_fd_event_error_trampoline);
} /* evpl_add_fd_event */

SYMBOL_EXPORT void
evpl_remove_fd_event(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    evpl_remove_event(evpl, &event->event);
} /* evpl_remove_fd_event */

SYMBOL_EXPORT int
evpl_fd_event_fd(struct evpl_fd_event *event)
{
    return event->event.fd;
} /* evpl_fd_event_fd */

SYMBOL_EXPORT void
evpl_fd_event_read_interest(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    evpl_core_abort_if(!event->read_callback,
                       "evpl_fd_event_read_interest: no read callback supplied");

    evpl_event_read_interest(evpl, &event->event);
} /* evpl_fd_event_read_interest */

SYMBOL_EXPORT void
evpl_fd_event_read_disinterest(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    evpl_event_read_disinterest(evpl, &event->event);
} /* evpl_fd_event_read_disinterest */

SYMBOL_EXPORT void
evpl_fd_event_write_interest(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    evpl_core_abort_if(!event->write_callback,
                       "evpl_fd_event_write_interest: no write callback supplied");

    evpl_event_write_interest(evpl, &event->event);
} /* evpl_fd_event_write_interest */

SYMBOL_EXPORT void
evpl_fd_event_write_disinterest(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    evpl_event_write_disinterest(evpl, &event->event);
} /* evpl_fd_event_write_disinterest */

SYMBOL_EXPORT void
evpl_fd_event_mark_readable(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    evpl_event_mark_readable(evpl, &event->event);
} /* evpl_fd_event_mark_readable */

SYMBOL_EXPORT void
evpl_fd_event_mark_unreadable(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    evpl_event_mark_unreadable(evpl, &event->event);
} /* evpl_fd_event_mark_unreadable */

SYMBOL_EXPORT void
evpl_fd_event_mark_unwritable(
    struct evpl          *evpl,
    struct evpl_fd_event *event)
{
    evpl_event_mark_unwritable(evpl, &event->event);
} /* evpl_fd_event_mark_unwritable */
