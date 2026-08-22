// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#ifndef EVPL_INCLUDED
#error "Do not include evpl_fd_event.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

/*
 * A caller-owned file descriptor as a first-class event source.
 *
 * Intended for descriptors evpl has no protocol for (device files such as
 * /dev/fuse, inotify, signalfd, ...).  The fd must be non-blocking; evpl
 * registers it with the event mechanism once and thereafter latches
 * readiness, so the contract is uniform across epoll, kqueue, and select:
 *
 *  - Nothing is armed at add time; call evpl_fd_event_read_interest() (and,
 *    if wanted, evpl_fd_event_write_interest()) to start delivery.  Arming
 *    an interest requires the corresponding callback to have been supplied.
 *
 *  - Once the fd becomes readable, read_callback is invoked once per loop
 *    pass -- without sleeping between passes -- until the callback consumes
 *    the readiness: read until EAGAIN (or a short read) and then call
 *    evpl_fd_event_mark_unreadable().  A callback may deliberately return
 *    early without draining (for fairness with other work); it is simply
 *    invoked again on the next pass.  Forgetting mark_unreadable() does not
 *    lose events, but it keeps the loop from ever sleeping.
 *
 *  - mark_unreadable() with data still pending is portable only as a way to
 *    end the current burst: an edge-triggered mechanism (epoll, kqueue)
 *    stays quiet until new data arrives, but a level-triggered one (select)
 *    re-reports the pending data by itself.  The uniform guarantee is
 *    quiescence after draining to EAGAIN.
 *
 *  - evpl_fd_event_mark_readable() re-queues the event without a kernel
 *    edge; use it to resume consumption that was deliberately parked while
 *    data may still be pending, which no edge-triggered mechanism would
 *    otherwise revisit.
 *
 *  - Write interest works symmetrically with mark_unwritable(); most
 *    consumers of always-writable descriptors never arm it.
 *
 *  - error_callback (optional) fires when the mechanism reports an error or
 *    hangup on the fd.  Device files may instead surface teardown through
 *    read() failing (e.g. ENODEV); handle both.
 *
 * All calls must be made on the thread that owns the evpl.  Removal is
 * legal from inside one of the event's own callbacks; once
 * evpl_remove_fd_event() returns the library holds no further reference,
 * so the caller may free the storage the event lives in.  The fd itself is
 * never closed by evpl.
 */

struct evpl_fd_event;

#ifndef EVPL_INTERNAL
struct evpl_fd_event {
    uint64_t opaque[10];
};
#endif /* ifndef EVPL_INTERNAL */

typedef void (*evpl_fd_event_callback_t)(
    struct evpl          *evpl,
    struct evpl_fd_event *event);

void
evpl_add_fd_event(
    struct evpl             *evpl,
    struct evpl_fd_event    *event,
    int                      fd,
    evpl_fd_event_callback_t read_callback,
    evpl_fd_event_callback_t write_callback,
    evpl_fd_event_callback_t error_callback);

void
evpl_remove_fd_event(
    struct evpl          *evpl,
    struct evpl_fd_event *event);

int
evpl_fd_event_fd(
    struct evpl_fd_event *event);

void
evpl_fd_event_read_interest(
    struct evpl          *evpl,
    struct evpl_fd_event *event);

void
evpl_fd_event_read_disinterest(
    struct evpl          *evpl,
    struct evpl_fd_event *event);

void
evpl_fd_event_write_interest(
    struct evpl          *evpl,
    struct evpl_fd_event *event);

void
evpl_fd_event_write_disinterest(
    struct evpl          *evpl,
    struct evpl_fd_event *event);

void
evpl_fd_event_mark_readable(
    struct evpl          *evpl,
    struct evpl_fd_event *event);

void
evpl_fd_event_mark_unreadable(
    struct evpl          *evpl,
    struct evpl_fd_event *event);

void
evpl_fd_event_mark_unwritable(
    struct evpl          *evpl,
    struct evpl_fd_event *event);
