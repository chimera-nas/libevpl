// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/timerfd.h>

#include <spdk/thread.h>

#include "core/spdk/evpl_spdk.h"
#include "core/core.h"
#include "core/event_fn.h"
#include "core/evpl.h"
#include "core/evpl_shared.h"

_Static_assert(offsetof(struct evpl_core_spdk, epoll) == 0,
               "epoll state must be first so evc->u.epoll aliases evc->u.spdk.epoll");

/*
 * Program the one-shot timerfd to fire in ns nanoseconds (0 disarms).  The
 * syscall is skipped when the requested value matches the last programming;
 * armed_ns is cleared by the drain callback when the timer fires, so a skip
 * can never leave a fired (and therefore unarmed) timerfd believed armed.
 * A fired-but-not-yet-drained timerfd is still readable, which keeps the
 * fd_group hot, so skipping in that window is also safe.
 */
static void
evpl_core_spdk_arm(
    struct evpl_core_spdk *s,
    uint64_t               ns)
{
    struct itimerspec its;
    int               rc;

    if (ns == s->armed_ns) {
        return;
    }

    memset(&its, 0, sizeof(its));

    its.it_value.tv_sec  = ns / 1000000000ULL;
    its.it_value.tv_nsec = ns % 1000000000ULL;

    rc = timerfd_settime(s->timer_fd, 0, &its, NULL);

    evpl_core_abort_if(rc, "evpl_core_spdk_arm: timerfd_settime failed: %s",
                       strerror(errno));

    s->armed_ns = ns;
} /* evpl_core_spdk_arm */

/*
 * Read handler for the timerfd.  The timerfd exists only to pop the thread's
 * fd_group when an evpl timer deadline or pending-work kick comes due while
 * an interrupt-mode reactor sleeps; actual timer dispatch is evpl_continue's
 * heap logic.
 */
static void
evpl_core_spdk_timer_drain(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_core_spdk *s = &evpl->core.u.spdk;
    uint64_t               expirations;
    ssize_t                rc;

    for (;;) {
        rc = read(event->fd, &expirations, sizeof(expirations));

        if (rc != sizeof(expirations)) {
            break;
        }

        /* The one-shot fired, so the kernel has disarmed it. */
        s->armed_ns = 0;
    }

    evpl_event_mark_unreadable(evpl, event);
} /* evpl_core_spdk_timer_drain */

/*
 * Interrupt-mode sleep gate, run after every pump from fresh state (event
 * callbacks and deferrals run after the wait inside evpl_continue, so any
 * decision made earlier would be stale).  While work is pending the timerfd
 * is held at 1ns so the reactor re-enters the pump instead of sleeping;
 * otherwise it is armed to the nearest evpl timer deadline (capped by a
 * positive wait_ms) or disarmed entirely.
 */
static void
evpl_core_spdk_rearm(struct evpl_core *evc)
{
    struct evpl_core_spdk *s    = &evc->u.spdk;
    struct evpl           *evpl = evpl_from_core(evc);
    uint64_t               ns;
    uint64_t               cap;
    int64_t                remain;
    int                    pending;

    pending = evpl->poll_mode ||
        evpl->num_active_events ||
        evpl->num_active_deferrals ||
        evpl->pending_close_binds != NULL ||
        s->last_wait_full;

    if (pending) {
        evpl_core_spdk_arm(s, 1);
        return;
    }

    ns = 0;

    if (evpl->num_timers) {
        remain = (int64_t) (evpl->timers[0]->deadline - evpl_now_ticks());

        ns = remain > 0 ? evpl_ticks_to_ns((uint64_t) remain) : 1;

        if (ns == 0) {
            ns = 1;
        }
    }

    if (evpl->config.wait_ms > 0) {
        cap = (uint64_t) evpl->config.wait_ms * 1000000ULL;

        if (ns == 0 || cap < ns) {
            ns = cap;
        }
    }

    evpl_core_spdk_arm(s, ns);
} /* evpl_core_spdk_rearm */

static int
evpl_core_spdk_pump(struct evpl_core *evc)
{
    struct evpl_core_spdk *s    = &evc->u.spdk;
    struct evpl           *evpl = evpl_from_core(evc);
    int                    work;

    s->last_wait_full = 0;

    s->in_pump = 1;

    work = evpl_continue(evpl);

    s->in_pump = 0;

    if (s->interrupt_mode) {
        evpl_core_spdk_rearm(evc);
    }

    return work;
} /* evpl_core_spdk_pump */

static int
evpl_core_spdk_poller_fn(void *ctx)
{
    return evpl_core_spdk_pump(ctx) ? SPDK_POLLER_BUSY : SPDK_POLLER_IDLE;
} /* evpl_core_spdk_poller_fn */

/* fd_group handler for the internal epoll fd: >0 events processed, 0 none. */
static int
evpl_core_spdk_interrupt_fn(void *ctx)
{
    return evpl_core_spdk_pump(ctx);
} /* evpl_core_spdk_interrupt_fn */

/*
 * Reactor phase transitions.  Registering this callback also marks the pump
 * poller interrupt-capable so SPDK suspends it during interrupt phases (the
 * fd_group handler pumps instead).  On entry to interrupt mode a 1ns priming
 * kick closes the window where work created while polling would otherwise be
 * stranded with nothing armed.
 */
static void
evpl_core_spdk_set_mode_cb(
    struct spdk_poller *poller,
    void               *ctx,
    bool                interrupt_mode)
{
    struct evpl_core      *evc = ctx;
    struct evpl_core_spdk *s   = &evc->u.spdk;

    (void) poller;

    s->interrupt_mode = interrupt_mode;

    if (interrupt_mode) {
        evpl_core_spdk_arm(s, 1);
    }
} /* evpl_core_spdk_set_mode_cb */

static int
evpl_core_spdk_init(
    struct evpl_core *evc,
    int               max_events)
{
    struct evpl_core_spdk *s    = &evc->u.spdk;
    struct evpl           *evpl = evpl_from_core(evc);
    int                    rc;

    s->thread = spdk_get_thread();

    evpl_core_abort_if(!s->thread,
                       "EVPL_CORE_MECH_SPDK requires evpl_create() to run on an "
                       "spdk_thread; the host application must initialize the SPDK "
                       "env and thread library first");

    rc = evpl_core_epoll_ops.init(evc, max_events);

    evpl_core_abort_if(rc, "evpl_core_spdk_init: epoll init failed: %s",
                       strerror(rc));

    /* Each fast-path pass is a separate poller callback on a shared reactor,
     * so bound the pure-poll iterations between timer/fd sweeps to keep
     * socket and timer latency within a few reactor iterations. */
    if (evpl->config.poll_iterations > 16) {
        evpl->config.poll_iterations = 16;
    }

    s->timer_fd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK | TFD_CLOEXEC);

    evpl_core_abort_if(s->timer_fd < 0,
                       "evpl_core_spdk_init: timerfd_create failed: %s",
                       strerror(errno));

    evpl_add_event(evpl, &s->timer_event, s->timer_fd,
                   evpl_core_spdk_timer_drain, NULL, NULL);

    evpl_event_read_interest(evpl, &s->timer_event);

    s->poller = spdk_poller_register(evpl_core_spdk_poller_fn, evc, 0);

    evpl_core_abort_if(!s->poller,
                       "evpl_core_spdk_init: spdk_poller_register failed");

    if (spdk_interrupt_mode_is_enabled()) {
        /* May invoke the mode callback immediately if the thread is already
         * in its interrupt phase. */
        spdk_poller_register_interrupt(s->poller, evpl_core_spdk_set_mode_cb,
                                       evc);

        s->intr = spdk_interrupt_register(s->epoll.fd,
                                          evpl_core_spdk_interrupt_fn,
                                          evc, "evpl");

        evpl_core_abort_if(!s->intr,
                           "evpl_core_spdk_init: spdk_interrupt_register failed");

        /* Priming kick: timers or binds created by thread-init callbacks run
         * before the first pump, and a sleeping reactor must not miss them. */
        evpl_core_spdk_arm(s, 1);
    }

    return 0;
} /* evpl_core_spdk_init */

static void
evpl_core_spdk_destroy(struct evpl_core *evc)
{
    struct evpl_core_spdk *s = &evc->u.spdk;

    evpl_core_abort_if(spdk_get_thread() != s->thread,
                       "evpl_destroy must run on the owning spdk_thread under "
                       "EVPL_CORE_MECH_SPDK");

    evpl_core_abort_if(s->in_pump,
                       "evpl_destroy must not be called from inside an evpl "
                       "callback under EVPL_CORE_MECH_SPDK; destroy from an spdk "
                       "message or poller instead");

    /* Detach from SPDK before tearing down any fds so the pump can never run
     * against a dead epoll. */
    if (s->intr) {
        spdk_interrupt_unregister(&s->intr);
    }

    spdk_poller_unregister(&s->poller);

    /* No evpl_remove_event for timer_event: core destroy runs after event
     * dispatch is finished (mirroring how run_event is handled), and closing
     * the fd removes it from the epoll interest set. */
    close(s->timer_fd);

    evpl_core_epoll_ops.destroy(evc);
} /* evpl_core_spdk_destroy */

static void
evpl_core_spdk_add(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    evpl_core_epoll_ops.add(evc, event);
} /* evpl_core_spdk_add */

static void
evpl_core_spdk_remove(
    struct evpl_core  *evc,
    struct evpl_event *event)
{
    evpl_core_epoll_ops.remove(evc, event);
} /* evpl_core_spdk_remove */

static int
evpl_core_spdk_wait(
    struct evpl_core *evc,
    int               max_msecs)
{
    struct evpl_core_spdk *s = &evc->u.spdk;
    int                    n;

    /* Never block the reactor: sleeping is the host's job.  max_msecs is
     * deliberately ignored rather than used to arm the timerfd -- callbacks
     * and deferrals run after this wait within the same evpl_continue, so
     * any arming decision made here would be stale; evpl_core_spdk_rearm
     * runs post-pump from fresh state instead. */
    (void) max_msecs;

    n = evpl_core_epoll_ops.wait(evc, 0);

    /* A full batch may leave undelivered events latched in the inner epoll
     * with no new edge to pop the fd_group; the rearm kick covers it. */
    s->last_wait_full = (n == s->epoll.max_events);

    return n;
} /* evpl_core_spdk_wait */

const struct evpl_core_ops evpl_core_spdk_ops = {
    .name    = "spdk",
    .flags   = EVPL_CORE_OPS_EXTERNAL_LOOP,
    .init    = evpl_core_spdk_init,
    .destroy = evpl_core_spdk_destroy,
    .add     = evpl_core_spdk_add,
    .remove  = evpl_core_spdk_remove,
    .wait    = evpl_core_spdk_wait,
};
