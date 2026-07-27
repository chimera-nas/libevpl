// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * evpl_thread over spdk_thread (EVPL_CORE_MECH_SPDK guest mode).
 *
 * The worker is a lightweight spdk_thread created here and placed onto a
 * reactor by the host application's scheduler; libevpl never creates an OS
 * thread and never pumps the spdk_thread itself.  Creation and teardown are
 * message-driven so no step ever blocks a reactor:
 *
 *   create:  spdk_thread_create -> send_msg(start): evpl_create (which
 *            registers the pump poller), register stop event, init_callback,
 *            signal ready.  The creator blocks for readiness only when it is
 *            a plain pthread; an spdk_thread creator returns immediately,
 *            because the new thread may be co-scheduled on the creator's own
 *            reactor and no form of waiting could then ever complete.
 *
 *   destroy: signal the stop eventfd.  The stop handler (inside the pump)
 *            pushes every bind into pending close and registers a teardown
 *            poller.  The teardown poller (outside the pump) idles until the
 *            binds drain -- the reactor keeps servicing other threads -- then
 *            runs shutdown_callback, evpl_destroy, and spdk_thread_exit.  A
 *            plain-pthread destroyer waits for completion; an spdk_thread
 *            destroyer detaches and the worker frees the handle itself.
 */

#include <pthread.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <stdio.h>

#include <spdk/thread.h>
#include <spdk/cpuset.h>

#include "core/evpl.h"
#include "evpl/evpl.h"
#include "core/evpl_shared.h"
#include "core/event_fn.h"
#include "core/macros.h"
#include "core/wakeup.h"
#include "core/thread/thread_internal.h"

#define evpl_thread_abort_if(cond, ...) \
        evpl_abort_if(cond, "thread", __FILE__, __LINE__, __VA_ARGS__)

static int
evpl_thread_spdk_teardown(void *ctx)
{
    struct evpl_thread *evpl_thread = ctx;
    struct evpl        *evpl        = evpl_thread->evpl;
    int                 detached;

    if (evpl_has_pending_binds(evpl)) {
        /* The pump poller is still draining closes; let the reactor service
         * other threads instead of spinning here. */
        return SPDK_POLLER_IDLE;
    }

    evpl_remove_event(evpl, &evpl_thread->stop_event);

    if (evpl_thread->shutdown_callback) {
        evpl_thread->shutdown_callback(evpl, evpl_thread->private_data);
    }

    /* Unregisters the pump poller and interrupt via the mechanism's destroy;
     * runs outside the pump, satisfying its re-entrancy guard. */
    evpl_destroy(evpl);

    evpl_thread->evpl = NULL;

    spdk_poller_unregister(
        (struct spdk_poller **) &evpl_thread->spdk_teardown_poller);

    pthread_mutex_lock(&evpl_thread->lock);
    evpl_thread->done = 1;
    detached          = evpl_thread->detached;
    pthread_cond_signal(&evpl_thread->cond);
    pthread_mutex_unlock(&evpl_thread->lock);

    if (detached) {
        /* The destroyer returned without waiting; the handle is ours. */
        evpl_wakeup_close(&evpl_thread->stop_wakeup);

        if (evpl_thread->config) {
            evpl_free(evpl_thread->config);
        }

        evpl_free(evpl_thread);
    }

    spdk_thread_exit(spdk_get_thread());

    return SPDK_POLLER_BUSY;
} /* evpl_thread_spdk_teardown */

/*
 * Stop-eventfd handler; runs inside evpl_continue() via the pump poller, so
 * it must not destroy the evpl.  It initiates the close of every bind and
 * hands completion to the teardown poller.
 */
static void
evpl_thread_spdk_stop_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    struct evpl_thread *evpl_thread =
        container_of(event, struct evpl_thread, stop_event);

    if (evpl_wakeup_drain(event->fd) < 0) {
        evpl_event_mark_unreadable(evpl, event);
    }

    evpl_close_all_binds(evpl);

    if (!evpl_thread->spdk_teardown_poller) {
        evpl_thread->spdk_teardown_poller =
            spdk_poller_register(evpl_thread_spdk_teardown, evpl_thread, 0);

        evpl_thread_abort_if(!evpl_thread->spdk_teardown_poller,
                             "evpl_thread: teardown poller registration failed");
    }
} /* evpl_thread_spdk_stop_event */

/* Runs on the new spdk_thread the first time its reactor polls it. */
static void
evpl_thread_spdk_start(void *ctx)
{
    struct evpl_thread *evpl_thread = ctx;
    struct evpl        *evpl;

    evpl = evpl_create(evpl_thread->config);

    evpl_thread->evpl = evpl;

    evpl_add_event(evpl, &evpl_thread->stop_event,
                   evpl_thread->stop_wakeup.rfd,
                   evpl_thread_spdk_stop_event, NULL, NULL);

    evpl_event_read_interest(evpl, &evpl_thread->stop_event);

    if (evpl_thread->init_callback) {
        evpl_thread->private_data = evpl_thread->init_callback(
            evpl,
            evpl_thread->private_data);
    }

    pthread_mutex_lock(&evpl_thread->lock);
    evpl_thread->ready = 1;
    pthread_cond_signal(&evpl_thread->cond);
    pthread_mutex_unlock(&evpl_thread->lock);
} /* evpl_thread_spdk_start */

struct evpl_thread *
evpl_thread_create_spdk(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data)
{
    static unsigned int evpl_thread_spdk_id = 0;
    struct evpl_thread *evpl_thread;
    struct spdk_thread *thread;
    struct spdk_cpuset  cpuset;
    struct spdk_cpuset *cpuset_ptr = NULL;
    char                name[64];
    unsigned int        id;
    int                 rc;

    evpl_thread = evpl_zalloc(sizeof(*evpl_thread));

    evpl_thread->spdk_mode         = 1;
    evpl_thread->init_callback     = init_function;
    evpl_thread->shutdown_callback = shutdown_function;
    evpl_thread->private_data      = private_data;

    /* Copy the config: the creator may return before the start message runs
     * on the new thread, so the caller's config cannot be borrowed. */
    if (config) {
        evpl_thread->config = evpl_zalloc(sizeof(*evpl_thread->config));
        *evpl_thread->config = *config;
    }

    pthread_mutex_init(&evpl_thread->lock, NULL);
    pthread_cond_init(&evpl_thread->cond, NULL);

    evpl_thread_abort_if(evpl_wakeup_open(&evpl_thread->stop_wakeup) < 0,
                         "evpl_thread_create: wakeup open failed");

    id = __sync_fetch_and_add(&evpl_thread_spdk_id, 1);

    snprintf(name, sizeof(name), "%s-%u",
             (config && config->name[0]) ? config->name : "evpl", id);

    if (config && config->spdk_cpumask[0]) {
        spdk_cpuset_zero(&cpuset);

        rc = spdk_cpuset_parse(&cpuset, config->spdk_cpumask);

        evpl_thread_abort_if(rc,
                             "evpl_thread_create: invalid spdk cpumask '%s'",
                             config->spdk_cpumask);

        cpuset_ptr = &cpuset;
    }

    thread = spdk_thread_create(name, cpuset_ptr);

    evpl_thread_abort_if(!thread,
                         "evpl_thread_create: spdk_thread_create failed; the "
                         "host application must initialize the SPDK env and "
                         "thread library before using EVPL_CORE_MECH_SPDK");

    evpl_thread->spdk_thread = thread;

    rc = spdk_thread_send_msg(thread, evpl_thread_spdk_start, evpl_thread);

    evpl_thread_abort_if(rc,
                         "evpl_thread_create: spdk_thread_send_msg failed: %s",
                         strerror(-rc));

    /* Block for readiness only when the creator is a plain pthread.  An
     * spdk_thread creator may share a reactor with the new thread, in which
     * case any wait here could never complete; init_callback (which runs on
     * the new thread) is the readiness hook for such callers. */
    if (spdk_get_thread() == NULL) {
        pthread_mutex_lock(&evpl_thread->lock);

        while (!evpl_thread->ready) {
            pthread_cond_wait(&evpl_thread->cond, &evpl_thread->lock);
        }

        pthread_mutex_unlock(&evpl_thread->lock);
    }

    return evpl_thread;
} /* evpl_thread_create_spdk */

void
evpl_thread_destroy_spdk(struct evpl_thread *evpl_thread)
{
    ssize_t len;
    int     free_now = 0;

    len = evpl_wakeup_signal(&evpl_thread->stop_wakeup);

    evpl_thread_abort_if(len != sizeof(uint64_t),
                         "evpl_thread_destroy: stop wakeup signal failed: "
                         "len=%zd errno=%d (%s)", len, errno, strerror(errno));

    if (spdk_get_thread() == NULL) {
        /* Plain pthread: safe to wait for the worker's teardown poller. */
        pthread_mutex_lock(&evpl_thread->lock);

        while (!evpl_thread->done) {
            pthread_cond_wait(&evpl_thread->cond, &evpl_thread->lock);
        }

        pthread_mutex_unlock(&evpl_thread->lock);

        free_now = 1;
    } else {
        /* spdk_thread caller: waiting could deadlock against a co-scheduled
         * worker, so detach; the worker frees the handle when done.  If the
         * worker already finished, freeing falls to us. */
        pthread_mutex_lock(&evpl_thread->lock);

        if (evpl_thread->done) {
            free_now = 1;
        } else {
            evpl_thread->detached = 1;
        }

        pthread_mutex_unlock(&evpl_thread->lock);
    }

    if (free_now) {
        evpl_wakeup_close(&evpl_thread->stop_wakeup);

        if (evpl_thread->config) {
            evpl_free(evpl_thread->config);
        }

        evpl_free(evpl_thread);
    }
} /* evpl_thread_destroy_spdk */
