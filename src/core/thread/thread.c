// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <pthread.h>
#include <sys/eventfd.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>

#include "core/evpl.h"
#include "evpl/evpl.h"
#include "core/evpl_shared.h"
#include "core/event_fn.h"
#include "core/macros.h"
#include "core/pthread_util.h"

extern struct evpl_shared *evpl_shared;

#define evpl_thread_debug(...) evpl_debug("thread", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_thread_info(...)  evpl_info("thread", __FILE__, __LINE__, \
                                         __VA_ARGS__)
#define evpl_thread_error(...) evpl_error("thread", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_thread_fatal(...) evpl_fatal("thread", __FILE__, __LINE__, \
                                          __VA_ARGS__)
#define evpl_thread_abort(...) evpl_abort("thread", __FILE__, __LINE__, \
                                          __VA_ARGS__)

#define evpl_thread_fatal_if(cond, ...) \
        evpl_fatal_if(cond, "thread", __FILE__, __LINE__, __VA_ARGS__)

#define evpl_thread_abort_if(cond, ...) \
        evpl_abort_if(cond, "thread", __FILE__, __LINE__, __VA_ARGS__)

struct evpl_thread {
    pthread_t                       thread;
    pthread_mutex_t                 lock;
    pthread_cond_t                  cond;
    int                             ready;
    /* Stop signal.  Owned by evpl_thread (this struct outlives the worker's
     * evpl, since it is freed only after pthread_join), so evpl_thread_destroy
     * can stop the worker by writing this fd without ever dereferencing the
     * worker's evpl -- which the worker creates, runs, and destroys entirely on
     * its own thread.  The event is registered on the worker's evpl and its
     * handler clears running from the worker thread. */
    int                             stop_eventfd;
    struct evpl_event               stop_event;
    struct evpl_thread_config      *config;
    struct evpl                    *evpl;
    evpl_thread_init_callback_t     init_callback;
    evpl_thread_shutdown_callback_t shutdown_callback;
    void                           *private_data;
};

struct evpl_threadpool {
    struct evpl_thread **threads;
    int                  nthreads;
};

/*
 * Read handler for a thread's stop_eventfd, registered on the worker's own evpl.
 * Runs on the worker thread, so it clears running directly (the same thread
 * evpl_run() reads it on); the loop exits on its next iteration.  Direct
 * assignment rather than evpl_stop() so it is idempotent if signaled twice.
 */
void
evpl_thread_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    uint64_t word;
    ssize_t  rc;

    do {
        rc = read(event->fd, &word, sizeof(word));
    } while (rc < 0 && errno == EINTR);

    if (rc != sizeof(word)) {
        evpl_event_mark_unreadable(evpl, event);
    }

    evpl->running = 0;
} /* evpl_thread_event */

void *
evpl_thread_function(void *ptr)
{
    struct evpl_thread *evpl_thread = ptr;
    struct evpl        *evpl;

    evpl = evpl_create(evpl_thread->config);

    evpl_thread->evpl = evpl;

    /* Register the stop fd (created by evpl_thread_create) on our own evpl, so
     * a write from evpl_thread_destroy wakes us and clears running on this
     * thread.  Done before signaling ready so the event is always live by the
     * time a destroyer can run. */
    evpl_add_event(evpl, &evpl_thread->stop_event, evpl_thread->stop_eventfd,
                   evpl_thread_event, NULL, NULL);
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

    evpl_run(evpl);

    evpl_remove_event(evpl, &evpl_thread->stop_event);

    evpl_destroy_close_bind(evpl);

    if (evpl_thread->shutdown_callback) {
        evpl_thread->shutdown_callback(evpl, evpl_thread->private_data);
    }

    evpl_destroy(evpl);

    return NULL;
} /* evpl_thread_function */

SYMBOL_EXPORT struct evpl_thread *
evpl_thread_create(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data)
{
    struct evpl_thread *evpl_thread;
    int                 rc;

    __evpl_init();

    evpl_thread = evpl_zalloc(sizeof(*evpl_thread));

    evpl_thread->config            = config;
    evpl_thread->init_callback     = init_function;
    evpl_thread->shutdown_callback = shutdown_function;
    evpl_thread->private_data      = private_data;

    evpl_thread->stop_eventfd = eventfd(0, EFD_NONBLOCK);
    evpl_thread_abort_if(evpl_thread->stop_eventfd < 0,
                         "evpl_thread_create: eventfd failed");

    pthread_mutex_init(&evpl_thread->lock, NULL);
    pthread_cond_init(&evpl_thread->cond, NULL);

    /* If the thread is never created, the ready-wait below would block
     * forever, so a creation failure must abort rather than fall through. */
    rc = evpl_pthread_create(&evpl_thread->thread, NULL,
                             evpl_thread_function, evpl_thread);

    evpl_thread_abort_if(rc, "evpl_thread_create: pthread_create failed: %s",
                         strerror(rc));

    pthread_mutex_lock(&evpl_thread->lock);

    while (!evpl_thread->ready) {
        pthread_cond_wait(&evpl_thread->cond, &evpl_thread->lock);
    }

    pthread_mutex_unlock(&evpl_thread->lock);

    return evpl_thread;
} /* evpl_thread_create */

SYMBOL_EXPORT void
evpl_thread_destroy(struct evpl_thread *evpl_thread)
{
    uint64_t value = 1;
    ssize_t  len;

    /* Signal stop via our own fd (never touch the worker's evpl, which the
     * worker frees on its own thread); the worker's stop_event handler clears
     * running.  Then join and only then close the fd. */
    do {
        len = write(evpl_thread->stop_eventfd, &value, sizeof(value));
    } while (len < 0 && errno == EINTR);

    evpl_thread_abort_if(len != sizeof(value),
                         "evpl_thread_destroy: write to stop_eventfd failed: "
                         "len=%zd errno=%d (%s)", len, errno, strerror(errno));

    pthread_join(evpl_thread->thread, NULL);

    close(evpl_thread->stop_eventfd);

    evpl_free(evpl_thread);
} /* evpl_thread_destroy */

SYMBOL_EXPORT struct evpl_threadpool *
evpl_threadpool_create(
    struct evpl_thread_config      *config,
    int                             nthreads,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data)
{
    struct evpl_threadpool *threadpool;
    int                     i;

    threadpool = evpl_zalloc(sizeof(*threadpool));

    threadpool->threads  = evpl_zalloc(sizeof(struct evpl_thread *) * nthreads);
    threadpool->nthreads = nthreads;

    for (i = 0; i < nthreads; ++i) {
        threadpool->threads[i] = evpl_thread_create(config,
                                                    init_function,
                                                    shutdown_function,
                                                    private_data);
    }

    return threadpool;
} /* evpl_threadpool_create */

SYMBOL_EXPORT void
evpl_threadpool_destroy(struct evpl_threadpool *threadpool)
{
    int i;

    for (i = 0; i < threadpool->nthreads; ++i) {
        evpl_thread_destroy(threadpool->threads[i]);
    }

    evpl_free(threadpool->threads);
    evpl_free(threadpool);
} /* evpl_threadpool_destroy */
