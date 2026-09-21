// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
#include "evpl/evpl_platform.h"

#include <errno.h>
#include <string.h>

#include "core/evpl.h"
#include "evpl/evpl.h"
#include "core/evpl_shared.h"
#include "core/event_fn.h"
#include "core/macros.h"
#include "core/pthread_util.h"
#include "core/thread/thread_internal.h"

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

/*
 * Read handler for a thread's stop wakeup, registered on the worker's own evpl.
 * Runs on the worker thread, so it clears running directly (the same thread
 * evpl_run() reads it on); the loop exits on its next iteration.  Direct
 * assignment rather than evpl_stop() so it is idempotent if signaled twice.
 */
void
evpl_thread_event(
    struct evpl          *evpl,
    struct evpl_doorbell *doorbell)
{
    (void) doorbell;
    evpl->running = 0;
} /* evpl_thread_event */

void *
evpl_thread_function(void *ptr)
{
    struct evpl_thread *evpl_thread = ptr;
    struct evpl        *evpl;

    evpl                = evpl_create(evpl_thread->config);
    evpl_thread->config = NULL;

    evpl_thread->evpl = evpl;

    evpl_add_doorbell(evpl, &evpl_thread->stop_receiver, evpl_thread_event);
    evpl_thread->stop_sender = evpl_doorbell_sender(&evpl_thread->stop_receiver);

    if (evpl_thread->init_callback) {
        evpl_thread->private_data = evpl_thread->init_callback(
            evpl,
            evpl_thread->private_data);
    }

    evpl_mutex_lock(&evpl_thread->lock);
    evpl_thread->ready = 1;
    evpl_cond_signal(&evpl_thread->cond);
    evpl_mutex_unlock(&evpl_thread->lock);

    evpl_run(evpl);

    evpl_remove_doorbell(evpl, &evpl_thread->stop_receiver);

    evpl_destroy_close_bind(evpl);

    if (evpl_thread->shutdown_callback) {
        evpl_thread->shutdown_callback(evpl, evpl_thread->private_data);
    }

    evpl_destroy(evpl);

    return NULL;
} /* evpl_thread_function */

static struct evpl_thread *
evpl_thread_create_internal(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data,
    int                             wait_ready)
{
    struct evpl_thread *evpl_thread;
    int                 rc;

    __evpl_init();

#ifdef HAVE_SPDK
    if ((config && config->core_mech != EVPL_CORE_MECH_INHERIT ?
         config->core_mech : evpl_shared->config->core_mech) == EVPL_CORE_MECH_SPDK) {
        return evpl_thread_create_spdk(config, init_function,
                                       shutdown_function, private_data, wait_ready);
    }
#endif /* ifdef HAVE_SPDK */

    evpl_thread = evpl_zalloc(sizeof(*evpl_thread));

    evpl_thread->config            = config;
    evpl_thread->init_callback     = init_function;
    evpl_thread->shutdown_callback = shutdown_function;
    evpl_thread->private_data      = private_data;

    evpl_mutex_init(&evpl_thread->lock, NULL);
    evpl_cond_init(&evpl_thread->cond, NULL);

    /* Give worker threads an explicit 8MB stack: Linux (glibc) defaults
     * there, but macOS pthreads default to 512KB, which deep inline
     * completion chains (e.g. a synchronous backend walking a
     * near-SYMLOOP_MAX symlink chain under ASan) overflow. */
    evpl_native_thread_attr_t thread_attr;
    evpl_native_thread_attr_init(&thread_attr);
    evpl_native_thread_attr_setstacksize(&thread_attr, 8 * 1024 * 1024);

    /* If the thread is never created, the ready-wait below would block
     * forever, so a creation failure must abort rather than fall through. */
    rc = evpl_pthread_create(&evpl_thread->thread, &thread_attr,
                             evpl_thread_function, evpl_thread);

    evpl_native_thread_attr_destroy(&thread_attr);

    evpl_thread_abort_if(rc, "evpl_thread_create: evpl_native_thread_create failed: %s",
                         strerror(rc));

    evpl_mutex_lock(&evpl_thread->lock);

    while (wait_ready && !evpl_thread->ready) {
        evpl_cond_wait(&evpl_thread->cond, &evpl_thread->lock);
    }

    evpl_mutex_unlock(&evpl_thread->lock);

    return evpl_thread;
} /* evpl_thread_create */

SYMBOL_EXPORT struct evpl_thread *
evpl_thread_create(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data)
{
    return evpl_thread_create_internal(config, init_function, shutdown_function,
                                       private_data, evpl_current_spdk_thread() == NULL);
} /* evpl_thread_create */

SYMBOL_EXPORT struct evpl_thread *
evpl_thread_create_async(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data)
{
    return evpl_thread_create_internal(config, init_function, shutdown_function,
                                       private_data, 0);
} /* evpl_thread_create_async */

SYMBOL_EXPORT void
evpl_thread_destroy(struct evpl_thread *evpl_thread)
{
#ifdef HAVE_SPDK
    if (evpl_thread->spdk_mode) {
        evpl_thread_destroy_spdk(evpl_thread);
        return;
    }
#endif /* ifdef HAVE_SPDK */
    evpl_mutex_lock(&evpl_thread->lock);
    while (!evpl_thread->ready) {
        evpl_cond_wait(&evpl_thread->cond, &evpl_thread->lock);
    }
    evpl_mutex_unlock(&evpl_thread->lock);
    int rc = evpl_doorbell_signal(evpl_thread->stop_sender);

    evpl_thread_abort_if(rc && rc != ECANCELED, "thread stop signal failed: %d", rc);
    evpl_native_thread_join(evpl_thread->thread, NULL);
    evpl_doorbell_sender_release(evpl_thread->stop_sender);
    evpl_cond_destroy(&evpl_thread->cond);
    evpl_mutex_destroy(&evpl_thread->lock);

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
        struct evpl_thread_config *worker_config = NULL;
        if (config) {
            worker_config = evpl_zalloc(sizeof(*worker_config));
            *worker_config = *config;
        }
        threadpool->threads[i] = evpl_thread_create(worker_config,
                                                    init_function,
                                                    shutdown_function,
                                                    private_data);
    }

    if (config) {
        evpl_thread_config_release(config);
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

struct evpl_thread_join_request {
    struct evpl_thread *thread;
    evpl_completion_t   callback;
    void               *private_data;
};

static void *
evpl_thread_join_async(void *arg)
{
    struct evpl_thread_join_request *request = arg;

    evpl_thread_destroy(request->thread);
    if (request->callback) {
        request->callback(request->private_data);
    }
    evpl_free(request);
    return NULL;
} /* evpl_thread_join_async */

SYMBOL_EXPORT void
evpl_thread_destroy_async(
    struct evpl_thread *thread,
    evpl_completion_t   callback,
    void               *private_data)
{
#ifdef HAVE_SPDK
    if (thread->spdk_mode) {
        evpl_thread_destroy_async_spdk(thread, callback, private_data);
        return;
    }
#endif /* ifdef HAVE_SPDK */
    /* Native join must not block an SPDK caller sharing this process. */
    struct evpl_thread_join_request *request = evpl_zalloc(sizeof(*request));
    evpl_native_thread_t             joiner;
    int                              rc;
    request->thread       = thread;
    request->callback     = callback;
    request->private_data = private_data;
    rc                    = evpl_pthread_create(&joiner, NULL, evpl_thread_join_async, request);
    evpl_thread_abort_if(rc, "async join thread creation failed: %d", rc);
    evpl_native_thread_detach(joiner);
} /* evpl_thread_destroy_async */

struct evpl_pool_stop {
    atomic_uint       remaining;
    evpl_completion_t callback;
    void             *private_data;
};

static void
evpl_pool_stopped(void *arg)
{
    struct evpl_pool_stop *stop = arg;

    if (atomic_fetch_sub(&stop->remaining, 1) == 1) {
        evpl_completion_t callback     = stop->callback;
        void             *private_data = stop->private_data;
        evpl_free(stop);
        if (callback) {
            callback(private_data);
        }
    }
} /* evpl_pool_stopped */

SYMBOL_EXPORT void
evpl_threadpool_destroy_async(
    struct evpl_threadpool *pool,
    evpl_completion_t       callback,
    void                   *private_data)
{
    struct evpl_pool_stop *stop = evpl_zalloc(sizeof(*stop));

    /* Extra reference prevents an early completion freeing the coordinator. */
    atomic_init(&stop->remaining, pool->nthreads + 1);
    stop->callback     = callback;
    stop->private_data = private_data;
    for (int i = 0; i < pool->nthreads; i++) {
        evpl_thread_destroy_async(pool->threads[i], evpl_pool_stopped, stop);
    }
    evpl_free(pool->threads);
    evpl_free(pool);
    evpl_pool_stopped(stop);
} /* evpl_threadpool_destroy_async */
