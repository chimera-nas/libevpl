// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include <pthread.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "core/internal.h"
#include "evpl/evpl.h"
#include "core/evpl_shared.h"
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
    struct evpl_thread_config       config;
    struct evpl                    *evpl;
    evpl_thread_init_callback_t     init_callback;
    evpl_thread_shutdown_callback_t shutdown_callback;
    void                           *private_data;
};

struct evpl_threadpool {
    struct evpl_thread **threads;
    int                  nthreads;
};

void
evpl_thread_event(
    struct evpl       *evpl,
    struct evpl_event *event)
{
    uint64_t word;
    ssize_t  rc;

    rc = read(event->fd, &word, sizeof(word));

    if (rc != sizeof(word)) {
        evpl_event_mark_unreadable(event);
    }

} /* evpl_thread_event */

void *
evpl_thread_function(void *ptr)
{
    struct evpl_thread *evpl_thread = ptr;
    struct evpl        *evpl;

    evpl = evpl_create(&evpl_thread->config);

    evpl_thread->evpl = evpl;

    if (evpl_thread->init_callback) {
        evpl_thread->private_data = evpl_thread->init_callback(
            evpl,
            evpl_thread->private_data);
    }

    evpl_run(evpl);

    if (evpl_thread->shutdown_callback) {
        evpl_thread->shutdown_callback(evpl_thread->private_data);
    }

    evpl_destroy(evpl);

    return NULL;
} /* evpl_thread_function */

struct evpl_thread *
evpl_thread_create(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data)
{
    struct evpl_thread *evpl_thread;

    __evpl_init();

    evpl_thread = evpl_zalloc(sizeof(*evpl_thread));

    if (config) {
        evpl_thread->config = *config;
    } else {
        evpl_thread->config = evpl_shared->config->thread_default;
    }

    evpl_thread->init_callback     = init_function;
    evpl_thread->shutdown_callback = shutdown_function;
    evpl_thread->private_data      = private_data;

    pthread_create(&evpl_thread->thread, NULL,
                   evpl_thread_function, evpl_thread);

    return evpl_thread;
} /* evpl_thread_create */

void
evpl_thread_destroy(struct evpl_thread *evpl_thread)
{
    while (!evpl_thread->evpl) {
        /* Just in case the thread is still initializing */
        __sync_synchronize();
    }

    evpl_stop(evpl_thread->evpl);

    pthread_join(evpl_thread->thread, NULL);

    evpl_free(evpl_thread);
} /* evpl_thread_destroy */

struct evpl_threadpool *
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

void
evpl_threadpool_destroy(struct evpl_threadpool *threadpool)
{
    int i;

    for (i = 0; i < threadpool->nthreads; ++i) {
        evpl_thread_destroy(threadpool->threads[i]);
    }

    evpl_free(threadpool->threads);
    evpl_free(threadpool);
} /* evpl_threadpool_destroy */
