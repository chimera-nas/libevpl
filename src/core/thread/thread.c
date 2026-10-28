// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/* pthread_setname_np() is a GNU extension in glibc. */
#ifndef _GNU_SOURCE
#define _GNU_SOURCE 1
#endif /* ifndef _GNU_SOURCE */

#include "core/os.h"
#include "evpl/evpl_platform.h"

#include <errno.h>
#include <stdio.h>
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

/*
 * Linux keeps 15 characters of a thread name and rejects longer ones, so
 * names are cut to that length on every platform to look the same in ps,
 * top and debuggers everywhere.
 */
#define EVPL_THREAD_NAME_MAX 15

/* Length of name cut to at most max bytes, backed up so the cut never
 * splits a UTF-8 character. */
static size_t
evpl_thread_name_len(
    const char *name,
    size_t      max)
{
    size_t len = strlen(name);

    if (len <= max) {
        return len;
    }

    while (max > 0 && ((unsigned char) name[max] & 0xC0) == 0x80) {
        max--;
    }

    return max;
} /* evpl_thread_name_len */

SYMBOL_EXPORT void
evpl_thread_set_name(const char *name)
{
    char   short_name[EVPL_THREAD_NAME_MAX + 1];
    size_t len;

    if (!name) {
        return;
    }

    len = evpl_thread_name_len(name, EVPL_THREAD_NAME_MAX);
    memcpy(short_name, name, len);
    short_name[len] = '\0';

#ifdef _WIN32
    {
        /* SetThreadDescription() first shipped in Windows 10 1607, so look
         * it up rather than fail to load on an older kernel32. */
        typedef HRESULT (WINAPI *set_description_fn)(
            HANDLE,
            PCWSTR);
        set_description_fn set_description;
        wchar_t            wide_name[EVPL_THREAD_NAME_MAX + 1];
        HRESULT            hr;

        set_description = (set_description_fn) (void *) GetProcAddress(
            GetModuleHandleW(L"kernel32.dll"), "SetThreadDescription");

        if (set_description &&
            MultiByteToWideChar(CP_UTF8, 0, short_name, -1, wide_name,
                                EVPL_THREAD_NAME_MAX + 1) > 0) {
            hr = set_description(GetCurrentThread(), wide_name);

            if (FAILED(hr)) {
                evpl_thread_debug("failed to name thread '%s': 0x%lx",
                                  short_name, (unsigned long) hr);
            }
        }
    }
#else  /* ifdef _WIN32 */
    {
        int rc;

#ifdef __APPLE__
        /* macOS can only name the calling thread. */
        rc = pthread_setname_np(short_name);
#else  /* ifdef __APPLE__ */
        rc = pthread_setname_np(pthread_self(), short_name);
#endif /* ifdef __APPLE__ */

        if (rc) {
            evpl_thread_debug("failed to name thread '%s': %s",
                              short_name, strerror(rc));
        }
    }
#endif /* ifdef _WIN32 */
} /* evpl_thread_set_name */

/* Name a native worker from its config.  A threadpool worker gets the name
 * plus _<index>, shortening the name rather than the index to fit. */
static void
evpl_thread_apply_name(
    const struct evpl_thread_config *config,
    int                              pool_index)
{
    char   name[EVPL_THREAD_NAME_MAX + 1];
    char   suffix[16];
    int    suffix_len;
    size_t base_len;

    if (!config || !config->name[0]) {
        return;
    }

    if (pool_index < 0) {
        evpl_thread_set_name(config->name);
        return;
    }

    suffix_len = snprintf(suffix, sizeof(suffix), "_%d", pool_index);
    base_len   = evpl_thread_name_len(config->name,
                                      EVPL_THREAD_NAME_MAX - suffix_len);

    /* base_len + suffix_len <= EVPL_THREAD_NAME_MAX, so this fits. */
    memcpy(name, config->name, base_len);
    memcpy(name + base_len, suffix, suffix_len + 1);
    evpl_thread_set_name(name);
} /* evpl_thread_apply_name */

void *
evpl_thread_function(void *ptr)
{
    struct evpl_thread *evpl_thread = ptr;
    struct evpl        *evpl;

    /* evpl_create() consumes the config, so take the name first. */
    evpl_thread_apply_name(evpl_thread->config, evpl_thread->pool_index);

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

int
evpl_thread_config_is_spdk(const struct evpl_thread_config *config)
{
#ifdef HAVE_SPDK
    __evpl_init();

    return (config && config->core_mech != EVPL_CORE_MECH_INHERIT ?
            config->core_mech : evpl_shared->config->core_mech) == EVPL_CORE_MECH_SPDK;
#else  /* ifdef HAVE_SPDK */
    (void) config;
    return 0;
#endif /* ifdef HAVE_SPDK */
} /* evpl_thread_config_is_spdk */

/* pool_index is the worker's index in a threadpool, or -1 for a lone
 * thread; only native workers use it, to number their OS thread names. */
static struct evpl_thread *
evpl_thread_create_internal(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data,
    int                             wait_ready,
    int                             pool_index)
{
    struct evpl_thread *evpl_thread;
    int                 rc;

    __evpl_init();

#ifdef HAVE_SPDK
    if (evpl_thread_config_is_spdk(config)) {
        return evpl_thread_create_spdk(config, init_function,
                                       shutdown_function, private_data, wait_ready);
    }
#endif /* ifdef HAVE_SPDK */

    evpl_thread = evpl_zalloc(sizeof(*evpl_thread));

    evpl_thread->config            = config;
    evpl_thread->pool_index        = pool_index;
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
                                       private_data, evpl_current_spdk_thread() == NULL,
                                       -1);
} /* evpl_thread_create */

SYMBOL_EXPORT struct evpl_thread *
evpl_thread_create_async(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data)
{
    return evpl_thread_create_internal(config, init_function, shutdown_function,
                                       private_data, 0, -1);
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
        threadpool->threads[i] = evpl_thread_create_internal(worker_config,
                                                             init_function,
                                                             shutdown_function,
                                                             private_data,
                                                             evpl_current_spdk_thread() == NULL,
                                                             i);
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
