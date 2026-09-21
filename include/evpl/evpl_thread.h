// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once
#include "evpl/evpl_export.h"

#ifndef EVPL_INCLUDED
#error "Do not include evpl_thread.h directly, include evpl/evpl.h instead"
#endif /* ifndef EVPL_INCLUDED */

struct evpl;
struct evpl_thread;
struct evpl_threadpool;

typedef void *(*evpl_thread_init_callback_t)(
    struct evpl *evpl,
    void        *private_data);

typedef void (*evpl_thread_shutdown_callback_t)(
    struct evpl *evpl,
    void        *private_data);


EVPL_API struct evpl_thread *
evpl_thread_create(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data);

EVPL_API void evpl_thread_destroy(
    struct evpl_thread *thread);

EVPL_API struct evpl_threadpool *
evpl_threadpool_create(
    struct evpl_thread_config      *config,
    int                             nthreads,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data);

EVPL_API void evpl_threadpool_destroy(
    struct evpl_threadpool *threadpool);

/* Nonblocking stop. Callback runs after guest cleanup on an SPDK worker or
 * on a native join helper. It may run concurrently with the requesting
 * thread; marshal back to the caller's executor if needed. Handles are consumed.
 * SPDK completion does not mean the host has reaped the logical thread yet. */
EVPL_API void evpl_thread_destroy_async(
    struct evpl_thread *thread,
    evpl_completion_t   callback,
    void               *private_data);
EVPL_API void evpl_threadpool_destroy_async(
    struct evpl_threadpool *pool,
    evpl_completion_t       callback,
    void                   *private_data);

/* Never waits for initialization; init_function is the readiness callback.
 * Use from host reactor callbacks, including those with no current SPDK thread.
 * Configuration ownership transfers to the worker. */
EVPL_API struct evpl_thread * evpl_thread_create_async(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data);
