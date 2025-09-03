// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

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


struct evpl_thread *
evpl_thread_create(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data);

void evpl_thread_destroy(
    struct evpl_thread *thread);

struct evpl_threadpool *
evpl_threadpool_create(
    struct evpl_thread_config      *config,
    int                             nthreads,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data);

void evpl_threadpool_destroy(
    struct evpl_threadpool *threadpool);
