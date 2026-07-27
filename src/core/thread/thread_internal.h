// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <pthread.h>

#include "core/evpl.h"
#include "core/wakeup.h"
#include "evpl/evpl.h"

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
    struct evpl_wakeup              stop_wakeup;
    struct evpl_event               stop_event;
    struct evpl_thread_config      *config;
    struct evpl                    *evpl;
    evpl_thread_init_callback_t     init_callback;
    evpl_thread_shutdown_callback_t shutdown_callback;
    void                           *private_data;

    /* SPDK guest mode (EVPL_CORE_MECH_SPDK): the worker is an spdk_thread
     * scheduled by the host application, not a pthread.  done/detached are
     * the teardown handshake: a plain-pthread destroyer waits on done; an
     * spdk_thread destroyer sets detached and the worker frees this struct
     * itself.  Pointers are void* so this header stays free of SPDK types. */
    unsigned int                    spdk_mode;
    int                             done;
    int                             detached;
    void                           *spdk_thread;
    void                           *spdk_teardown_poller;
};

struct evpl_threadpool {
    struct evpl_thread **threads;
    int                  nthreads;
};

#ifdef HAVE_SPDK
struct evpl_thread *
evpl_thread_create_spdk(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data);

void
evpl_thread_destroy_spdk(
    struct evpl_thread *evpl_thread);
#endif /* ifdef HAVE_SPDK */
