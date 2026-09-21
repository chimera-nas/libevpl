// SPDX-FileCopyrightText: 2025 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#pragma once
#include "evpl/evpl_platform.h"
#include "core/evpl.h"
#ifdef HAVE_SPDK
#include "core/wakeup.h"
#endif // ifdef HAVE_SPDK
struct evpl_thread {
    evpl_native_thread_t            thread;
    evpl_mutex_t                    lock;
    evpl_cond_t                     cond;
    int                             ready;
    /* The sender outlives the worker loop; a worker that has already stopped
     * safely rejects subsequent stop requests. */
    struct evpl_doorbell            stop_receiver;
    struct evpl_doorbell_sender    *stop_sender;
    struct evpl_thread_config      *config;
    struct evpl                    *evpl;
    evpl_thread_init_callback_t     init_callback;
    evpl_thread_shutdown_callback_t shutdown_callback;
    void                           *private_data;
    evpl_completion_t               completion;
    void                           *completion_private;
#ifdef HAVE_SPDK
    struct evpl_wakeup              stop_wakeup;
    struct evpl_event               stop_event;
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
#endif // ifdef HAVE_SPDK
};

struct evpl_threadpool {
    struct evpl_thread **threads;
    int                  nthreads;
};

#ifdef HAVE_SPDK
void evpl_thread_destroy_async_spdk(
    struct evpl_thread *thread,
    evpl_completion_t   callback,
    void               *private_data);
struct evpl_thread *
evpl_thread_create_spdk(
    struct evpl_thread_config      *config,
    evpl_thread_init_callback_t     init_function,
    evpl_thread_shutdown_callback_t shutdown_function,
    void                           *private_data,
    int                             wait_ready);

void
evpl_thread_destroy_spdk(
    struct evpl_thread *evpl_thread);
#endif /* ifdef HAVE_SPDK */
