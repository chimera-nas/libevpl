// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include "core/os.h"
#pragma once

#include <errno.h>
#include "evpl/evpl_platform.h"


/*
 * evpl_native_thread_create with bounded retry on EAGAIN.
 *
 * EAGAIN from evpl_native_thread_create is almost always transient resource pressure
 * (RLIMIT_NPROC, cgroup pids/memory limits, kernel threads-max) during load
 * spikes.  Retry briefly to ride out the spike, then hand the error back so
 * the caller can fail loudly; callers must never ignore the result, since a
 * missing thread typically turns into a silent hang on a ready-flag or
 * work queue that nothing will ever service.
 *
 * Returns 0 on success or the final evpl_native_thread_create error code.
 */
static inline int
evpl_pthread_create(
    evpl_native_thread_t            *thread,
    const evpl_native_thread_attr_t *attr,
    void *                         (*start_routine )(
        void *),
    void                            *arg)
{
    unsigned int delay = 1000;
    int          attempt;
    int          rc;

    for (attempt = 0; ; attempt++) {
        rc = evpl_native_thread_create(thread, attr, start_routine, arg);

        if (rc != EAGAIN || attempt >= 100) {
            return rc;
        }

        evpl_sleep_us(delay);

        if (delay < 100000) {
            delay *= 2;
        }
    }
} /* evpl_pthread_create */
