// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once
#include "evpl/evpl_export.h"

#ifndef EVPL_INCLUDED
#error "Do not include evpl_rdma.h directly, include evpl/evpl.h instead"
#endif // ifndef EVPL_INCLUDED

#define EVPL_RDMA_FLAG_TAKE_REF 0x01

/* Export only after EVPL_NOTIFY_CONNECTED for this bind: the remote key
 * belongs to the connection's memory-registration domain. */
EVPL_API void evpl_rdma_get_address(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    struct evpl_iovec *iovec,
    uint32_t          *r_key,
    uint64_t          *r_address);

/*
 * Queue a one-sided RDMA read or write on a connected bind.  callback runs
 * exactly once for every operation, on the bind's thread, also when the
 * connection closes first: with 0 when the operation completed, with the
 * transport's error when the close cut it short after it had started, and
 * with ECONNRESET when it was still queued.  Every callback runs before the
 * bind's EVPL_NOTIFY_DISCONNECTED, never after it, so state the application
 * frees at DISCONNECTED is never called into.  Queuing an operation from
 * inside that notification, or later, aborts the process: it could only
 * complete afterwards.  On a bind whose protocol has no RDMA, callback runs at
 * once with ENOTSUP.  By DISCONNECTED the library has dropped its references
 * to iov.
 *
 * When the close completes operations that were still queued, it completes
 * the queued reads first and then the queued writes; operations the transport
 * had already started complete as it returns them.  The abort for queuing
 * after DISCONNECTED is best-effort for its EVPL_BIND_CLOSED part: a bind may
 * be reused once closed and reuse resets its flags, so a stale bind pointer
 * can pass the check.
 *
 * Two cases are not exactly-once.  evpl_rdma_write with niov == 0 queues
 * nothing and returns without calling callback.  The ENOTSUP case above
 * runs callback synchronously, from inside the call and before any
 * DISCONNECTED, not later on the bind's thread.
 */
EVPL_API void evpl_rdma_read(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    uint32_t           remote_key,
    uint64_t           remote_address,
    struct evpl_iovec *iov,
    int                niov,
    void (            *callback )(
        int   status,
        void *private_data),
    void              *private_data);

EVPL_API void evpl_rdma_write(
    struct evpl       *evpl,
    struct evpl_bind  *bind,
    uint32_t           remote_key,
    uint64_t           remote_address,
    struct evpl_iovec *iov,
    int                niov,
    unsigned int       flags,
    void (            *callback )(
        int   status,
        void *private_data),
    void              *private_data);