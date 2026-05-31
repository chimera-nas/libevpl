// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include "core/allocator.h"
#include "core/iovec_ring.h"
#include "core/dgram_ring.h"
#include "core/evpl.h"

#define EVPL_MAX_PRIVATE         4096

#define EVPL_BIND_PENDING_CLOSED 0x01
#define EVPL_BIND_CLOSED         0x02
#define EVPL_BIND_FINISH         0x04
#define EVPL_BIND_SENT_NOTIFY    0x08

/* Set by a protocol's pending_close callback when teardown cannot complete
 * synchronously (e.g. RDMA must wait for the RDMA_CM_EVENT_DISCONNECTED event
 * before the cm_id can be destroyed).  While set, the core leaves the bind on
 * pending_close_binds without calling close()/destroy.  The protocol clears it
 * once the asynchronous teardown has reached the point where the bind can be
 * finalized. */
#define EVPL_BIND_CLOSE_DEFERRED 0x10

struct evpl_bind {
    struct evpl_protocol   *protocol;
    uint64_t                flags;
    struct evpl_deferral    flush_deferral;
    struct evpl_deferral    close_deferral;
    evpl_notify_callback_t  notify_callback;
    evpl_segment_callback_t segment_callback;       /* only for dgram-on-stream */
    evpl_accept_callback_t  accept_callback;       /* only for listeners */
    void                   *private_data;

    struct evpl_bind       *prev;
    struct evpl_bind       *next;

    struct evpl_iovec_ring  iovec_send;
    struct evpl_iovec_ring  iovec_recv;
    struct evpl_iovec_ring  iovec_rdma_read;
    /* Framed, ready-to-write output for transports that add per-message framing
     * (TCP_RDMA emulation).  Kept separate from iovec_send -- which stages the
     * raw payload paired positionally with dgram_send -- so framed output and a
     * mid-flush ack can never be mis-paired with a later send's payload. */
    struct evpl_iovec_ring  iovec_send_framed;
    struct evpl_dgram_ring  dgram_read;
    struct evpl_dgram_ring  dgram_send;

    struct evpl_address    *local;
    struct evpl_address    *remote;
    /* protocol specific private data follows */
};

struct evpl_bind *
evpl_bind_prepare(
    struct evpl          *evpl,
    struct evpl_protocol *protocol,
    struct evpl_address  *local,
    struct evpl_address  *remote);

void
evpl_bind_destroy(
    struct evpl      *evpl,
    struct evpl_bind *bond);


#define evpl_bind_private(bind) ((void *) ((bind) + 1))
#define evpl_private2bind(ptr)  (((struct evpl_bind *) (ptr)) - 1)

