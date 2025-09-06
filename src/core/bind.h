// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include "core/allocator.h"
#include "core/iovec_ring.h"
#include "core/dgram_ring.h"
#include "core/rdma_request.h"
#include "core/evpl.h"

#define EVPL_MAX_PRIVATE         4096

#define EVPL_BIND_PENDING_CLOSED 0x01
#define EVPL_BIND_CLOSED         0x02
#define EVPL_BIND_FINISH         0x04
#define EVPL_BIND_SENT_NOTIFY    0x08

struct evpl_bind {
    struct evpl_protocol         *protocol;
    uint64_t                      flags;
    struct evpl_deferral          flush_deferral;
    struct evpl_deferral          close_deferral;
    evpl_notify_callback_t        notify_callback;
    evpl_segment_callback_t       segment_callback; /* only for dgram-on-stream */
    evpl_accept_callback_t        accept_callback; /* only for listeners */
    void                         *private_data;

    struct evpl_bind             *prev;
    struct evpl_bind             *next;

    struct evpl_iovec_ring        iovec_send;
    struct evpl_iovec_ring        iovec_recv;

    struct evpl_rdma_request_ring rdma_rw;

    struct evpl_dgram_ring        dgram_send;

    struct evpl_address          *local;
    struct evpl_address          *remote;
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

