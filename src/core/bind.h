/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

#include "core/internal.h"
#include "core/buffer.h"
#include "core/bvec_ring.h"
#include "core/dgram_ring.h"
#include "core/event.h"
#include "core/deferral.h"

#define EVPL_MAX_PRIVATE      4096

#define EVPL_BIND_FINISH      0x01
#define EVPL_BIND_SENT_NOTIFY 0x02

struct evpl_bind {
    struct evpl_protocol     *protocol;
    uint64_t                  flags;
    struct evpl_deferral      flush_deferral;
    struct evpl_deferral      close_deferral;
    evpl_notify_callback_t    callback;
    void                     *private_data;

    /* used only for listeners */
    evpl_accept_callback_t    accept_callback;

    struct evpl_bind         *prev;
    struct evpl_bind         *next;

    struct evpl_bvec_ring     bvec_send;
    struct evpl_bvec_ring     bvec_recv;

    struct evpl_dgram_ring    dgram_send;
    struct evpl_dgram_ring    dgram_recv;

    struct evpl_endpoint_stub local;
    struct evpl_endpoint_stub remote;
    /* protocol specific private data follows */
};

struct evpl_bind *
evpl_bind_alloc(
    struct evpl *evpl);

void
evpl_bind_destroy(
    struct evpl      *evpl,
    struct evpl_bind *bond);


#define evpl_bind_private(bind) ((void *) ((bind) + 1))
#define evpl_private2bind(ptr)  (((struct evpl_bind *) (ptr)) - 1)

