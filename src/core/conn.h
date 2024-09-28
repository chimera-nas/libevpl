/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

#include "core/internal.h"
#include "core/buffer.h"
#include "core/event.h"
#include "core/deferral.h"

#define EVPL_MAX_PRIVATE 4096

#define EVPL_BIND_FINISH 0x01

struct evpl_bind {
    struct evpl_protocol      *protocol;
    uint64_t                   flags;
    struct evpl_deferral       flush_deferral;
    struct evpl_deferral       close_deferral;
    evpl_notify_callback_t     callback;
    void                      *private_data;

    /* used only for listeners */
    evpl_accept_callback_t     accept_callback;

    struct evpl_endpoint      *endpoint;
    struct evpl_bind          *prev;
    struct evpl_bind          *next;

    struct evpl_bvec_ring      send_ring;
    struct evpl_bvec_ring      recv_ring;
    /* protocol specific private data follows */
};

struct evpl_bind *
evpl_bind_alloc(
    struct evpl          *evpl,
    struct evpl_endpoint *endpoint);

void
evpl_bind_destroy(
    struct evpl      *evpl,
    struct evpl_bind *bond);


#define evpl_bind_private(bind)         ((void *) ((bind) + 1))
#define evpl_private2bind(ptr)          (((struct evpl_bind *) (ptr)) - 1)

