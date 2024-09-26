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

#define EVPL_CONN_FINISH    0x01

struct evpl_conn {
    struct evpl_conn_protocol *protocol;
    uint64_t              flags;
    struct evpl_deferral  flush_deferral;
    struct evpl_deferral  close_deferral;
    evpl_event_callback_t callback;
    void                 *private_data;
    struct evpl_endpoint *endpoint;
    struct evpl_conn     *next;

    struct evpl_bvec_ring send_ring;
    struct evpl_bvec_ring recv_ring;
    /* protocol specific private data follows */
};

struct evpl_listener {
    struct evpl_conn_protocol *protocol;
    struct evpl_endpoint  *endpoint;
    evpl_accept_callback_t accept_callback;
    void                  *private_data;
    struct evpl_listener  *prev;
    struct evpl_listener  *next;
    /* protocol specific private data follows */
};


struct evpl_conn *
evpl_alloc_conn(
    struct evpl *evpl,
    struct evpl_endpoint *endpoint);

void
evpl_conn_destroy(
    struct evpl      *evpl,
    struct evpl_conn *conn);


#define evpl_conn_private(conn) ((void*)((conn) + 1))
#define evpl_listener_private(listener) ((void*)((listener) + 1))
#define evpl_private2conn(ptr) (((struct evpl_conn *)(ptr)) - 1)
#define evpl_private2listener(ptr) (((struct evpl_listener *)(ptr)) - 1) 
