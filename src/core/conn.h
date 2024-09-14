/*
 * SPDX-FileCopyrightText: 2024 Ben Jarvis
 *
 * SPDX-License-Identifier: LGPL
 */

#pragma once

struct evpl_conn {
    struct evpl_event     event; /* must be first member */

    union {     /* must be second member */
        struct evpl_socket s;
    };

    evpl_event_callback_t callback;
    void                 *private_data;

    struct evpl_bvec_ring send_ring;
    struct evpl_bvec_ring recv_ring;

    char                  address[256];
    int                   port;
    int                   protocol;

    struct evpl_conn     *next;
};

struct evpl_conn *
evpl_alloc_conn(
    struct evpl *evpl,
    int          protocol,
    const char  *address,
    int          port);

void
evpl_conn_destroy(
    struct evpl      *evpl,
    struct evpl_conn *conn);
