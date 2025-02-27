// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#pragma once

#include <stdint.h>

struct xdr_dbuf;

struct evpl;
struct evpl_rpc2_thread;
struct evpl_rpc2_server;
struct evpl_rpc2_request;
struct evpl_endpoint;
struct evpl_iovec;

struct evpl_rpc2_program;

struct evpl_rpc2_conn {
    struct evpl_rpc2_thread *thread;
    struct evpl_rpc2_server *server;
    struct evpl_rpc2_msg    *recv_msg;
    uint32_t                 next_xid;
    void                    *private_data;
};

typedef void (*evpl_rpc2_dispatch_callback_t)(
    struct evpl_rpc2_thread  *thread,
    struct evpl_rpc2_request *request,
    void                     *private_data);

struct evpl_rpc2_server *
evpl_rpc2_init(
    struct evpl_rpc2_program **programs,
    int                        nprograms);

void
evpl_rpc2_start(
    struct evpl_rpc2_server *server,
    int                      protocol,
    struct evpl_endpoint    *endpoint);

struct evpl_rpc2_thread *
evpl_rpc2_attach(
    struct evpl             *evpl,
    struct evpl_rpc2_server *server,
    void                    *private_data);

void
evpl_rpc2_detach(
    struct evpl_rpc2_thread *thread);

void
evpl_rpc2_destroy(
    struct evpl_rpc2_server *server);