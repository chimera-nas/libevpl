// SPDX-FileCopyrightText: 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#pragma once

#include <stdint.h>
#include <evpl/evpl.h>
struct xdr_dbuf;

struct evpl;
struct evpl_rpc2_thread;
struct evpl_rpc2_server;
struct evpl_rpc2_request;
struct evpl_endpoint;
struct evpl_iovec;
struct evpl_rpc2_program;
struct evpl_rpc2_call;

#define EVPL_RPC2_NOTIFY_ACCEPTED     1
#define EVPL_RPC2_NOTIFY_CONNECTED    2
#define EVPL_RPC2_NOTIFY_DISCONNECTED 3

struct evpl_rpc2_notify {
    unsigned int notify_type;
};


struct evpl_rpc2_conn {
    enum evpl_protocol_id protocol;
    int                              rdma;
    struct evpl_rpc2_thread         *thread;
    struct evpl_rpc2_server_binding *server_binding;
    struct evpl_bind                *bind;
    struct xdr_dbuf                 *thread_dbuf;
    struct evpl_rpc2_msg            *recv_msg;
    struct evpl_rpc2_msg            *pending_calls;
    uint32_t                         next_xid;
    void                            *private_data;
    struct evpl_rpc2_conn           *prev;
    struct evpl_rpc2_conn           *next;
};

typedef void (*evpl_rpc2_reply_callback_t)(
    struct evpl           *evpl,
    struct evpl_rpc2_call *call,
    int                    status,
    void                  *private_data);

typedef void (*evpl_rpc2_dispatch_callback_t)(
    struct evpl_rpc2_thread  *thread,
    struct evpl_rpc2_request *request,
    void                     *private_data);

typedef void (*evpl_rpc2_notify_callback_t)(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_conn   *conn,
    struct evpl_rpc2_notify *notify,
    void                    *private_data);

struct evpl_rpc2_thread *
evpl_rpc2_thread_init(
    struct evpl                *evpl,
    struct evpl_rpc2_program  **programs,
    int                         nprograms,
    evpl_rpc2_notify_callback_t notify_callback,
    void                       *private_data);

void
evpl_rpc2_thread_destroy(
    struct evpl_rpc2_thread *thread);


struct evpl_rpc2_server *
evpl_rpc2_server_init(
    struct evpl_rpc2_program **programs,
    int                        nprograms);

void
evpl_rpc2_server_start(
    struct evpl_rpc2_server *server,
    int                      protocol,
    struct evpl_endpoint    *endpoint);

void
evpl_rpc2_server_attach(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_server *server,
    void                    *private_data);

void
evpl_rpc2_server_detach(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_server *server);

void
evpl_rpc2_server_stop(
    struct evpl_rpc2_server *server);

void
evpl_rpc2_server_destroy(
    struct evpl_rpc2_server *server);


struct evpl_rpc2_conn *
evpl_rpc2_client_connect(
    struct evpl_rpc2_thread *thread,
    int                      protocol,
    struct evpl_endpoint    *endpoint);

void
evpl_rpc2_client_disconnect(
    struct evpl_rpc2_thread *thread,
    struct evpl_rpc2_conn   *conn);