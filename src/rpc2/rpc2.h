
#pragma once

#include <stdint.h>

struct xdr_dbuf;

struct evpl;
struct evpl_rpc2_agent;
struct evpl_rpc2_request;
struct evpl_endpoint;
struct evpl_iovec;

struct evpl_rpc2_server;
struct evpl_rpc2_program;

struct evpl_rpc2_conn {
    int                      is_server;
    struct evpl_rpc2_server *server;
    struct evpl_rpc2_agent  *agent;
    struct evpl_rpc2_msg    *recv_msg;
    uint32_t                 next_xid;
    void                    *private_data;
};

struct evpl_rpc2_agent *
evpl_rpc2_init(
    struct evpl *evpl);

void evpl_rpc2_destroy(
    struct evpl_rpc2_agent *agent);

typedef void (*evpl_rpc2_dispatch_callback_t)(
    struct evpl_rpc2_agent   *agent,
    struct evpl_rpc2_request *request,
    void                     *private_data);

struct evpl_rpc2_server *
evpl_rpc2_listen(
    struct evpl_rpc2_agent    *agent,
    int                        protocol,
    struct evpl_endpoint      *endpoint,
    struct evpl_rpc2_program **programs,
    int                        nprograms,
    void                      *private_data);

void
evpl_rpc2_server_destroy(
    struct evpl_rpc2_agent  *agent,
    struct evpl_rpc2_server *server);

struct evpl_bind *
evpl_rpc2_connect(
    struct evpl_rpc2_agent       *agent,
    int                           protocol,
    struct evpl_endpoint         *endpoint,
    evpl_rpc2_dispatch_callback_t dispatch_callback,
    void                         *private_data);