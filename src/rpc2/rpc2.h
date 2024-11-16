
#pragma once

#include <stdint.h>

struct evpl;
struct evpl_rpc2_agent;
struct evpl_rpc2_request;
struct evpl_endpoint;
struct evpl_iovec;

struct evpl_rpc2_program {
    uint32_t program;
    uint32_t version;
    int      (*call_dispatch)(
        uint32_t           xid,
        uint32_t           proc,
        struct evpl_iovec *iov,
        int                niov);
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

struct evpl_bind *
evpl_rpc2_listen(
    struct evpl_rpc2_agent       *agent,
    int                           protocol,
    struct evpl_endpoint         *endpoint,
    evpl_rpc2_dispatch_callback_t dispatch_callback,
    void                         *private_data);

struct evpl_bind *
evpl_rpc2_connect(
    struct evpl_rpc2_agent       *agent,
    int                           protocol,
    struct evpl_endpoint         *endpoint,
    evpl_rpc2_dispatch_callback_t dispatch_callback,
    void                         *private_data);

void evpl_rpc2_call(
    struct evpl_rpc2_agent *agent,
    struct evpl_bind       *bind,
    unsigned int            program,
    unsigned int            version,
    unsigned int            opcode);
