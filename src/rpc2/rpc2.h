#pragma once

struct evpl;
struct evpl_rpc2_agent;
struct evpl_rpc2_request;
struct evpl_endpoint;
struct evpl_rpc2_agent *
evpl_rpc2_init(
    struct evpl *evpl);

void evpl_rpc2_destroy(
    struct evpl_rpc2_agent *agent);

typedef void (*evpl_rpc2_dispatch_callback_t)(
    struct evpl_rpc2_agent *agent,
    struct evpl_rpc2_request *request,
    void *private_data);

struct evpl_bind *
evpl_rpc2_listen(
    struct evpl_rpc2_agent *agent,
    int protocol,
    struct evpl_endpoint *endpoint,
    evpl_rpc2_dispatch_callback_t dispatch_callback,
    void *private_data);

struct evpl_bind *
evpl_rpc2_connect(
    struct evpl_rpc2_agent *agent,
    int protocol,
    struct evpl_endpoint *endpoint,
    evpl_rpc2_dispatch_callback_t dispatch_callback,
    void *private_data);

void evpl_rpc2_call(
    struct evpl_rpc2_agent *agent,
    struct evpl_bind *bind,
    unsigned int program,
    unsigned int version,
    unsigned int opcode);
