#pragma once

struct evpl;
struct evpl_rpc2_client;
struct evpl_rpc2_msg;

struct evpl_rpc2_client *
evpl_rpc2_client_init(
    struct evpl *evpl);

void
evpl_rpc2_client_destroy(
    struct evpl_rpc2_client *client);

struct evpl_rpc2_endpoint *
evpl_rpc2_client_connect(
    struct evpl_rpc2_client *client,
    int                      protocol,
    const char              *address,
    int                      port);
