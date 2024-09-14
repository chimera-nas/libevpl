#pragma once

struct evpl;
struct evpl_rpc2_server;
struct evpl_rpc2_msg;

struct evpl_rpc2_server *
evpl_rpc2_server_init(
    struct evpl *evpl);

void
evpl_rpc2_server_destroy(
    struct evpl_rpc2_server *server);

int
evpl_rpc2_server_listen(
    struct evpl_rpc2_server *server,
    int                      protocol,
    const char              *address,
    int                      port);
