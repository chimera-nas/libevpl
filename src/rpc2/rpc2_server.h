#pragma once

struct eventpoll;
struct eventpoll_rpc2_server;
struct eventpoll_rpc2_msg;

struct eventpoll_rpc2_server *
eventpoll_rpc2_server_init(
    struct eventpoll *eventpoll);

void
eventpoll_rpc2_server_destroy(
    struct eventpoll_rpc2_server *server);

int
eventpoll_rpc2_server_listen(
    struct eventpoll_rpc2_server *server,
    int protocol,
    const char *address,
    int port);
