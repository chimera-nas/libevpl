#pragma once

struct eventpoll;
struct eventpoll_rpc2_client;
struct eventpoll_rpc2_msg;

struct eventpoll_rpc2_client *
eventpoll_rpc2_client_init(
    struct eventpoll *eventpoll);

void
eventpoll_rpc2_client_destroy(
    struct eventpoll_rpc2_client *client);

struct eventpoll_rpc2_endpoint *
eventpoll_rpc2_client_connect(
    struct eventpoll_rpc2_client *client,
    int                        protocol,
    const char                *address,
    int                        port);
