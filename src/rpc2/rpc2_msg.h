#ifndef __EVENTPOLL_RPC2_H__
#define __EVENTPOLL_RPC2_H__

#include "eventpoll.h"

struct eventpoll_rpc2_msg {
    uint32_t    length;
};


struct eventpoll_rpc2_server;
struct eventpoll_rpc2_client;
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
    int                        port)

#endif
