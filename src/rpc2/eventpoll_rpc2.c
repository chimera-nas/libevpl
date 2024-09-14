#include <stdint.h>

#include "eventpoll_rpc2.h"
#include "eventpoll_internal.h"

struct eventpoll_rpc2_msg {
    uint32_t    length;
};

struct eventpoll_rpc2_server {
    struct eventpoll *eventpoll;
};

struct eventpoll_rpc2_server *
eventpoll_rpc2_server_init(
    struct eventpoll *eventpoll)
{
    struct eventpoll_rpc2_server *server;

    server =  eventpoll_zalloc(sizeof(*server)); 

    server->eventpoll = eventpoll;

    return server;
}

void
eventpoll_rpc2_server_destroy(
    struct eventpoll_rpc2_server *server)
{
    eventpoll_free(server);
}

int
eventpoll_rpc2_server_listen(
    struct eventpoll_rpc2_server *server,
    int protocol,
    const char *address,
    int port)
{
    int error;

    error = eventpoll_listen(
        server->eventpoll,
        protocol,
        adddress,
        port,
        eventpoll_rpc2_server_accept,
        server);

    return error;
}

struct eventpoll_rpc2_endpoint *
eventpoll_rpc2_client_connect(
    struct eventpoll          *eventpoll,
    int                        protocol,
    const char                *address,
    int                        port)
{
    struct eventpoll_rpc2_endpoint *endpoint;

    endpoint = eventpoll_zalloc(sizeof(*endpoint));

    return endpoint;
}

struct eventpoll_conn *
eventpoll_connect(
    struct eventpoll          *eventpoll,
    int                        protocol,
    const char                *address,
    int                        port,
    eventpoll_event_callback_t callback,
    void                      *private_data);

