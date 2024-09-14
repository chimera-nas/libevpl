#include <stdint.h>

#include "rpc2/rpc2_client.h"
#include "core/internal.h"

struct eventpoll_rpc2_client {
    struct eventpoll *eventpoll;
};

struct eventpoll_rpc2_endpoint {
    int protocol;
};

struct eventpoll_rpc2_client *
eventpoll_rpc2_client_init(
    struct eventpoll *eventpoll)
{
    struct eventpoll_rpc2_client *client;

    client = eventpoll_zalloc(sizeof(*client));

    client->eventpoll = eventpoll;

    return client;
}

void
eventpoll_rpc2_client_destroy(
    struct eventpoll_rpc2_client *client)
{
    eventpoll_free(client);
}

struct eventpoll_rpc2_endpoint *
eventpoll_rpc2_client_connect(
    struct eventpoll_rpc2_client *client,
    int                        protocol,
    const char                *address,
    int                        port)
{
    struct eventpoll_rpc2_endpoint *endpoint;

    endpoint = eventpoll_zalloc(sizeof(*endpoint));

    return endpoint;
}
