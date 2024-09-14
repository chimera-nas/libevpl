#include <stdint.h>

#include "rpc2/rpc2_server.h"
#include "core/internal.h"

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

static void
eventpoll_rpc2_server_accept(
    struct eventpoll_conn      *conn,
    eventpoll_event_callback_t *callback,
    void                      **conn_private_data,
    void                       *private_data)
{

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
        address,
        port,
        eventpoll_rpc2_server_accept,
        server);

    return error;
}
