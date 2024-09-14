#include <stdint.h>

#include "rpc2/rpc2_server.h"
#include "core/internal.h"

struct evpl_rpc2_msg {
    uint32_t length;
};

struct evpl_rpc2_server {
    struct evpl *evpl;
};

struct evpl_rpc2_server *
evpl_rpc2_server_init(struct evpl *evpl)
{
    struct evpl_rpc2_server *server;

    server =  evpl_zalloc(sizeof(*server));

    server->evpl = evpl;

    return server;
} /* evpl_rpc2_server_init */

void
evpl_rpc2_server_destroy(struct evpl_rpc2_server *server)
{
    evpl_free(server);
} /* evpl_rpc2_server_destroy */

static void
evpl_rpc2_server_accept(
    struct evpl_conn      *conn,
    evpl_event_callback_t *callback,
    void                 **conn_private_data,
    void                  *private_data)
{

} /* evpl_rpc2_server_accept */

int
evpl_rpc2_server_listen(
    struct evpl_rpc2_server *server,
    int                      protocol,
    const char              *address,
    int                      port)
{
    int error;

    error = evpl_listen(
        server->evpl,
        protocol,
        address,
        port,
        evpl_rpc2_server_accept,
        server);

    return error;
} /* evpl_rpc2_server_listen */
