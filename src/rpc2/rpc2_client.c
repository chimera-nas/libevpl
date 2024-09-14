#include <stdint.h>

#include "rpc2/rpc2_client.h"
#include "core/internal.h"

struct evpl_rpc2_client {
    struct evpl *evpl;
};

struct evpl_rpc2_endpoint {
    int protocol;
};

struct evpl_rpc2_client *
evpl_rpc2_client_init(struct evpl *evpl)
{
    struct evpl_rpc2_client *client;

    client = evpl_zalloc(sizeof(*client));

    client->evpl = evpl;

    return client;
} /* evpl_rpc2_client_init */

void
evpl_rpc2_client_destroy(struct evpl_rpc2_client *client)
{
    evpl_free(client);
} /* evpl_rpc2_client_destroy */

struct evpl_rpc2_endpoint *
evpl_rpc2_client_connect(
    struct evpl_rpc2_client *client,
    int                      protocol,
    const char              *address,
    int                      port)
{
    struct evpl_rpc2_endpoint *endpoint;

    endpoint = evpl_zalloc(sizeof(*endpoint));

    return endpoint;
} /* evpl_rpc2_client_connect */
