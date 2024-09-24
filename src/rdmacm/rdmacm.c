#include <rdma/rdma_cma.h>
#include <sys/socket.h>
#include <netdb.h>

#include "core/protocol.h"
#include "core/internal.h"
#include "core/conn.h"
#include "core/endpoint.h"

struct ibv_context **context = NULL;

struct evpl_rdmacm_devices {
    struct ibv_context    **context;
    int                     num_devices;
};

struct evpl_rdmacm {
    struct rdma_event_channel *event_channel;
};

struct evpl_rdmacm_id {
    struct rdma_cm_id   *id;
};


void *
evpl_rdmacm_init()
{
    struct evpl_rdmacm_devices *devices;

    devices = evpl_zalloc(sizeof(*devices));

    evpl_debug("rdmacm init");

    devices->context = rdma_get_devices(&devices->num_devices);

    evpl_debug("found %d rdmacm devices", devices->num_devices);

    return devices;
}

void
evpl_rdmacm_cleanup(void *private_data)
{
    struct evpl_rdmacm_devices *devices = private_data;

    evpl_debug("rdmacm cleanup");

    rdma_free_devices(devices->context);
    evpl_free(devices);

}

void *
evpl_rdmacm_create(void *private_data)
{
    struct evpl_rdmacm *rdmacm;

    rdmacm = evpl_zalloc(sizeof(*rdmacm));

    evpl_debug("creating rdma event channel");
    rdmacm->event_channel = rdma_create_event_channel();

    evpl_debug("returning rdmacm private %p", rdmacm);
    return rdmacm;
}

void
evpl_rdmacm_destroy(void *private_data)
{
    struct evpl_rdmacm *rdmacm = private_data;

    evpl_debug("destroying rdma event channel");
    rdma_destroy_event_channel(rdmacm->event_channel);

    evpl_free(rdmacm);
}

void
evpl_rdmacm_listen(
    struct evpl        *evpl,
    struct evpl_listener *listener)
{
    struct evpl_rdmacm    *rdmacm;
    struct evpl_rdmacm_id *rdmacm_id = evpl_listener_private(listener);
    struct addrinfo *p;
    int rc;

    rdmacm = evpl_protocol_private(evpl, EVPL_RDMACM_RC);

    rdmacm_id = evpl_zalloc(sizeof(*rdmacm_id));

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->id, rdmacm_id, RDMA_PS_TCP);

    evpl_debug("rdma_create_id rc %d", rc);

    for (p = listener->endpoint->ai; p != NULL; p = p->ai_next) {

        if (rdma_bind_addr(rdmacm_id->id, p->ai_addr) == -1) {
            continue;
        }

        break;
    }

    if (p == NULL) {
        evpl_debug("Failed to bind to any addr");
        return;
    }

    rdma_listen(rdmacm_id->id, 64);

}

void
evpl_rdmacm_read(
    struct evpl       *evpl,
    struct evpl_event *event)
{

}

void
evpl_rdmacm_write(
    struct evpl       *evpl,
    struct evpl_event *event)
{

}

void
evpl_rdmacm_error(
    struct evpl       *evpl,
    struct evpl_event *event)
{

}

void
evpl_rdmacm_connect(
    struct evpl        *evpl,
    struct evpl_conn   *conn)
{
    struct evpl_rdmacm    *rdmacm;
    struct evpl_rdmacm_id *rdmacm_id = evpl_conn_private(conn);
    int rc;

    rdmacm = evpl_protocol_private(evpl, EVPL_RDMACM_RC);

    rc = rdma_create_id(rdmacm->event_channel, &rdmacm_id->id, rdmacm_id, RDMA_PS_TCP);

    evpl_debug("rdma_create_id rc %d", rc);
}

struct evpl_protocol evpl_rdmacm_rc = {
    .id = EVPL_RDMACM_RC,
    .name = "RDMACM_RC",
    .init = evpl_rdmacm_init,
    .cleanup = evpl_rdmacm_cleanup,
    .create = evpl_rdmacm_create,
    .destroy = evpl_rdmacm_destroy,
    .listen = evpl_rdmacm_listen,
    .connect = evpl_rdmacm_connect,
};
