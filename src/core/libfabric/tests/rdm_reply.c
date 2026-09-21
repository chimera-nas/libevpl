// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/* Unknown peers choose ephemeral ports. Replies must use the borrowed source
 * address; no endpoint is reconstructed from a known client port. */
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <rdma/fabric.h>
#include "core/evpl.h"
#include "core/address.h"
#include "core/test_log.h"
#include "test_common.h"

#define CLIENTS 3
#define PARTS   5
static const unsigned int sizes[] = { 32, 128, 4096, 65536 };
struct client_state {
    struct evpl_bind *bind;
    unsigned int      id, round, replies;
};
static unsigned int       requests;

static void
client_notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *arg)
{
    struct client_state *client = arg;
    unsigned int         i;
    unsigned char        expected = 16 * client->id + client->round;

    if (notify->notify_type != EVPL_NOTIFY_RECV_MSG) {
        return;
    }
    evpl_test_abort_if(!notify->recv_msg.addr || notify->recv_msg.niov != 1 ||
                       notify->recv_msg.length != sizes[client->round], "invalid RDM reply");
    for (i = 0; i < notify->recv_msg.length; i++) {
        evpl_test_abort_if(((unsigned char *) notify->recv_msg.iovec[0].data)[i] != expected,
                           "RDM reply was corrupted or routed to the wrong peer");
    }
    client->replies++;
    evpl_iovecs_release(evpl, notify->recv_msg.iovec, notify->recv_msg.niov);
} /* client_notify */

static void
server_notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *arg)
{
    struct sockaddr_in *source;

    if (notify->notify_type != EVPL_NOTIFY_RECV_MSG) {
        return;
    }
    evpl_test_abort_if(!notify->recv_msg.addr, "unsolicited RDM receive has no reply address");
    source = (struct sockaddr_in *) notify->recv_msg.addr->addr;
    evpl_test_abort_if(source->sin_family != AF_INET || !source->sin_port ||
                       !source->sin_addr.s_addr, "invalid ephemeral peer address");
    requests++;
    evpl_sendto(evpl, bind, notify->recv_msg.addr,
                notify->recv_msg.iovec[0].data, notify->recv_msg.length);
    evpl_sendtov(evpl, bind, notify->recv_msg.addr, notify->recv_msg.iovec,
                 notify->recv_msg.niov, notify->recv_msg.length, 0);
    evpl_sendtov(evpl, bind, notify->recv_msg.addr, notify->recv_msg.iovec,
                 notify->recv_msg.niov, notify->recv_msg.length, EVPL_SEND_FLAG_TAKE_REF);
} /* server_notify */

int
main(void)
{
    struct client_state   clients[CLIENTS] = { 0 };
    struct evpl          *evpl;
    struct evpl_bind     *server_bind;
    struct evpl_endpoint *server, *endpoint;
    struct evpl_iovec     iov[PARTS];
    struct fi_info       *hints, *info;
    unsigned int          i, j, round, length, remaining, complete, parts;
    int                   rc;

    alarm(30);
    if (getenv("EVPL_TEST_RDM_ONLY")) {
        hints                = fi_allocinfo();
        hints->ep_attr->type = FI_EP_MSG;
        hints->caps          = FI_MSG;
        rc                   = fi_getinfo(FI_VERSION(1, 17), NULL, NULL, 0, hints, &info);
        evpl_test_abort_if(rc != -FI_ENODATA, "RDM-only fixture unexpectedly has MSG support");
        fi_freeinfo(hints);
    }
    test_evpl_config();
    evpl        = evpl_create(NULL);
    server      = evpl_endpoint_create("127.0.0.1", 8000);
    server_bind = evpl_bind(evpl, EVPL_DATAGRAM_LIBFABRIC_RDM, server, server_notify, NULL);
    for (i = 0; i < CLIENTS; i++) {
        clients[i].id   = i + 1;
        endpoint        = evpl_endpoint_create("127.0.0.1", 0);
        clients[i].bind = evpl_bind(evpl, EVPL_DATAGRAM_LIBFABRIC_RDM, endpoint,
                                    client_notify, &clients[i]);
        evpl_endpoint_close(endpoint);
    }
    for (round = 0; round < sizeof(sizes) / sizeof(sizes[0]); round++) {
        parts = round == 0 ? 1 : round == 1 ? 4 : PARTS;
        for (i = 0; i < CLIENTS; i++) {
            clients[i].round   = round;
            clients[i].replies = 0;
            remaining          = sizes[round];
            for (j = 0; j < parts; j++) {
                length = remaining / (parts - j);
                evpl_test_abort_if(evpl_iovec_alloc(evpl, length, 1, 1, 0, &iov[j]) != 1,
                                   "payload allocation failed");
                memset(iov[j].data, 16 * clients[i].id + round, length);
                remaining -= length;
            }
            evpl_sendtoepv(evpl, clients[i].bind, server, iov, parts, sizes[round], 0);
            evpl_iovecs_release(evpl, iov, parts);
        }
        do {
            evpl_continue(evpl);
            complete = 0;
            for (i = 0; i < CLIENTS; i++) {
                complete += clients[i].replies == 3;
                evpl_test_abort_if(clients[i].replies > 3, "duplicate reply");
            }
        } while (complete != CLIENTS);
    }
    evpl_test_abort_if(requests != CLIENTS * 4, "missing or duplicate request");
    for (i = 0; i < CLIENTS; i++) {
        evpl_close(evpl, clients[i].bind);
    }
    evpl_close(evpl, server_bind);
    evpl_endpoint_close(server);
    evpl_destroy(evpl);
    return 0;
} /* main */
