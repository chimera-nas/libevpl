// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "evpl/evpl.h"
#include "tests/test_common.h"

static unsigned int received;
static const char   payload[] = "borrowed peer address";

static void
client_notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    if (notify->notify_type != EVPL_NOTIFY_RECV_MSG) {
        return;
    }
    if (notify->recv_msg.length != sizeof(payload) ||
        memcmp(notify->recv_msg.iovec[0].data, payload, sizeof(payload))) {
        fprintf(stderr, "incorrect UDP reply\n");
        exit(1);
    }
    received++;
    evpl_iovecs_release(evpl, notify->recv_msg.iovec, notify->recv_msg.niov);
} /* client_notify */

static void
server_notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    if (notify->notify_type != EVPL_NOTIFY_RECV_MSG) {
        return;
    }
    /* Queue several replies sharing an address which UDP releases as soon
     * as this callback returns. Cover copying, cloning and taking iovecs. */
    evpl_sendto(evpl, bind, notify->recv_msg.addr, payload, sizeof(payload));
    evpl_sendtov(evpl, bind, notify->recv_msg.addr, notify->recv_msg.iovec,
                 notify->recv_msg.niov, notify->recv_msg.length, 0);
    evpl_sendtov(evpl, bind, notify->recv_msg.addr, notify->recv_msg.iovec,
                 notify->recv_msg.niov, notify->recv_msg.length, EVPL_SEND_FLAG_TAKE_REF);
} /* server_notify */

int
main(void)
{
    struct evpl          *evpl;
    struct evpl_endpoint *server, *client;
    struct evpl_bind     *server_bind, *client_bind;
    struct evpl_iovec     iovec;

    test_evpl_config();
    evpl        = evpl_create(NULL);
    server      = evpl_endpoint_create("127.0.0.1", 8000);
    client      = evpl_endpoint_create("127.0.0.1", 8001);
    server_bind = evpl_bind(evpl, EVPL_DATAGRAM_SOCKET_UDP, server, server_notify, NULL);
    client_bind = evpl_bind(evpl, EVPL_DATAGRAM_SOCKET_UDP, client, client_notify, NULL);

    evpl_sendtoep(evpl, client_bind, server, payload, sizeof(payload));
    if (evpl_iovec_alloc(evpl, sizeof(payload), 0, 1, 0, &iovec) != 1) {
        return 1;
    }
    memcpy(iovec.data, payload, sizeof(payload));
    evpl_sendtoepv(evpl, client_bind, server, &iovec, 1, sizeof(payload), 0);
    evpl_iovec_release(evpl, &iovec);

    /* Endpoint references must be independent of the pending sends. */
    evpl_endpoint_close(server);
    evpl_endpoint_close(client);
    while (received < 6) {
        evpl_continue(evpl);
    }
    evpl_close(evpl, client_bind);
    evpl_close(evpl, server_bind);
    evpl_destroy(evpl);
    return received == 6 ? 0 : 1;
} /* main */
