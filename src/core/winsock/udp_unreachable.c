// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include "core/test_log.h"
#include "evpl/evpl.h"
#include "tests/test_common.h"

static void
notified(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    unsigned int *disconnected = private_data;

    (void) evpl;
    (void) bind;
    if (notify->notify_type == EVPL_NOTIFY_DISCONNECTED) {
        (*disconnected)++;
    }
} /* notified */
static void
expired(
    struct evpl       *evpl,
    struct evpl_timer *timer)
{
    evpl_stop(evpl);
    (void) timer;
} /* expired */
int
main(void)
{
    SOCKET                probe;
    struct sockaddr_in    address        = { 0 };
    int                   address_length = sizeof(address);
    struct evpl          *evpl;
    struct evpl_bind     *sender;
    struct evpl_endpoint *local, *remote;
    struct evpl_timer     timer;
    unsigned int          disconnected = 0;

    test_evpl_config();
    probe = socket(AF_INET, SOCK_DGRAM, 0);
    evpl_test_abort_if(probe == INVALID_SOCKET, "probe socket failed");
    address.sin_family      = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    evpl_test_abort_if(bind(probe, (struct sockaddr *) &address, sizeof(address)) ||
                       getsockname(probe, (struct sockaddr *) &address, &address_length), "probe bind failed");
    closesocket(probe);
    evpl   = evpl_create(NULL);
    local  = evpl_endpoint_create("127.0.0.1", 0);
    remote = evpl_endpoint_create("127.0.0.1", ntohs(address.sin_port));
    sender = evpl_bind(evpl, EVPL_DATAGRAM_SOCKET_UDP, local, notified, &disconnected);
    evpl_test_abort_if(!sender, "sender bind failed");
    evpl_sendtoep(evpl, sender, remote, "probe", 5);
    evpl_add_oneshot_timer(evpl, &timer, expired, 200000);
    evpl_run(evpl);
    evpl_test_abort_if(disconnected, "ICMP closed an unconnected UDP socket");
    evpl_destroy(evpl);
    evpl_endpoint_close(local);
    evpl_endpoint_close(remote);
    evpl_test_abort_if(disconnected != 1, "destroy did not finish UDP teardown");
    return 0;
} /* main */
