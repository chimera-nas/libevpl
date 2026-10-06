// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include "evpl/evpl.h"
#include "core/test_log.h"

struct peer {
    int send;
    int connected;
    int disconnected;
};

static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *event,
    void               *private_data)
{
    struct peer *peer          = private_data;
    char         payload[4096] = { 0 };

    switch (event->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            peer->connected++;
            if (peer->send) {
                /* Deliberately exceeds the peer's posted 64-byte receive. */
                evpl_send(evpl, bind, payload, sizeof(payload));
            }
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            peer->disconnected++;
            break;
        case EVPL_NOTIFY_RECV_MSG:
        case EVPL_NOTIFY_RECV_DATA:
            evpl_test_abort("oversized RC message must fail, not be delivered");
            break;
    } /* switch */
} /* notify */

static void
accept_peer(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *callback,
    evpl_segment_callback_t *segment,
    void                   **private_data,
    void                    *arg)
{
    *callback     = notify;
    *segment      = NULL;
    *private_data = arg;
} /* accept_peer */

int
main(void)
{
    struct evpl_global_config    *config = evpl_global_config_init();
    struct evpl_thread_config    *tcfg;
    struct evpl                  *evpl;
    struct evpl_endpoint         *ep;
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    struct evpl_bind             *bind;
    struct peer                   cancelled = { 0 }, client = { .send = 1 }, server = { 0 };
    const char                   *address = getenv("EVPL_TEST_RDMA_IP");

    evpl_test_abort_if(!address, "RDMA test address is required");
    evpl_global_config_set_rdmacm_datagram_size_override(config, 64);
    /* Registration pins the whole slab; the 1 GiB default is more than the
     * Soft-RoCE CI guest can spare (see test_evpl_rdma_config). */
    evpl_global_config_set_slab_size(config, 64 * 1024 * 1024);
    evpl_global_config_set_rdmacm_srq_size(config, 256);
    evpl_init(config);
    tcfg = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(tcfg, 0);
    evpl = evpl_create(tcfg);
    ep   = evpl_endpoint_create(address, 8017);

    /* Closing before address resolution must not dereference a missing QP. */
    bind = evpl_connect(evpl, EVPL_DATAGRAM_RDMACM_RC, NULL, ep, notify, NULL, &cancelled);
    evpl_test_abort_if(!bind, "connect failed");
    evpl_close(evpl, bind);
    for (int i = 0; i < 10000 && !cancelled.disconnected; ++i) {
        evpl_continue(evpl);
        evpl_sleep_us(1000);
    }
    evpl_test_abort_if(cancelled.disconnected != 1, "cancelled bind did not disconnect");

    listener = evpl_listener_create();
    binding  = evpl_listener_attach(evpl, listener, accept_peer, &server);
    evpl_test_abort_if(evpl_listen(listener, EVPL_DATAGRAM_RDMACM_RC, ep), "listen failed");
    bind = evpl_connect(evpl, EVPL_DATAGRAM_RDMACM_RC, NULL, ep, notify, NULL, &client);
    evpl_test_abort_if(!bind, "connect failed");
    for (int i = 0; i < 10000 && (!client.disconnected || !server.disconnected); ++i) {
        evpl_continue(evpl);
        evpl_sleep_us(1000);
    }
    evpl_test_abort_if(client.connected != 1 || server.connected != 1,
                       "both peers must establish before testing the receive error");
    evpl_test_abort_if(client.disconnected != 1 || server.disconnected != 1,
                       "receive error must disconnect both peers");
    evpl_listener_detach(evpl, binding);
    evpl_listener_destroy(listener);
    evpl_endpoint_close(ep);
    evpl_destroy(evpl);
    return 0;
} /* main */
