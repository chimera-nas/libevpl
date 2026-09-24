// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include "core/bind.h"
#include "tests/test_common.h"

#define MESSAGES 129

struct peer {
    unsigned int connected, disconnected, received, sent;
};

static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *event,
    void               *private_data)
{
    struct peer *peer     = private_data;
    uint32_t     expected = peer->received;

    switch (event->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            peer->connected++;
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            peer->disconnected++;
            break;
        case EVPL_NOTIFY_RECV_MSG:
            test_message_equals(event, &expected, sizeof(expected));
            peer->received++;
            evpl_iovecs_release(evpl, event->recv_msg.iovec, event->recv_msg.niov);
            break;
        case EVPL_NOTIFY_SENT:
            evpl_test_abort_if(event->notify_status, "send failed during ring growth");
            peer->sent += event->sent.msgs;
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
    struct peer                   client = { 0 }, server = { 0 };
    const char                   *address = getenv("EVPL_TEST_RDMA_IP");
    uint32_t                      value   = 0;

    evpl_test_abort_if(!address, "RDMA test address is required");
    evpl_global_config_set_dgram_ring_size(config, 2);
    evpl_global_config_set_iovec_ring_size(config, 2);
    /* Registration pins the whole slab; the 1 GiB default is more than the
     * Soft-RoCE CI guest can spare (see test_evpl_rdma_config). */
    evpl_global_config_set_slab_size(config, 64 * 1024 * 1024);
    evpl_global_config_set_rdmacm_srq_size(config, 256);
    evpl_init(config);
    tcfg = evpl_thread_config_init();
    evpl_thread_config_set_wait_ms(tcfg, 0);
    evpl     = evpl_create(tcfg);
    ep       = evpl_endpoint_create(address, 8018);
    listener = evpl_listener_create();
    binding  = evpl_listener_attach(evpl, listener, accept_peer, &server);
    evpl_test_abort_if(evpl_listen(listener, EVPL_DATAGRAM_RDMACM_RC, ep), "listen failed");
    bind = evpl_connect(evpl, EVPL_DATAGRAM_RDMACM_RC, NULL, ep, notify, NULL, &client);
    evpl_test_abort_if(!bind, "connect failed");
    evpl_bind_request_send_notifications(evpl, bind);
    for (int i = 0; i < 10000 && (!client.connected || !server.connected); ++i) {
        evpl_continue(evpl);
        evpl_sleep_us(1000);
    }
    evpl_test_abort_if(client.connected != 1 || server.connected != 1, "connection did not establish");

    evpl_send(evpl, bind, &value, sizeof(value));
    evpl_continue(evpl);
    /* The first WR is posted, but its completion has not been consumed.
     * Enqueue without progressing: growth must preserve its completion ID. */
    evpl_test_abort_if(client.sent || bind->dgram_send.tail == bind->dgram_send.waist,
                       "first send must be outstanding before growing the ring");
    for (value = 1; value < MESSAGES; ++value) {
        evpl_send(evpl, bind, &value, sizeof(value));
    }
    evpl_test_abort_if(bind->dgram_send.size <= 2, "datagram ring did not grow");
    for (int i = 0; i < 10000 && (client.sent != MESSAGES || server.received != MESSAGES); ++i) {
        evpl_continue(evpl);
        evpl_sleep_us(1000);
    }
    evpl_test_abort_if(client.sent != MESSAGES || server.received != MESSAGES,
                       "every send and receive must complete after ring growth");
    evpl_finish(evpl, bind);
    for (int i = 0; i < 10000 && (!client.disconnected || !server.disconnected); ++i) {
        evpl_continue(evpl);
        evpl_sleep_us(1000);
    }
    evpl_test_abort_if(client.disconnected != 1 || server.disconnected != 1, "disconnect did not complete");
    evpl_listener_detach(evpl, binding);
    evpl_listener_destroy(listener);
    evpl_endpoint_close(ep);
    evpl_destroy(evpl);
    return 0;
} /* main */
