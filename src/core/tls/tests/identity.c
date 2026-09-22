// SPDX-FileCopyrightText: 2026 Ben Jarvis
// SPDX-License-Identifier: LGPL-2.1-only
#include "core/os.h"
#include <stdio.h>
#include "evpl/evpl.h"
#include "core/tls/tls.h"
#include "core/test_log.h"

struct peer {
    int server;
    int connected;
    int received;
    int disconnected;
};
static struct peer client, server = { .server = 1 };
static const char  payload[] = "authenticated TLS payload";

static void
notify(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *event,
    void               *data)
{
    struct peer *peer = data;
    char         buffer[sizeof(payload)], alpn[8];
    int          length;

    switch (event->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            peer->connected++;
            evpl_test_abort_if(evpl_tls_get_alpn(bind, alpn, sizeof(alpn)) != 2 || strcmp(alpn, "h2"), "ALPN mismatch");
            if (!peer->server) {
                evpl_send(evpl, bind, payload, sizeof(payload));
            }
            break;
        case EVPL_NOTIFY_RECV_DATA:
            length = evpl_recv(evpl, bind, buffer, sizeof(buffer), EVPL_RECV_FLAG_ALL_OR_NONE);
            if (length == sizeof(buffer)) {
                evpl_test_abort_if(memcmp(buffer, payload, sizeof(buffer)), "TLS payload mismatch");
                peer->received++;
                if (peer->server) {
                    evpl_send(evpl, bind, payload, sizeof(payload));
                }
                evpl_finish(evpl, bind);
            }
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            peer->disconnected++;
            break;
        default:
            break;
    } /* switch */
} /* notify */

static void
accept_connection(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *callback,
    evpl_segment_callback_t *segment,
    void                   **connection_data,
    void                    *data)
{
    (void) evpl;
    (void) bind;
    (void) segment;
    (void) data;
    *callback        = notify;
    *connection_data = &server;
} /* accept_connection */

int
main(
    int    argc,
    char **argv)
{
    struct evpl_global_config    *config;
    struct evpl                  *evpl;
    struct evpl_endpoint         *endpoint;
    struct evpl_listener         *listener;
    struct evpl_listener_binding *binding;
    const char                   *protocols[] = { "h2", "http/1.1" };
    int                           success;

    if (argc != 5) {
        return 2;
    }
    success = atoi(argv[4]);
    config  = evpl_global_config_init();
    evpl_global_config_set_tls_cert(config, argv[1]);
    evpl_global_config_set_tls_key(config, argv[2]);
    evpl_global_config_set_tls_ca(config, argv[3]);
    evpl_global_config_set_tls_verify_peer(config, success == 2 ? 0 : 1);
    evpl_tls_set_alpn_protocols(protocols, 2);
    evpl_init(config);
    evpl     = evpl_create(NULL);
    endpoint = evpl_endpoint_create("127.0.0.1", 8000);
    listener = evpl_listener_create();
    binding  = evpl_listener_attach(evpl, listener, accept_connection, NULL);
    evpl_test_abort_if(evpl_listen(listener, EVPL_STREAM_SOCKET_TLS, endpoint), "Cannot listen");
    if (success == 2) {
        puts("READY");
        fflush(stdout);
    } else {
        evpl_test_abort_if(!evpl_connect(evpl, EVPL_STREAM_SOCKET_TLS, NULL, endpoint, notify, NULL, &client),
                           "Cannot connect");
    }
    while (!server.disconnected || (success != 2 && !client.disconnected)) {
        evpl_continue(evpl);
    }
    evpl_listener_detach(evpl, binding);
    evpl_listener_destroy(listener);
    evpl_destroy(evpl);
    evpl_cleanup();
    if (success == 2) {
        return server.connected != 1 || server.received != 1;
    }
    if (success) {
        return client.connected != 1 || server.connected != 1 || client.received != 1 || server.received != 1;
    }
    return client.connected || client.received || server.received;
} /* main */
