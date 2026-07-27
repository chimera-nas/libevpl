// SPDX-FileCopyrightText: 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

/*
 * TCP ping-pong between evpl threads running as spdk_threads: covers the
 * listener over an SPDK evpl thread, the cross-thread accept handoff
 * (connect_requests + run_wakeup), and socket send/recv under the poller
 * pump.  All I/O logic runs in callbacks on the SPDK evpl threads; main()
 * stays on a plain pthread where the blocking listener/thread APIs are safe.
 */

#include <stddef.h>
#include <stdint.h>

#include "spdk_test_harness.h"

static const char localhost[] = "127.0.0.1";
static int        port        = 8000;

struct pingpong_state {
    volatile int run;
    int          sent;
    int          recv;
    int          niters;
    uint32_t     value;
};

static struct evpl_listener_binding *server_binding;
static struct evpl_listener         *listener;

static void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct pingpong_state *state = private_data;
    uint32_t               value;
    int                    length;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            evpl_test_info("client connected");
            break;
        case EVPL_NOTIFY_RECV_DATA:

            do {
                length = evpl_recv(evpl, bind, &value, sizeof(value),
                                   EVPL_RECV_FLAG_ALL_OR_NONE);

                if (length == sizeof(value)) {

                    state->recv++;

                    if (state->recv < state->niters) {

                        evpl_send(evpl, bind, &state->value,
                                  sizeof(state->value));

                        state->value++;
                        state->sent++;
                    } else {
                        state->run = 0;
                    }
                }
            } while (length > 0);

            break;

        case EVPL_NOTIFY_DISCONNECTED:
            evpl_test_info("client disconnected");
            break;
    } /* switch */

} /* client_callback */

static void
server_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    uint32_t value;
    int      length;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_CONNECTED:
            evpl_test_info("server connected");
            break;
        case EVPL_NOTIFY_DISCONNECTED:
            evpl_test_info("server disconnected");
            break;
        case EVPL_NOTIFY_RECV_DATA:

            do {
                length = evpl_recv(evpl, bind, &value, sizeof(value),
                                   EVPL_RECV_FLAG_ALL_OR_NONE);

                if (length == sizeof(value)) {
                    evpl_send(evpl, bind, &value, sizeof(value));
                }
            } while (length > 0);

            break;
    } /* switch */

} /* server_callback */

static void
accept_callback(
    struct evpl             *evpl,
    struct evpl_bind        *accepted_bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    *notify_callback   = server_callback;
    *conn_private_data = private_data;
} /* accept_callback */

static void *
server_init(
    struct evpl *evpl,
    void        *private_data)
{
    server_binding = evpl_listener_attach(evpl, listener, accept_callback,
                                          private_data);

    return private_data;
} /* server_init */

static void
server_shutdown(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_listener_detach(evpl, server_binding);
} /* server_shutdown */

static void *
client_init(
    struct evpl *evpl,
    void        *private_data)
{
    struct pingpong_state *state = private_data;
    struct evpl_endpoint  *ep;
    struct evpl_bind      *bind;

    ep = evpl_endpoint_create(localhost, port);

    bind = evpl_connect(evpl, EVPL_STREAM_SOCKET_TCP, NULL, ep,
                        client_callback, NULL, state);

    evpl_send(evpl, bind, &state->value, sizeof(state->value));

    state->value++;
    state->sent++;

    return private_data;
} /* client_init */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_thread   *server_thread;
    struct evpl_thread   *client_thread;
    struct evpl_endpoint *listen_ep;
    struct pingpong_state state = {
        .run    = 1,
        .sent   = 0,
        .recv   = 0,
        .niters = 100,
        .value  = 1
    };

    evpl_spdk_test_init(3);

    evpl_spdk_test_config();

    listener = evpl_listener_create();

    /* Blocks until server_init attached the binding on the worker. */
    server_thread = evpl_thread_create(NULL, server_init, server_shutdown,
                                       &state);

    listen_ep = evpl_endpoint_create("0.0.0.0", port);

    evpl_listen(listener, EVPL_STREAM_SOCKET_TCP, listen_ep);

    client_thread = evpl_thread_create(NULL, client_init, NULL, &state);

    while (state.run) {
        usleep(1000);
    }

    evpl_test_info("ping-pong completed: sent %d recv %d",
                   state.sent, state.recv);

    evpl_thread_destroy(client_thread);
    evpl_thread_destroy(server_thread);

    evpl_listener_destroy(listener);

    return 0;
} /* main */
