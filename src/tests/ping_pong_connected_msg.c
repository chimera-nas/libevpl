// SPDX-FileCopyrightText: 2024 - 2026 Ben Jarvis
//
// SPDX-License-Identifier: LGPL-2.1-only

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/test_log.h"
#include "evpl/evpl.h"
#include "test_common.h"

enum evpl_protocol_id                proto       = EVPL_DATAGRAM_SOCKET_UDP;
const char                           localhost[] = "127.0.0.1";
const char                          *address     = localhost;
int                                  port        = 8000;

static struct evpl_listener         *listener;
static struct evpl_listener_binding *server_binding;

struct client_state {
    volatile int done;
    int          inflight;
    int          depth;
    int          sent;
    int          recv;
    int          niters;
    uint32_t     value;
};

int
test_segment_callback(
    struct evpl      *evpl,
    struct evpl_bind *bind,
    void             *private_data)
{
    return sizeof(uint32_t);
} /* test_segment_callback */

/* Keep the send window full; called from the init callback and again from
 * the receive notifications as the window drains. */
static void
client_fill_window(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct client_state *state)
{
    while (state->inflight < state->depth &&
           state->sent < state->niters) {

        evpl_send(evpl, bind, &state->value, sizeof(state->value));

        state->inflight++;
        state->sent++;

        evpl_test_debug("client sending value %u sent %u recv %u",
                        state->value, state->sent, state->recv);

        state->value++;
    }
} /* client_fill_window */

void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    struct client_state *state = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:

            state->recv++;
            state->inflight--;

            evpl_test_info("client received value %u. sent %u recv %u",
                           *(uint32_t *) notify->recv_msg.iovec[0].data,
                           state->sent, state->recv);

            evpl_iovecs_release(evpl, notify->recv_msg.iovec, notify->recv_msg.niov);

            if (state->recv == state->niters) {
                state->done = 1;
            } else {
                client_fill_window(evpl, bind, state);
            }

            break;
    } /* switch */

} /* client_callback */

static void *
client_thread_init(
    struct evpl *evpl,
    void        *private_data)
{
    struct client_state  *state = private_data;
    struct evpl_endpoint *server;
    struct evpl_bind     *bind;

    server = evpl_endpoint_create(address, port);

    bind = evpl_connect(evpl, proto, NULL, server, client_callback,
                        test_segment_callback, state);

    client_fill_window(evpl, bind, state);

    return private_data;
} /* client_thread_init */

void
server_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    uint32_t value;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:

            value = *(uint32_t *) notify->recv_msg.iovec[0].data;

            evpl_test_info("server received %u, echoing", value);

            evpl_send(evpl, bind, &value, sizeof(value));

            evpl_iovecs_release(evpl, notify->recv_msg.iovec, notify->recv_msg.niov);

            break;
    } /* switch */

} /* server_callback */

void
accept_callback(
    struct evpl             *evpl,
    struct evpl_bind        *bind,
    evpl_notify_callback_t  *notify_callback,
    evpl_segment_callback_t *segment_callback,
    void                   **conn_private_data,
    void                    *private_data)
{
    *notify_callback   = server_callback;
    *segment_callback  = test_segment_callback;
    *conn_private_data = private_data;
} /* accept_callback */

static void *
server_thread_init(
    struct evpl *evpl,
    void        *private_data)
{
    server_binding = evpl_listener_attach(evpl, listener, accept_callback,
                                          private_data);

    return private_data;
} /* server_thread_init */

static void
server_thread_shutdown(
    struct evpl *evpl,
    void        *private_data)
{
    evpl_listener_detach(evpl, server_binding);
} /* server_thread_shutdown */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_thread   *server_thread;
    struct evpl_thread   *client_thread;
    struct evpl_endpoint *me;
    int                   rc, opt;
    struct client_state   state = {
        .inflight = 0,
        .depth    = 100,
        .sent     = 0,
        .recv     = 0,
        .niters   = 10000,
        .value    = 1
    };

    test_evpl_config();

    while ((opt = getopt(argc, argv, "a:p:r:")) != -1) {
        switch (opt) {
            case 'a':
                address = optarg;
                break;
            case 'p':
                port = atoi(optarg);
                break;
            case 'r':
                rc = evpl_protocol_lookup(&proto, optarg);
                if (rc) {
                    fprintf(stderr, "Invalid protocol '%s'\n", optarg);
                    return 1;
                }
                break;
            default:
                fprintf(stderr,
                        "Usage: %s [-r protocol] [-a address] [-p port]\n",
                        argv[0]);
                return 1;
        } /* switch */
    }

    me = evpl_endpoint_create("0.0.0.0", port);

    listener = evpl_listener_create();

    /* Blocks until the binding is attached on the server thread. */
    server_thread = evpl_thread_create(NULL, server_thread_init,
                                       server_thread_shutdown, &state);

    evpl_listen(listener, proto, me);

    client_thread = evpl_thread_create(NULL, client_thread_init, NULL, &state);

    while (!state.done) {
        usleep(1000);
    }

    evpl_test_debug("client completed iterations");

    evpl_thread_destroy(client_thread);
    evpl_thread_destroy(server_thread);

    evpl_listener_destroy(listener);

    return 0;
} /* main */
