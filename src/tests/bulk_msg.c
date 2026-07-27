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

enum evpl_protocol_id proto       = EVPL_DATAGRAM_RDMACM_RC;
const char            localhost[] = "127.0.0.1";
const char           *address     = localhost;
int                   port        = 8000;

struct client_state {
    volatile int          done;
    int                   inflight;
    int                   depth;
    int                   sent;
    int                   recv;
    int                   niters;
    uint32_t              value;
    struct evpl_endpoint *server_ep;
    struct evpl_endpoint *client_ep;
};

/* Keep the send window full; called from the init callback and again from
 * the SENT notifications as the window drains.  Like the original manual
 * pump, the test completes when everything has been SENT -- datagrams are
 * unreliable, so completion must not depend on every echo arriving. */
static void
client_fill_window(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct client_state *state)
{
    while (state->inflight < state->depth &&
           state->sent < state->niters) {

        evpl_sendtoep(evpl, bind, state->server_ep, &state->value,
                      sizeof(state->value));

        state->sent++;
        state->inflight++;

        state->value++;
    }

    if (state->sent == state->niters) {
        state->done = 1;
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
        case EVPL_NOTIFY_SENT:
            evpl_test_info("sent %u msgs %u bytes", notify->sent.msgs,
                           notify->sent.bytes);
            state->inflight -= notify->sent.msgs;

            client_fill_window(evpl, bind, state);
            break;
        case EVPL_NOTIFY_RECV_MSG:

            state->recv++;

            evpl_test_info("client sent %u recv %u value %u",
                           state->sent, state->recv,
                           *(uint32_t *) notify->recv_msg.iovec[0].data);

            evpl_iovecs_release(evpl, notify->recv_msg.iovec, notify->recv_msg.niov);

            break;
    } /* switch */

} /* client_callback */

static void *
client_thread_init(
    struct evpl *evpl,
    void        *private_data)
{
    struct client_state *state = private_data;
    struct evpl_bind    *bind;

    bind = evpl_bind(evpl, proto, state->client_ep, client_callback, state);

    evpl_bind_request_send_notifications(evpl, bind);

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
    struct evpl_endpoint *client = private_data;
    uint32_t              value;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_MSG:
            value = *(uint32_t *) notify->recv_msg.iovec[0].data;
            evpl_test_info("server received %u, echoing", value);

            evpl_sendtoep(evpl, bind, client, &value, sizeof(value));

            evpl_iovecs_release(evpl, notify->recv_msg.iovec, notify->recv_msg.niov);

            break;
    } /* switch */

} /* server_callback */

static void *
server_thread_init(
    struct evpl *evpl,
    void        *private_data)
{
    struct client_state *state = private_data;

    evpl_bind(evpl, proto, state->server_ep, server_callback,
              state->client_ep);

    return private_data;
} /* server_thread_init */

int
main(
    int   argc,
    char *argv[])
{
    struct evpl_thread *server_thread;
    struct evpl_thread *client_thread;
    int                 rc, opt;
    struct client_state state = {
        .inflight = 0,
        .depth    = 100,
        .sent     = 0,
        .recv     = 0,
        .niters   = 10000,
        .value    = 1,
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

    state.server_ep = evpl_endpoint_create(address, port);
    state.client_ep = evpl_endpoint_create(address, port + 1);

    /* evpl_thread_create blocks until the init callback ran, so the server
     * bind exists before the client's first burst. */
    server_thread = evpl_thread_create(NULL, server_thread_init, NULL, &state);
    client_thread = evpl_thread_create(NULL, client_thread_init, NULL, &state);

    while (!state.done) {
        usleep(1000);
    }

    evpl_test_debug("client completed iterations");

    evpl_thread_destroy(client_thread);
    evpl_thread_destroy(server_thread);

    return 0;
} /* main */
