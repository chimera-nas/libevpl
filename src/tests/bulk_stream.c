// SPDX-FileCopyrightText: 2024 - 2025 Ben Jarvis
//
// SPDX-License-Identifier: LGPL

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/uio.h>
#include <unistd.h>

#include "core/test_log.h"
#include "evpl/evpl.h"

enum evpl_protocol_id proto       = EVPL_STREAM_SOCKET_TCP;
const char            localhost[] = "127.0.0.1";
const char           *address     = localhost;
int                   port        = 8000;


struct client_state {
    int      run;
    int      inflight;
    int      depth;
    int      sent;
    int      recv;
    int      niters;
    uint32_t value;
};

void
client_send(
    struct evpl         *evpl,
    struct evpl_bind    *bind,
    struct client_state *state)
{
    while (state->inflight < state->depth &&
           state->sent < state->niters) {

        evpl_send(evpl, bind, &state->value, sizeof(state->value));

        state->sent++;
        state->inflight++;

        evpl_test_debug("client sent sent %u recv %u value %u",
                        state->sent, state->recv, state->value);

        state->value++;

    }
} /* client_send */

void
client_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    uint32_t             value;
    int                  length;
    struct client_state *state = private_data;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_DATA:

            while (1) {
                length = evpl_recv(evpl, bind, &value, sizeof(value));

                if (length != sizeof(value)) {
                    break;
                }

                state->recv++;
                state->inflight--;

                evpl_test_info("client received sent %u recv %u value %u",
                               state->sent, state->recv, value);

                client_send(evpl, bind, state);
            }

            break;
    } /* switch */

} /* client_callback */

void *
client_thread(void *arg)
{
    struct evpl          *evpl;
    struct evpl_endpoint *server;
    struct evpl_bind     *bind;
    struct client_state  *state = arg;

    evpl = evpl_create(NULL);

    server = evpl_endpoint_create(address, port);

    bind = evpl_connect(evpl, proto, NULL, server, client_callback, NULL, state);

    client_send(evpl, bind, state);

    while (state->recv != state->niters) {
        evpl_continue(evpl);
    }

    evpl_test_debug("client completed iterations");

    state->run = 0;

    evpl_destroy(evpl);

    return NULL;
} /* client_thread */

void
server_callback(
    struct evpl        *evpl,
    struct evpl_bind   *bind,
    struct evpl_notify *notify,
    void               *private_data)
{
    uint32_t value;
    int      length;

    switch (notify->notify_type) {
        case EVPL_NOTIFY_RECV_DATA:

            while (1) {

                length = evpl_recv(evpl, bind, &value, sizeof(value));

                if (length != sizeof(value)) {
                    break;
                }

                evpl_test_info("server received %u, echoing", value);

                evpl_send(evpl, bind, &value, sizeof(value));
            }

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
    *conn_private_data = private_data;
} /* accept_callback */

int
main(
    int   argc,
    char *argv[])
{
    pthread_t             thr;
    struct evpl          *evpl;
    struct evpl_endpoint *me;
    struct evpl_listener *listener;
    int                   rc, opt;
    struct client_state   state = {
        .run      = 1,
        .inflight = 0,
        .depth    = 100,
        .sent     = 0,
        .recv     = 0,
        .niters   = 10000,
        .value    = 1
    };

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


    evpl = evpl_create(NULL);

    me = evpl_endpoint_create("0.0.0.0", port);

    listener = evpl_listener_create();

    evpl_listener_attach(evpl, listener, accept_callback, &state);

    evpl_listen(listener, proto, me);

    pthread_create(&thr, NULL, client_thread, &state);

    while (state.run) {
        evpl_continue(evpl);
    }

    pthread_join(thr, NULL);

    evpl_destroy(evpl);

    return 0;
} /* main */
